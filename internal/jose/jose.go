// Package jose is the shared JWT/JWS validation core for T1's two identity
// paths ("shared validation internals,
// different trust anchors"): LTI 1.3 launch id_tokens verify against a
// per-platform JWKS from the registry (step 2); OIDC bearer tokens verify
// against the one operated issuer (step 4). Both inherit exactly this core:
// compact-JWS parsing, an RSA signature check, an explicit alg allowlist with
// `none` rejected structurally, and time/audience/issuer claim checks.
//
// Deliberately stdlib-only (the S1 posture): verification composes
// crypto/rsa primitives per the spec text — RFC 7515 (JWS), RFC 7517 (JWK),
// RFC 7519 (JWT), OpenID Connect Core 1.0 §3.1.3.7 — which keeps the in-repo
// conformance suite's reference the SPEC, not a library's reading of it (D-020).
package jose

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// allowedAlgs is the explicit allowlist (RFC 7515 §4.1.1; RFC 8725 §3.1:
// "libraries MUST NOT accept tokens using `none` when a signed token is
// expected", and algorithm confusion is prevented by allowlisting, never by
// trusting the header). RSASSA-PKCS1-v1_5 only — the profile every LTI
// platform and mainstream OIDC provider signs with; anything else is a
// rejection, not a fallback.
var allowedAlgs = map[string]crypto.Hash{
	"RS256": crypto.SHA256,
	"RS384": crypto.SHA384,
	"RS512": crypto.SHA512,
}

// Header is the decoded JOSE header of a compact JWS.
type Header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

var (
	ErrMalformed   = errors.New("jose: malformed compact JWS")
	ErrAlgRejected = errors.New("jose: alg not in allowlist")
	ErrBadSig      = errors.New("jose: signature verification failed")
)

// PeekClaims decodes the payload WITHOUT verifying the signature. It exists
// for exactly one purpose: reading `iss` to select the trust anchor (the LTI
// platform registry keys the JWKS by issuer). Nothing read here may be
// trusted until Verify has run against the anchor the issuer selected.
func PeekClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMalformed
	}
	return decodeSegment(parts[1])
}

// Verify checks the compact JWS signature against key and returns the
// claims. Enforced here, before any claim is surfaced (RFC 7515 §5.2):
//   - exactly three segments, each valid base64url
//   - header alg in the allowlist; "none" and unknown algs rejected
//     structurally (RFC 8725 §3.1/§3.2)
//   - RSASSA-PKCS1-v1_5 verification over ASCII(header '.' payload)
func Verify(token string, key *rsa.PublicKey) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMalformed
	}
	hdrRaw, err := decodeSegment(parts[0])
	if err != nil {
		return nil, ErrMalformed
	}
	alg, _ := hdrRaw["alg"].(string)
	hash, ok := allowedAlgs[alg]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrAlgRejected, alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformed
	}
	var digest []byte
	signingInput := []byte(parts[0] + "." + parts[1])
	switch hash {
	case crypto.SHA256:
		d := sha256.Sum256(signingInput)
		digest = d[:]
	case crypto.SHA384:
		d := sha512.Sum384(signingInput)
		digest = d[:]
	case crypto.SHA512:
		d := sha512.Sum512(signingInput)
		digest = d[:]
	}
	if err := rsa.VerifyPKCS1v15(key, hash, digest, sig); err != nil {
		return nil, ErrBadSig
	}
	return decodeSegment(parts[1])
}

// ParseHeader decodes just the JOSE header (for kid-based key selection
// before verification — the kid itself is untrusted routing data).
func ParseHeader(token string) (Header, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Header{}, ErrMalformed
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Header{}, ErrMalformed
	}
	var h Header
	if err := json.Unmarshal(raw, &h); err != nil {
		return Header{}, ErrMalformed
	}
	return h, nil
}

func decodeSegment(seg string) (map[string]any, error) {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil, ErrMalformed
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, ErrMalformed
	}
	return m, nil
}

// ---- claim checks (RFC 7519 §4.1; OIDC Core §3.1.3.7) ----------------------

// CheckTime enforces exp (REQUIRED here: a token that cannot expire is a
// rejection — RFC 7519 §4.1.4 with the IMS Security Framework §5.1.3 making
// exp mandatory on launch id_tokens) and, when present, iat/nbf, all with
// bounded clock skew.
func CheckTime(claims map[string]any, now time.Time, skew time.Duration) error {
	exp, ok := numericDate(claims["exp"])
	if !ok {
		return errors.New("jose: exp claim missing")
	}
	if now.After(exp.Add(skew)) {
		return errors.New("jose: token expired")
	}
	if iat, ok := numericDate(claims["iat"]); ok && iat.After(now.Add(skew)) {
		return errors.New("jose: iat in the future")
	}
	if nbf, ok := numericDate(claims["nbf"]); ok && nbf.After(now.Add(skew)) {
		return errors.New("jose: token not yet valid")
	}
	return nil
}

// CheckIssuer enforces exact iss match (OIDC Core §3.1.3.7 step 2).
func CheckIssuer(claims map[string]any, issuer string) error {
	if iss, _ := claims["iss"].(string); iss != issuer || issuer == "" {
		return fmt.Errorf("jose: issuer %q not the expected %q", claims["iss"], issuer)
	}
	return nil
}

// CheckAudience enforces that aud contains clientID, honouring both the
// string and array forms (RFC 7519 §4.1.3), and — when multiple audiences are
// present — that azp, if present, equals clientID (OIDC Core §3.1.3.7 steps
// 3–5, made mandatory for LTI by the IMS Security Framework §5.1.3).
func CheckAudience(claims map[string]any, clientID string) error {
	if clientID == "" {
		return errors.New("jose: empty expected audience")
	}
	var auds []string
	switch v := claims["aud"].(type) {
	case string:
		auds = []string{v}
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok {
				auds = append(auds, s)
			}
		}
	}
	found := false
	for _, a := range auds {
		if a == clientID {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("jose: audience %v does not contain %q", claims["aud"], clientID)
	}
	if len(auds) > 1 {
		if azp, ok := claims["azp"].(string); ok && azp != clientID {
			return fmt.Errorf("jose: azp %q is not %q", azp, clientID)
		}
	}
	return nil
}

func numericDate(v any) (time.Time, bool) {
	f, ok := v.(float64) // JSON numbers decode to float64
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}

// ---- JWKS (RFC 7517) --------------------------------------------------------

// ParseJWKS parses an RSA JWK Set document into kid→public key. Non-RSA and
// malformed entries are skipped, not fatal: a provider may rotate in EC keys
// we do not use; the failure surfaces as "kid not found" at verification.
func ParseJWKS(doc []byte) (map[string]*rsa.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(doc, &set); err != nil {
		return nil, fmt.Errorf("jose: unparseable JWKS: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.N == "" || k.E == "" {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}
	}
	return keys, nil
}
