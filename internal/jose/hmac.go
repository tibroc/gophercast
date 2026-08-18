package jose

// HS256 — added for serve-auth Phase B (the stateless LTI session cookie,
// D-044). The session must be validatable with NO database read (it resolves
// inside authn on the serve path, whose pool is the least-privilege
// ocng_serve role), so it is a symmetric-key JWS over the already-bounded
// principal. Same hardened-core posture as Verify: alg pinned exactly,
// "none" and RSA algs rejected structurally, constant-time MAC compare.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// SignHS256 mints a compact JWS over claims with an HMAC-SHA256 signature.
func SignHS256(claims map[string]any, secret []byte) (string, error) {
	hj, err := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	cj, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hj) + "." + base64.RawURLEncoding.EncodeToString(cj)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// VerifyHS256 checks an HMAC-SHA256 compact JWS and returns the claims.
// The alg is pinned to exactly "HS256" — an RS256 (or none) token can never
// pass here regardless of signature bytes (RFC 8725 §3.1 key/alg confusion).
func VerifyHS256(token string, secret []byte) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMalformed
	}
	hdr, err := decodeSegment(parts[0])
	if err != nil {
		return nil, ErrMalformed
	}
	if alg, _ := hdr["alg"].(string); alg != "HS256" {
		return nil, fmt.Errorf("%w: %q", ErrAlgRejected, alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformed
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, ErrBadSig
	}
	return decodeSegment(parts[1])
}
