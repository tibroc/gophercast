package jose

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
)

// SignRS256 mints a compact JWS over claims. Production ocng never signs in
// T1's core-launch scope (the tool only VERIFIES; tool-signed messages belong
// to the out-of-scope Deep Linking response, D-043) — this exists for the
// in-repo conformance suites' in-test platform and in-test issuer, which must
// mint both valid and deliberately malformed tokens with keys the test
// controls.
func SignRS256(claims map[string]any, key *rsa.PrivateKey, kid string) (string, error) {
	return signWith(claims, key, map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
}

// SignWithHeader mints a compact JWS with a caller-controlled header — the
// suites use it to produce alg:none and alg-confusion negatives.
func SignWithHeader(claims map[string]any, key *rsa.PrivateKey, header map[string]any) (string, error) {
	return signWith(claims, key, header)
}

func signWith(claims map[string]any, key *rsa.PrivateKey, header map[string]any) (string, error) {
	hj, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cj, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hj) + "." + base64.RawURLEncoding.EncodeToString(cj)
	if header["alg"] == "none" {
		// RFC 7515 §A.5: unsecured JWS has an empty signature part
		return signingInput + ".", nil
	}
	d := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// JWKSDocument renders the public half of key as a one-key RSA JWK Set
// (RFC 7517) — what the in-test platform/issuer serves over httptest.
func JWKSDocument(key *rsa.PublicKey, kid string) []byte {
	doc, _ := json.Marshal(map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"kid": kid,
			"alg": "RS256",
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}},
	})
	return doc
}
