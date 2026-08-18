package jose

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

// HS256 exists for ONE consumer: the stateless LTI session cookie
// (serve-auth Phase B). The negatives mirror the RS256 suite's posture:
// tamper, wrong key, alg confusion, none — all rejected structurally.
func TestHS256(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	claims := map[string]any{"sub": "user-42", "roles": []any{"ROLE_LTI_USER"}}

	tok, err := SignHS256(claims, secret)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyHS256(tok, secret)
	if err != nil {
		t.Fatalf("round-trip: %v", err)
	}
	if got["sub"] != "user-42" {
		t.Fatalf("claims lost in round-trip: %v", got)
	}

	// tampered payload → ErrBadSig
	parts := strings.Split(tok, ".")
	tampered := parts[0] + "." + parts[1][:len(parts[1])-2] + "AA" + "." + parts[2]
	if _, err := VerifyHS256(tampered, secret); err == nil {
		t.Error("tampered token verified")
	}
	// wrong key
	if _, err := VerifyHS256(tok, []byte("another-secret-another-secret-xx")); err == nil {
		t.Error("wrong-key token verified")
	}
	// alg confusion: an RS256 token must NEVER pass HS256 verification —
	// VerifyHS256 pins alg to exactly HS256 (RFC 8725 §3.1)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsTok, err := SignRS256(claims, key, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyHS256(rsTok, secret); err == nil {
		t.Error("RS256 token passed HS256 verification (alg confusion)")
	}
	// alg none
	noneTok, err := SignWithHeader(claims, key, map[string]any{"alg": "none", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyHS256(noneTok, secret); err == nil {
		t.Error("alg:none token passed HS256 verification")
	}
	// malformed
	if _, err := VerifyHS256("not-a-jws", secret); err == nil {
		t.Error("malformed token verified")
	}
}
