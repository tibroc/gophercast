package oidcauth

// The OIDC bearer-validation conformance suite over an IN-TEST ISSUER: the
// suite holds the keypair and serves discovery+JWKS from httptest, so every
// malformed token is craftable. The spec text is
// the reference: OIDC Core §3.1.3.7, RFC 7519, RFC 8725. The e2e half — a real
// Keycloak in compose, same-answer-two-doors against the dev seam — is T1
// step 6.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ocng/internal/jose"
)

type testIssuer struct {
	key *rsa.PrivateKey
	kid string
	srv *httptest.Server
	url string
}

// newTestIssuer serves /.well-known/openid-configuration and /jwks for a key
// the test controls. issuerOverride lets the discovery-mismatch case lie
// about its identity.
func newTestIssuer(t *testing.T, issuerOverride string) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ti := &testIssuer{key: key, kid: "op-key-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		iss := ti.url
		if issuerOverride != "" {
			iss = issuerOverride
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"issuer":"` + iss + `","jwks_uri":"` + ti.url + `/jwks"}`))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jose.JWKSDocument(&key.PublicKey, ti.kid))
	})
	ti.srv = httptest.NewServer(mux)
	ti.url = ti.srv.URL
	t.Cleanup(ti.srv.Close)
	return ti
}

const clientID = "ocng-api"

func (ti *testIssuer) claims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":                ti.url,
		"aud":                clientID,
		"sub":                "user-123",
		"preferred_username": "jdoe",
		"exp":                now.Add(5 * time.Minute).Unix(),
		"iat":                now.Unix(),
		"roles":              []any{"ROLE_USER", "ROLE_COURSE_ALPHA"},
	}
}

func (ti *testIssuer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	tok, err := jose.SignRS256(claims, ti.key, ti.kid)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func validator(ti *testIssuer) *Validator {
	return New(Config{IssuerURL: ti.url, ClientID: clientID})
}

// ---- negatives first ---------------------------------------------------------

func TestBearerRejections(t *testing.T) {
	ti := newTestIssuer(t, "")
	ctx := context.Background()

	reject := func(name, clause string, token func() string) {
		t.Run(name, func(t *testing.T) {
			if _, err := validator(ti).Validate(ctx, token()); err == nil {
				t.Errorf("[%s] token accepted", clause)
			}
		})
	}

	// signature is the issuer's identity — RFC 7515 §5.2
	reject("wrong key: signed by a key the issuer never published", "RFC 7515 §5.2", func() string {
		attacker, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		tok, err := jose.SignRS256(ti.claims(), attacker, ti.kid)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	})

	// unsecured JWS never accepted — RFC 8725 §3.1
	reject("alg none", "RFC 8725 §3.1", func() string {
		tok, err := jose.SignWithHeader(ti.claims(), ti.key, map[string]any{"alg": "none", "typ": "JWT", "kid": ti.kid})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	})

	// integrity: a modified payload invalidates the signature — RFC 7515 §5.2
	reject("tampered payload", "RFC 7515 §5.2", func() string {
		tok := ti.sign(t, ti.claims())
		parts := strings.Split(tok, ".")
		// swap the roles claim for an elevated one, keep the old signature
		elevated := ti.claims()
		elevated["roles"] = []any{"ROLE_ADMIN"}
		cj, _ := json.Marshal(elevated)
		parts[1] = base64.RawURLEncoding.EncodeToString(cj)
		return strings.Join(parts, ".")
	})

	// exact issuer — OIDC Core §3.1.3.7 step 2
	reject("wrong iss", "OIDC Core §3.1.3.7 step 2", func() string {
		c := ti.claims()
		c["iss"] = "https://some-other-idp.example"
		return ti.sign(t, c)
	})

	// audience must contain our client_id — OIDC Core §3.1.3.7 step 3
	reject("wrong aud", "OIDC Core §3.1.3.7 step 3", func() string {
		c := ti.claims()
		c["aud"] = "another-app"
		return ti.sign(t, c)
	})

	// multi-audience with azp naming someone else — OIDC Core §3.1.3.7 steps 4-5
	reject("multi-aud with foreign azp", "OIDC Core §3.1.3.7 steps 4-5", func() string {
		c := ti.claims()
		c["aud"] = []any{clientID, "another-app"}
		c["azp"] = "another-app"
		return ti.sign(t, c)
	})

	// time — RFC 7519 §4.1.4; OIDC Core §3.1.3.7 steps 9-10
	reject("expired", "RFC 7519 §4.1.4", func() string {
		c := ti.claims()
		c["exp"] = time.Now().Add(-10 * time.Minute).Unix()
		return ti.sign(t, c)
	})
	reject("iat in the future", "OIDC Core §3.1.3.7 step 10", func() string {
		c := ti.claims()
		c["iat"] = time.Now().Add(10 * time.Minute).Unix()
		return ti.sign(t, c)
	})
	reject("exp missing", "RFC 7519 §4.1.4", func() string {
		c := ti.claims()
		delete(c, "exp")
		return ti.sign(t, c)
	})

	// kid the issuer never published (after the rotation-tolerant refetch)
	reject("unknown kid", "RFC 7515 §4.1.4 key resolution", func() string {
		tok, err := jose.SignWithHeader(ti.claims(), ti.key, map[string]any{"alg": "RS256", "typ": "JWT", "kid": "never-published"})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	})

	// the roles mapper is REQUIRED IdP configuration (ADR-002) — a token
	// without the claim fails loudly at the first request
	reject("missing roles claim", "ADR-002 role-mapping contract", func() string {
		c := ti.claims()
		delete(c, "roles")
		return ti.sign(t, c)
	})
	reject("empty roles claim", "ADR-002 role-mapping contract", func() string {
		c := ti.claims()
		c["roles"] = []any{}
		return ti.sign(t, c)
	})

	// malformed compact JWS
	reject("not a JWT at all", "RFC 7515 §5.2", func() string { return "Bearer-of-bad-news" })
}

// A discovery document naming a DIFFERENT issuer than configured re-anchors
// all trust and must be refused (OIDC Discovery §4.3 issuer validation).
func TestDiscoveryIssuerMismatchRejected(t *testing.T) {
	ti := newTestIssuer(t, "https://liar.example")
	if _, err := validator(ti).Validate(context.Background(), ti.sign(t, ti.claims())); err == nil {
		t.Fatal("validator trusted a discovery document naming a different issuer")
	}
}

// ---- positives ----------------------------------------------------------------

func TestBearerAccepted(t *testing.T) {
	ti := newTestIssuer(t, "")
	id, err := validator(ti).Validate(context.Background(), ti.sign(t, ti.claims()))
	if err != nil {
		t.Fatalf("conformant token rejected: %v", err)
	}
	if id.Subject != "user-123" || id.Username != "jdoe" {
		t.Errorf("identity wrong: %+v", id)
	}
	if len(id.Roles) != 2 || id.Roles[0] != "ROLE_USER" || id.Roles[1] != "ROLE_COURSE_ALPHA" {
		t.Errorf("roles wrong: %v", id.Roles)
	}
}

// Keycloak's default shape needs no custom mapper: a dotted RolesClaim path
// reads realm_access.roles.
func TestBearerDottedRolesClaim(t *testing.T) {
	ti := newTestIssuer(t, "")
	v := New(Config{IssuerURL: ti.url, ClientID: clientID, RolesClaim: "realm_access.roles"})
	c := ti.claims()
	delete(c, "roles")
	c["realm_access"] = map[string]any{"roles": []any{"ROLE_USER"}}
	id, err := v.Validate(context.Background(), ti.sign(t, c))
	if err != nil {
		t.Fatalf("dotted roles claim rejected: %v", err)
	}
	if len(id.Roles) != 1 || id.Roles[0] != "ROLE_USER" {
		t.Errorf("roles wrong: %v", id.Roles)
	}
}

// Username falls back to sub when the preferred claim is absent.
func TestBearerUsernameFallback(t *testing.T) {
	ti := newTestIssuer(t, "")
	c := ti.claims()
	delete(c, "preferred_username")
	id, err := validator(ti).Validate(context.Background(), ti.sign(t, c))
	if err != nil {
		t.Fatal(err)
	}
	if id.Username != "user-123" {
		t.Errorf("username fallback wrong: %q", id.Username)
	}
}
