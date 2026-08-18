package authn

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"ocng/internal/jose"
	"ocng/internal/oidcauth"
)

func req(t *testing.T, headers map[string]string) *http.Request {
	t.Helper()
	r, err := http.NewRequest("GET", "http://core/admin-ng/event/events.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// Seam-on parsing must be byte-for-byte the pre-T1 semantics the 1–6 suites
// were measured against (adminapi.go:55-67 / searchapi.go:50-62 before the
// step-1 swap).
func TestDevSeamParsingParity(t *testing.T) {
	a := DevSeam(nil)

	cases := []struct {
		name  string
		hdr   string
		roles []string
		ok    bool
	}{
		{"absent header → anonymous", "", []string{"ROLE_ANONYMOUS"}, false},
		{"single role", "ROLE_ADMIN", []string{"ROLE_ADMIN"}, true},
		{"comma list with spaces", " ROLE_USER , ROLE_COURSE_ALPHA ", []string{"ROLE_USER", "ROLE_COURSE_ALPHA"}, true},
		{"empty segments dropped", ",,ROLE_USER,,", []string{"ROLE_USER"}, true},
		{"only separators → anonymous", ", ,", []string{"ROLE_ANONYMOUS"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := map[string]string{}
			if c.hdr != "" {
				h["X-Roles"] = c.hdr
			}
			p, ok := a.Principal(req(t, h))
			if ok != c.ok || !reflect.DeepEqual(p.Roles, c.roles) {
				t.Errorf("got roles=%v ok=%v, want roles=%v ok=%v", p.Roles, ok, c.roles, c.ok)
			}
		})
	}
}

// With the seam OFF (the assembled binary's default), X-Roles is inert: the
// production shape must be closed by the binary itself, not by deployment
// discipline (ADR-012). This is the step-1 slice of the T1 §6 hostility
// matrix.
func TestSeamOffIgnoresXRoles(t *testing.T) {
	a := New(Config{DevSeam: false})
	p, ok := a.Principal(req(t, map[string]string{"X-Roles": "ROLE_ADMIN,ROLE_GLOBAL_ADMIN"}))
	if ok || !reflect.DeepEqual(p.Roles, []string{"ROLE_ANONYMOUS"}) {
		t.Fatalf("seam off must yield anonymous: got roles=%v ok=%v", p.Roles, ok)
	}
	if a.Service(func() *http.Request {
		r := req(t, nil)
		r.SetBasicAuth("admin", "opencast")
		return r
	}()) {
		t.Fatal("seam off must refuse Basic service credentials")
	}
}

// Identity-assumption headers are never consulted — seam on OR off. The
// header set must not elevate and must not authenticate (increment-5 §4.1's
// property at the extraction layer).
func TestIdentityAssumptionHeadersNeverConsulted(t *testing.T) {
	hostile := map[string]string{
		"X-RUN-AS-USER":                    "admin",
		"X-RUN-WITH-ROLES":                 "ROLE_ADMIN",
		"X-Opencast-Matterhorn-User":       "admin",
		"X-Opencast-Matterhorn-Roles":      "ROLE_ADMIN",
		"X-Opencast-Matterhorn-Organization": "mh_default_org",
	}
	for _, a := range []*Authenticator{DevSeam(nil), New(Config{})} {
		p, ok := a.Principal(req(t, hostile))
		if ok || !reflect.DeepEqual(p.Roles, []string{"ROLE_ANONYMOUS"}) {
			t.Fatalf("hostile headers authenticated: roles=%v ok=%v (seam=%v)", p.Roles, ok, a.cfg.DevSeam)
		}
	}
	// and they do not ADD to a legitimate dev-seam identity
	h := map[string]string{"X-Roles": "ROLE_USER"}
	for k, v := range hostile {
		h[k] = v
	}
	p, ok := DevSeam(nil).Principal(req(t, h))
	if !ok || !reflect.DeepEqual(p.Roles, []string{"ROLE_USER"}) {
		t.Fatalf("hostile headers altered a legitimate principal: roles=%v ok=%v", p.Roles, ok)
	}
}

// The dev-seam service path is increment 3's measured shim: valid Basic →
// true, wrong password / unknown user / no header → false.
func TestServiceDevSeam(t *testing.T) {
	a := DevSeam(map[string]string{"admin": "opencast"})
	mk := func(user, pass string, set bool) *http.Request {
		r := req(t, nil)
		if set {
			r.SetBasicAuth(user, pass)
		}
		return r
	}
	if !a.Service(mk("admin", "opencast", true)) {
		t.Fatal("valid credentials refused")
	}
	for name, r := range map[string]*http.Request{
		"wrong password": mk("admin", "wrong", true),
		"unknown user":   mk("nobody", "opencast", true),
		"no header":      mk("", "", false),
	} {
		if a.Service(r) {
			t.Fatalf("%s accepted", name)
		}
	}
}

// ---- OIDC bearer chain (T1 step 4) ------------------------------------------

// bearerIssuer is a minimal in-test issuer (discovery + JWKS over httptest)
// so the chain tests control the keys.
func bearerIssuer(t *testing.T) (*oidcauth.Validator, func(claims map[string]any) string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuerURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"issuer":"` + issuerURL + `","jwks_uri":"` + issuerURL + `/jwks"}`))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Write(jose.JWKSDocument(&key.PublicKey, "k1"))
	})
	srv := httptest.NewServer(mux)
	issuerURL = srv.URL
	t.Cleanup(srv.Close)

	v := oidcauth.New(oidcauth.Config{IssuerURL: issuerURL, ClientID: "ocng-api"})
	sign := func(claims map[string]any) string {
		base := map[string]any{
			"iss": issuerURL, "aud": "ocng-api", "sub": "user-1",
			"exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(),
		}
		for k, val := range claims {
			base[k] = val
		}
		tok, err := jose.SignRS256(base, key, "k1")
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	return v, sign
}

// Identity comes from the VALIDATED token; a presented-but-invalid bearer is
// a hard anonymous and NEVER falls through to the dev seam — the caller
// chose to authenticate and failed.
func TestBearerChain(t *testing.T) {
	v, sign := bearerIssuer(t)
	a := New(Config{DevSeam: true, OIDC: v}) // seam ON: the fallthrough trap is live

	// valid bearer → roles from the token, identity-assumption headers and X-Roles inert
	r := req(t, map[string]string{
		"Authorization": "Bearer " + sign(map[string]any{"roles": []any{"ROLE_USER"}}),
		"X-Roles":       "ROLE_ADMIN",
		"X-RUN-AS-USER": "admin",
	})
	p, ok := a.Principal(r)
	if !ok || !reflect.DeepEqual(p.Roles, []string{"ROLE_USER"}) {
		t.Fatalf("valid bearer: roles=%v ok=%v", p.Roles, ok)
	}

	// invalid bearer + valid X-Roles under an ENABLED seam → anonymous
	r = req(t, map[string]string{
		"Authorization": "Bearer not-a-token",
		"X-Roles":       "ROLE_ADMIN",
	})
	if p, ok := a.Principal(r); ok || !reflect.DeepEqual(p.Roles, []string{"ROLE_ANONYMOUS"}) {
		t.Fatalf("invalid bearer fell through: roles=%v ok=%v", p.Roles, ok)
	}

	// bearer presented with no OIDC configured → anonymous, not seam
	noOIDC := New(Config{DevSeam: true})
	r = req(t, map[string]string{"Authorization": "Bearer whatever", "X-Roles": "ROLE_ADMIN"})
	if _, ok := noOIDC.Principal(r); ok {
		t.Fatal("bearer accepted with no validator configured")
	}
}

// Machine deposits on the OIDC path require a service role.
func TestBearerService(t *testing.T) {
	v, sign := bearerIssuer(t)
	a := New(Config{OIDC: v})

	mk := func(roles ...any) *http.Request {
		return req(t, map[string]string{"Authorization": "Bearer " + sign(map[string]any{"roles": roles})})
	}
	if !a.Service(mk("ROLE_CAPTURE_AGENT")) {
		t.Error("capture-agent bearer refused")
	}
	if !a.Service(mk("ROLE_ADMIN")) {
		t.Error("admin bearer refused")
	}
	if a.Service(mk("ROLE_USER")) {
		t.Error("plain user bearer accepted for a machine deposit")
	}
	if a.Service(req(t, map[string]string{"Authorization": "Bearer garbage"})) {
		t.Error("invalid bearer accepted for a machine deposit")
	}
}

// ---- acts-as gate (T1 step 5, ADR-002) ----------------------------------------

// The signed acts-as assertion is honoured only under the sudo grant; an
// ungranted attempt rejects the whole request; the header form never works.
func TestActsAsGate(t *testing.T) {
	v, sign := bearerIssuer(t)
	a := New(Config{OIDC: v})

	actAs := map[string]any{"username": "jdoe", "roles": []any{"ROLE_USER", "ROLE_COURSE_ALPHA"}}

	// granted: service principal with ROLE_SUDO → effective identity is the
	// asserted one, not the service's own
	r := req(t, map[string]string{"Authorization": "Bearer " + sign(map[string]any{
		"roles": []any{"ROLE_GLOBAL_ADMIN", "ROLE_SUDO"}, "act_as": actAs,
	})})
	p, ok := a.Principal(r)
	if !ok || !reflect.DeepEqual(p.Roles, []string{"ROLE_USER", "ROLE_COURSE_ALPHA"}) {
		t.Fatalf("granted acts-as: roles=%v ok=%v", p.Roles, ok)
	}

	// ungranted: same assertion without ROLE_SUDO → the REQUEST is rejected,
	// not downgraded to the caller's own identity
	r = req(t, map[string]string{"Authorization": "Bearer " + sign(map[string]any{
		"roles": []any{"ROLE_GLOBAL_ADMIN"}, "act_as": actAs,
	})})
	if p, ok := a.Principal(r); ok {
		t.Fatalf("ungranted acts-as accepted: roles=%v", p.Roles)
	}

	// malformed assertion on a valid token → rejected at validation
	r = req(t, map[string]string{"Authorization": "Bearer " + sign(map[string]any{
		"roles": []any{"ROLE_SUDO"}, "act_as": "jdoe",
	})})
	if _, ok := a.Principal(r); ok {
		t.Fatal("malformed act_as accepted")
	}

	// the HEADER form never works, sudo or not (ADR-002 constraint 2)
	r = req(t, map[string]string{
		"Authorization": "Bearer " + sign(map[string]any{"roles": []any{"ROLE_SUDO", "ROLE_USER"}}),
		"X-RUN-AS-USER": "admin",
		"X-Opencast-Matterhorn-User": "admin",
	})
	p, ok = a.Principal(r)
	if !ok || !reflect.DeepEqual(p.Roles, []string{"ROLE_SUDO", "ROLE_USER"}) {
		t.Fatalf("header impersonation altered the principal: roles=%v ok=%v", p.Roles, ok)
	}
}
