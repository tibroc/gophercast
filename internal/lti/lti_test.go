package lti

// The in-repo LTI 1.3 spec-conformance suite — T1's tier-1 LTI check
// (ratified 2026-08-17; no 1EdTech certification anywhere). The reference is
// the SPEC TEXT: LTI 1.3 Core and the IMS Security Framework 1.0, encoded case by
// case with the clause cited at each case. Negatives first: a launch
// validator that accepts valid launches but under-rejects malformed ones is
// the exact shape of an auth bypass, so the rejections are the contract.
// Tier 2 (saLTIre/lti-ri, including their invalid messages) is T1 step 7.

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"ocng/internal/jose"
)

// testPlatform is the in-test LMS: its own keypair, a JWKS endpoint the tool
// fetches, and a registry entry. The suite controls the keys, so every
// malformed token is craftable.
type testPlatform struct {
	key      *rsa.PrivateKey
	kid      string
	jwksSrv  *httptest.Server
	platform Platform
}

func newTestPlatform(t *testing.T, issuer, clientID string, deployments ...string) *testPlatform {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kid := "test-key-1"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jose.JWKSDocument(&key.PublicKey, kid))
	}))
	t.Cleanup(srv.Close)
	return &testPlatform{
		key: key, kid: kid, jwksSrv: srv,
		platform: Platform{
			Issuer: issuer, ClientID: clientID, DeploymentIDs: deployments,
			JWKSURI: srv.URL, AuthEndpoint: issuer + "/auth",
		},
	}
}

// harness wires a Service over the in-test platform and captures validated
// launches through OnLaunch.
type harness struct {
	svc      *Service
	h        http.Handler
	captured *Launch
}

func newHarness(t *testing.T, platforms ...Platform) *harness {
	t.Helper()
	hn := &harness{}
	hn.svc = &Service{
		Registry: NewRegistry(platforms),
		Store:    NewMemFlowStore(),
		Keys:     &jose.Fetcher{},
		OnLaunch: func(w http.ResponseWriter, r *http.Request, l Launch) {
			hn.captured = &l
			w.WriteHeader(http.StatusOK)
		},
	}
	hn.h = hn.svc.Handler()
	return hn
}

// login drives OIDC third-party-initiated login and returns the state and
// nonce the tool minted plus the state cookie it set.
func (hn *harness) login(t *testing.T, iss, clientID string) (state, nonce string, cookie *http.Cookie) {
	t.Helper()
	q := url.Values{"iss": {iss}, "login_hint": {"user-42"}}
	if clientID != "" {
		q.Set("client_id", clientID)
	}
	r := httptest.NewRequest("GET", "/lti/login?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	hn.h.ServeHTTP(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("login answered %d, want 302", w.Code)
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state, nonce = loc.Query().Get("state"), loc.Query().Get("nonce")
	if state == "" || nonce == "" {
		t.Fatalf("authentication request missing state/nonce: %s", loc)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == stateCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("login set no state cookie")
	}
	return state, nonce, cookie
}

// launch POSTs the form_post callback and returns the status code.
func (hn *harness) launch(t *testing.T, idToken, state string, cookie *http.Cookie) int {
	t.Helper()
	hn.captured = nil
	form := url.Values{"id_token": {idToken}, "state": {state}}
	r := httptest.NewRequest("POST", "/lti/launch", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	hn.h.ServeHTTP(w, r)
	return w.Code
}

// validClaims is a fully conformant LtiResourceLinkRequest (LTI Core §5.3.1's
// required claims, all present). Negatives mutate exactly one thing.
func validClaims(p Platform, nonce string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":              p.Issuer,
		"aud":              p.ClientID,
		"sub":              "user-42",
		"exp":              now.Add(5 * time.Minute).Unix(),
		"iat":              now.Unix(),
		"nonce":            nonce,
		ClaimMessageType:   MessageTypeResourceLink,
		ClaimVersion:       Version,
		ClaimDeploymentID:  p.DeploymentIDs[0],
		ClaimTargetLinkURI: "https://tool.example/launch/target",
		ClaimResourceLink:  map[string]any{"id": "rl-1"},
		ClaimRoles: []any{
			"http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor",
		},
		ClaimContext: map[string]any{"id": "course-7", "label": "OC101"},
	}
}

func (tp *testPlatform) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	tok, err := jose.SignRS256(claims, tp.key, tp.kid)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

const (
	issuer   = "https://lms.example"
	clientID = "ocng-client-1"
	deployID = "deploy-1"
)

// ---- negative cases (the point of the suite) --------------------------------

func TestLaunchRejections(t *testing.T) {
	tp := newTestPlatform(t, issuer, clientID, deployID)

	// each case gets a fresh login flow so exactly ONE thing is wrong
	reject := func(name, clause string, mutate func(h *harness, claims map[string]any) (idToken, state string, cookie *http.Cookie)) {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, tp.platform)
			state, nonce, cookie := h.login(t, issuer, clientID)
			claims := validClaims(tp.platform, nonce)
			idToken, useState, useCookie := mutate(h, claims)
			if idToken == "" {
				idToken = tp.sign(t, claims)
			}
			if useState == "" {
				useState = state
			}
			if useCookie == nil {
				useCookie = cookie
			}
			if code := h.launch(t, idToken, useState, useCookie); code != http.StatusUnauthorized {
				t.Errorf("[%s] accepted with %d, want 401", clause, code)
			}
			if h.captured != nil {
				t.Errorf("[%s] OnLaunch fired for a rejected launch", clause)
			}
		})
	}
	keep := func(h *harness, c map[string]any) (string, string, *http.Cookie) { return "", "", nil }
	_ = keep

	// signature over the assertion is the platform's identity —
	// IMS Security Framework §5.1.3 ("using the public key of the issuer");
	// RFC 7515 §5.2.
	reject("bad signature: signed by a key the platform never published", "IMS Sec §5.1.3 / RFC 7515 §5.2",
		func(h *harness, claims map[string]any) (string, string, *http.Cookie) {
			attacker, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			tok, err := jose.SignRS256(claims, attacker, tp.kid) // right kid, wrong key
			if err != nil {
				t.Fatal(err)
			}
			return tok, "", nil
		})

	// unsecured JWS must never be accepted where a signed token is expected —
	// RFC 8725 §3.1.
	reject("alg none rejected structurally", "RFC 8725 §3.1",
		func(h *harness, claims map[string]any) (string, string, *http.Cookie) {
			tok, err := jose.SignWithHeader(claims, tp.key, map[string]any{"alg": "none", "typ": "JWT"})
			if err != nil {
				t.Fatal(err)
			}
			return tok, "", nil
		})

	// the registry is the trust boundary: an issuer with no registration is
	// a rejection, never a default — IMS Sec §5.1.3 (iss identifies the
	// platform the tool registered with); ADR-002 A1.
	reject("unknown issuer", "IMS Sec §5.1.3 / ADR-002 A1",
		func(h *harness, claims map[string]any) (string, string, *http.Cookie) {
			claims["iss"] = "https://unregistered-lms.example"
			return "", "", nil
		})

	// aud must contain the tool's client_id for THIS registration —
	// OIDC Core §3.1.3.7 step 3, mandatory per IMS Sec §5.1.3.
	reject("wrong audience", "OIDC Core §3.1.3.7 step 3",
		func(h *harness, claims map[string]any) (string, string, *http.Cookie) {
			claims["aud"] = "some-other-tool"
			return "", "", nil
		})

	// exp is mandatory and enforced — RFC 7519 §4.1.4; OIDC Core §3.1.3.7
	// step 9.
	reject("expired token", "RFC 7519 §4.1.4",
		func(h *harness, claims map[string]any) (string, string, *http.Cookie) {
			claims["exp"] = time.Now().Add(-10 * time.Minute).Unix()
			return "", "", nil
		})
	reject("exp claim missing", "RFC 7519 §4.1.4 / IMS Sec §5.1.3",
		func(h *harness, claims map[string]any) (string, string, *http.Cookie) {
			delete(claims, "exp")
			return "", "", nil
		})

	// the nonce must have been minted by THIS tool for a live flow —
	// OIDC Core §3.1.3.7 step 11; IMS Sec §5.1.3.
	reject("nonce claim missing", "OIDC Core §3.1.3.7 step 11",
		func(h *harness, claims map[string]any) (string, string, *http.Cookie) {
			delete(claims, "nonce")
			return "", "", nil
		})
	reject("nonce the tool never minted", "IMS Sec §5.1.3",
		func(h *harness, claims map[string]any) (string, string, *http.Cookie) {
			claims["nonce"] = "attacker-invented-nonce"
			return "", "", nil
		})

	// deployment_id must match a REGISTERED deployment — LTI Core §5.6;
	// unknown deployment is a rejection, not a lookup miss.
	reject("unknown deployment_id", "LTI Core §5.6",
		func(h *harness, claims map[string]any) (string, string, *http.Cookie) {
			claims[ClaimDeploymentID] = "deploy-nobody-registered"
			return "", "", nil
		})

	// message_type: core launch only (D-043); anything else rejected —
	// LTI Core §5.3.1 (message_type REQUIRED and defines the contract).
	reject("wrong message type (LtiDeepLinkingRequest)", "LTI Core §5.3.1 / D-043",
		func(h *harness, claims map[string]any) (string, string, *http.Cookie) {
			claims[ClaimMessageType] = "LtiDeepLinkingRequest"
			return "", "", nil
		})

	// version must be "1.3.0" — LTI Core §5.3.1.
	reject("wrong version claim", "LTI Core §5.3.1",
		func(h *harness, claims map[string]any) (string, string, *http.Cookie) {
			claims[ClaimVersion] = "1.1"
			return "", "", nil
		})

	// required claims of LtiResourceLinkRequest — LTI Core §5.3.1.
	for claim, name := range map[string]string{
		ClaimResourceLink:  "resource_link",
		ClaimRoles:         "roles",
		ClaimTargetLinkURI: "target_link_uri",
		ClaimDeploymentID:  "deployment_id",
	} {
		claim := claim
		reject("required claim missing: "+name, "LTI Core §5.3.1",
			func(h *harness, claims map[string]any) (string, string, *http.Cookie) {
				delete(claims, claim)
				return "", "", nil
			})
	}
	reject("resource_link without id", "LTI Core §5.3.1",
		func(h *harness, claims map[string]any) (string, string, *http.Cookie) {
			claims[ClaimResourceLink] = map[string]any{"title": "no id"}
			return "", "", nil
		})

	// state binds the callback to the flow this tool started —
	// IMS Sec §5.1.1.4 (state) / OAuth 2.0 CSRF.
	reject("state the tool never minted", "IMS Sec §5.1.1.4",
		func(h *harness, claims map[string]any) (string, string, *http.Cookie) {
			return "", "attacker-invented-state", nil
		})
	reject("state cookie present but mismatched", "IMS Sec §5.1.1.4",
		func(h *harness, claims map[string]any) (string, string, *http.Cookie) {
			return "", "", &http.Cookie{Name: stateCookie, Value: "some-other-flow"}
		})
}

// Replay is the nonce store's reason to exist: the SECOND presentation of a
// once-valid token is rejected AFTER the first succeeded — the spend is
// asserted, not just "is the nonce known" (OIDC Core §15.5.2; IMS Sec §5.1.3).
// The attacker does their own fresh login (login is unauthenticated), so
// state is fresh and valid — only the nonce spend stands between a captured
// launch token and a session.
func TestLaunchReplayRejected(t *testing.T) {
	tp := newTestPlatform(t, issuer, clientID, deployID)
	h := newHarness(t, tp.platform)

	state1, nonce1, cookie1 := h.login(t, issuer, clientID)
	token := tp.sign(t, validClaims(tp.platform, nonce1))
	if code := h.launch(t, token, state1, cookie1); code != http.StatusOK {
		t.Fatalf("first launch rejected with %d — replay case needs a successful first use", code)
	}
	if h.captured == nil {
		t.Fatal("first launch did not reach OnLaunch")
	}

	// fresh, legitimate flow; captured token replayed into it
	state2, _, cookie2 := h.login(t, issuer, clientID)
	if code := h.launch(t, token, state2, cookie2); code != http.StatusUnauthorized {
		t.Errorf("replayed token accepted with %d, want 401 — nonce was not spent", code)
	}
	if h.captured != nil {
		t.Error("replayed launch reached OnLaunch")
	}
}

// ---- login initiation rejections --------------------------------------------

func TestLoginRejections(t *testing.T) {
	tp := newTestPlatform(t, issuer, clientID, deployID)
	h := newHarness(t, tp.platform)

	get := func(q url.Values) int {
		r := httptest.NewRequest("GET", "/lti/login?"+q.Encode(), nil)
		w := httptest.NewRecorder()
		h.h.ServeHTTP(w, r)
		return w.Code
	}
	// unknown issuer at login: the registry is the trust boundary from the
	// FIRST message (LTI Core §5.1.1; ADR-002 A1 — no default platform).
	if code := get(url.Values{"iss": {"https://unregistered.example"}, "login_hint": {"u"}}); code != http.StatusForbidden {
		t.Errorf("unknown issuer login answered %d, want 403", code)
	}
	// iss and login_hint are REQUIRED (LTI Core §5.1.1.1)
	if code := get(url.Values{"login_hint": {"u"}}); code != http.StatusBadRequest {
		t.Errorf("missing iss answered %d, want 400", code)
	}
	if code := get(url.Values{"iss": {issuer}}); code != http.StatusBadRequest {
		t.Errorf("missing login_hint answered %d, want 400", code)
	}
}

// ---- the positive case -------------------------------------------------------

func TestLaunchAccepted(t *testing.T) {
	tp := newTestPlatform(t, issuer, clientID, deployID)
	h := newHarness(t, tp.platform)

	state, nonce, cookie := h.login(t, issuer, clientID)
	code := h.launch(t, tp.sign(t, validClaims(tp.platform, nonce)), state, cookie)
	if code != http.StatusOK {
		t.Fatalf("conformant launch rejected with %d", code)
	}
	l := h.captured
	if l == nil {
		t.Fatal("validated launch did not reach OnLaunch")
	}
	if l.Issuer != issuer || l.ClientID != clientID || l.DeploymentID != deployID {
		t.Errorf("trust fields wrong: %+v", l)
	}
	if l.Subject != "user-42" || l.ResourceLinkID != "rl-1" || l.ContextID != "course-7" {
		t.Errorf("identity/context fields wrong: %+v", l)
	}
	if len(l.RoleURIs) != 1 || !strings.HasSuffix(l.RoleURIs[0], "#Instructor") {
		t.Errorf("roles not surfaced: %v", l.RoleURIs)
	}
}

// SameSite realities: cross-site form_post may arrive WITHOUT the state
// cookie (Lax browsers, plain-http dev). The server-side single-use spend of
// state is the hard gate; the cookie is defence in depth — absent is
// tolerated, present-but-wrong is rejected (tested above).
func TestLaunchAcceptedWithoutCookie(t *testing.T) {
	tp := newTestPlatform(t, issuer, clientID, deployID)
	h := newHarness(t, tp.platform)

	state, nonce, _ := h.login(t, issuer, clientID)
	if code := h.launch(t, tp.sign(t, validClaims(tp.platform, nonce)), state, nil); code != http.StatusOK {
		t.Fatalf("cookie-less conformant launch rejected with %d", code)
	}
}
