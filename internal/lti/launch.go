package lti

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"ocng/internal/jose"
)

// stateCookie carries the browser binding for the state value. Cross-site
// form_post realities: SameSite=None requires Secure, which plain-http dev
// shapes lack, so the cookie is DEFENCE IN DEPTH — the hard requirement is
// the server-side single-use spend of state (FlowStore), which no attacker
// can mint. If the cookie arrives it MUST match; if the browser withheld it
// (SameSite), the spend alone gates. A present-but-wrong cookie is always a
// rejection.
const stateCookie = "ocng_lti_state"

const (
	kindState = "state"
	kindNonce = "nonce"
	// flowTTL bounds the login→launch window (IMS Security §5.1.1: the
	// authentication request is short-lived).
	flowTTL = 10 * time.Minute
)

// Service is the LTI tool endpoints: login initiation and launch.
type Service struct {
	Registry *Registry
	Store    FlowStore
	Keys     *jose.Fetcher
	// RedirectPath is the tool's launch path, combined with the inbound
	// request's scheme/host to form redirect_uri (default /lti/launch).
	RedirectPath string
	// Skew is the clock tolerance for exp/iat (default 60s).
	Skew time.Duration
	// Now is injectable for the suite's expiry cases; default time.Now.
	Now func() time.Time
	// OnLaunch handles a VALIDATED launch (session minting is a later T1
	// step; the suite captures the Launch here).
	OnLaunch func(http.ResponseWriter, *http.Request, Launch)
}

// Handler mounts the two tool endpoints.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/lti/login", s.Login)   // GET or POST (LTI Core §5.1.1)
	mux.HandleFunc("/lti/launch", s.Launch) // POST form_post (IMS Security §5.1.2)
	return mux
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) skew() time.Duration {
	if s.Skew != 0 {
		return s.Skew
	}
	return 60 * time.Second
}

// Login is OIDC third-party-initiated login (LTI Core §5.1.1, IMS Security
// §5.1.1): the platform directs the browser here; ocng answers with an
// authentication request back to the platform's authorization endpoint.
// Unknown issuer/client_id → rejection (the registry is the trust boundary).
func (s *Service) Login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed request", http.StatusBadRequest)
		return
	}
	iss := r.Form.Get("iss")
	loginHint := r.Form.Get("login_hint")
	if iss == "" || loginHint == "" {
		// both REQUIRED (LTI Core §5.1.1.1)
		http.Error(w, "iss and login_hint are required", http.StatusBadRequest)
		return
	}
	platform, err := s.Registry.Lookup(iss, r.Form.Get("client_id"))
	if err != nil {
		http.Error(w, "unknown platform", http.StatusForbidden)
		return
	}

	state, nonce := NewValue(), NewValue()
	for kind, v := range map[string]string{kindState: state, kindNonce: nonce} {
		if err := s.Store.Mint(r.Context(), kind, v, flowTTL); err != nil {
			http.Error(w, "flow store unavailable", http.StatusInternalServerError)
			return
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name: stateCookie, Value: state, Path: "/lti/",
		MaxAge: int(flowTTL.Seconds()), HttpOnly: true,
		Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteNoneMode,
	})

	// The authentication request (IMS Security §5.1.1.2: response_type
	// id_token, response_mode form_post, scope openid, prompt none).
	q := url.Values{
		"response_type": {"id_token"},
		"response_mode": {"form_post"},
		"scope":         {"openid"},
		"prompt":        {"none"},
		"client_id":     {platform.ClientID},
		"redirect_uri":  {s.redirectURI(r)},
		"login_hint":    {loginHint},
		"state":         {state},
		"nonce":         {nonce},
	}
	if h := r.Form.Get("lti_message_hint"); h != "" {
		q.Set("lti_message_hint", h)
	}
	http.Redirect(w, r, platform.AuthEndpoint+"?"+q.Encode(), http.StatusFound)
}

func (s *Service) redirectURI(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	path := s.RedirectPath
	if path == "" {
		path = "/lti/launch"
	}
	return scheme + "://" + r.Host + path
}

// Launch is the form_post callback carrying the platform-signed id_token
// (IMS Security §5.1.2). Every rejection is 401 with a uniform body — the
// distinctions live in the suite via the validator's errors, not on the wire.
func (s *Service) Launch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed request", http.StatusBadRequest)
		return
	}
	cookieVal := ""
	if c, err := r.Cookie(stateCookie); err == nil {
		cookieVal = c.Value
	}
	launch, err := s.validate(r.Context(), r.PostForm.Get("id_token"), r.PostForm.Get("state"), cookieVal)
	if err != nil {
		http.Error(w, "launch rejected", http.StatusUnauthorized)
		return
	}
	if s.OnLaunch != nil {
		s.OnLaunch(w, r, launch)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// validate is the launch validation core: IMS Security Framework §5.1.3
// (authentication response validation) plus LTI Core §5.3 (message claims),
// in this order — flow binding, trust-anchor resolution, signature, standard
// claim checks, single-use nonce spend, deployment, message contract. Every
// failure is a rejection; nothing falls through to a default.
func (s *Service) validate(ctx context.Context, idToken, state, stateCookieVal string) (Launch, error) {
	// 1. state: minted by THIS tool and never used before (server-side
	//    single-use spend — the hard gate), and, when the browser sent the
	//    binding cookie, it must match (IMS Sec §5.1.1.4; OAuth 2.0 CSRF).
	if state == "" {
		return Launch{}, fmt.Errorf("lti: no state")
	}
	if stateCookieVal != "" && stateCookieVal != state {
		return Launch{}, fmt.Errorf("lti: state does not match browser binding")
	}
	if ok, err := s.Store.Spend(ctx, kindState, state); err != nil {
		return Launch{}, err
	} else if !ok {
		return Launch{}, fmt.Errorf("lti: state unknown, expired, or already used")
	}

	// 2. trust anchor: the UNVERIFIED iss selects the registration; nothing
	//    else read before Verify is trusted (registry = trust boundary,
	//    ADR-002 A1 — no default platform).
	peek, err := jose.PeekClaims(idToken)
	if err != nil {
		return Launch{}, err
	}
	iss, _ := peek["iss"].(string)
	platform, err := s.Registry.Lookup(iss, "")
	if err != nil {
		return Launch{}, err
	}

	// 3. signature against the platform's published JWKS (IMS Sec §5.1.3;
	//    RFC 7515 §5.2; alg allowlist with none rejected — RFC 8725 §3.1).
	hdr, err := jose.ParseHeader(idToken)
	if err != nil {
		return Launch{}, err
	}
	key, err := s.Keys.Key(ctx, platform.JWKSURI, hdr.Kid)
	if err != nil {
		return Launch{}, err
	}
	claims, err := jose.Verify(idToken, key)
	if err != nil {
		return Launch{}, err
	}

	// 4. standard claims: iss exact, aud contains client_id (+azp), exp
	//    mandatory with skew (OIDC Core §3.1.3.7 steps 2, 3–5, 9–10).
	if err := jose.CheckIssuer(claims, platform.Issuer); err != nil {
		return Launch{}, err
	}
	if err := jose.CheckAudience(claims, platform.ClientID); err != nil {
		return Launch{}, err
	}
	if err := jose.CheckTime(claims, s.now(), s.skew()); err != nil {
		return Launch{}, err
	}

	// 5. nonce: present, minted by this tool, and SPENT here — good exactly
	//    once; a replayed token dies on this line (OIDC Core §15.5.2;
	//    IMS Sec §5.1.3).
	nonce, _ := claims["nonce"].(string)
	if nonce == "" {
		return Launch{}, fmt.Errorf("lti: nonce claim missing")
	}
	if ok, err := s.Store.Spend(ctx, kindNonce, nonce); err != nil {
		return Launch{}, err
	} else if !ok {
		return Launch{}, fmt.Errorf("lti: nonce unknown, expired, or already used")
	}

	// 6. deployment_id must be REGISTERED for this platform (LTI Core §5.6).
	depID, _ := claims[ClaimDeploymentID].(string)
	if depID == "" || !platform.hasDeployment(depID) {
		return Launch{}, fmt.Errorf("lti: deployment_id %q not registered", depID)
	}

	// 7. the message contract (LTI Core §5.3.1 required claims): core
	//    launch only (D-043) — any other message type is a rejection.
	if mt, _ := claims[ClaimMessageType].(string); mt != MessageTypeResourceLink {
		return Launch{}, fmt.Errorf("lti: message type %q not in scope", mt)
	}
	if v, _ := claims[ClaimVersion].(string); v != Version {
		return Launch{}, fmt.Errorf("lti: version %q is not %q", v, Version)
	}
	if tl, _ := claims[ClaimTargetLinkURI].(string); tl == "" {
		return Launch{}, fmt.Errorf("lti: target_link_uri missing")
	}
	rl, _ := claims[ClaimResourceLink].(map[string]any)
	if id, _ := rl["id"].(string); id == "" {
		return Launch{}, fmt.Errorf("lti: resource_link.id missing")
	}
	if _, ok := claims[ClaimRoles].([]any); !ok {
		// REQUIRED claim; MAY be an empty array, but must be present
		return Launch{}, fmt.Errorf("lti: roles claim missing")
	}

	return s.launchFromClaims(claims, platform)
}

// launchFromClaims projects verified claims into the Launch struct.
func (s *Service) launchFromClaims(claims map[string]any, p Platform) (Launch, error) {
	l := Launch{
		Issuer:   p.Issuer,
		ClientID: p.ClientID,
		Claims:   claims,
	}
	l.Subject, _ = claims["sub"].(string)
	l.DeploymentID, _ = claims[ClaimDeploymentID].(string)
	l.TargetLinkURI, _ = claims[ClaimTargetLinkURI].(string)
	if roles, ok := claims[ClaimRoles].([]any); ok {
		for _, x := range roles {
			if s, ok := x.(string); ok {
				l.RoleURIs = append(l.RoleURIs, s)
			}
		}
	}
	if rl, ok := claims[ClaimResourceLink].(map[string]any); ok {
		l.ResourceLinkID, _ = rl["id"].(string)
	}
	if c, ok := claims[ClaimContext].(map[string]any); ok {
		l.ContextID, _ = c["id"].(string)
		l.ContextLabel, _ = c["label"].(string)
	}
	return l, nil
}


