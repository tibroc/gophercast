// The stateless LTI session — serve-auth Phase B (D-044, closing the T1
// F-A placeholder: authn chain link 2).
//
// Design, ratified 2026-08-17 (Option 2): a short-TTL HttpOnly cookie whose
// value is an HS256-signed JWS carrying the ALREADY-BOUNDED principal —
// lti.MapRoles runs AT LAUNCH and only its output is signed, never the raw
// launch claims, so resolving the cookie can never re-map or widen anything.
// Validation is pure computation (signature + time + namespace bound): NO
// database read, which is what keeps the serve path on the ocng_serve pool
// with the serve-read set exactly as ratified — the alternative (a session
// table) would have grown the set and forced a T2 invariant re-check.
// Accepted cost: no server-side revocation inside the TTL.
//
// The namespace bound (T1's security keystone) is enforced TWICE: Mint
// refuses to sign any role outside ROLE_LTI_*, and Validate rejects the
// whole session if one appears — so even a forged-with-the-real-key cookie
// cannot carry ROLE_ADMIN or an episode synthetic into a principal.
package authn

import (
	"net/http"
	"net/url"
	"time"

	"ocng/internal/jose"
	"ocng/internal/lti"
	"ocng/internal/search"
)

// SessionCookie is the LTI session cookie name.
const SessionCookie = "ocng_lti_session"

// DefaultSessionTTL is deliberately short (the "short-TTL" posture:
// roughly one lecture) — expiry is the only revocation this design has.
const DefaultSessionTTL = 2 * time.Hour

// sessionSkew tolerates small clock drift between replicas sharing the
// secret (the same posture as oidcauth's validation skew).
const sessionSkew = 30 * time.Second

// SessionCodec signs and validates the stateless LTI session cookie. One
// codec per process; every core replica must share Secret (login, launch
// and delivery may hit different replicas — ADR-009).
type SessionCodec struct {
	Secret []byte
	TTL    time.Duration    // zero → DefaultSessionTTL
	Now    func() time.Time // injectable for expiry tests; default time.Now
}

func (c *SessionCodec) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *SessionCodec) ttl() time.Duration {
	if c.TTL > 0 {
		return c.TTL
	}
	return DefaultSessionTTL
}

// Mint signs the bounded principal into a cookie value. Every role must be
// inside the ROLE_LTI_* bound — a caller handing anything else is a bug in
// the one place allowed to mint, and the refusal is loud, not a filter.
func (c *SessionCodec) Mint(username string, roles []string) (string, error) {
	for _, r := range roles {
		if !lti.RoleAllowed(r) {
			return "", ErrRoleOutsideBound
		}
	}
	now := c.now()
	anyRoles := make([]any, len(roles))
	for i, r := range roles {
		anyRoles[i] = r
	}
	return jose.SignHS256(map[string]any{
		"sub":   username,
		"roles": anyRoles,
		"iat":   now.Unix(),
		"exp":   now.Add(c.ttl()).Unix(),
	}, c.Secret)
}

// ErrRoleOutsideBound: an attempt to mint a session carrying a role outside
// the ROLE_LTI_* namespace (T1 keystone).
var ErrRoleOutsideBound = errRoleOutsideBound{}

type errRoleOutsideBound struct{}

func (errRoleOutsideBound) Error() string {
	return "authn: refusing to mint an LTI session with a role outside ROLE_LTI_*"
}

// Validate checks a presented cookie value: signature, time window, and the
// namespace bound. ok=false for anything wrong — tampered, expired, or
// carrying a role outside ROLE_LTI_* (the whole session is rejected, never
// filtered down).
func (c *SessionCodec) Validate(value string) (search.Principal, Info, bool) {
	claims, err := jose.VerifyHS256(value, c.Secret)
	if err != nil {
		return search.Principal{}, Info{}, false
	}
	if err := jose.CheckTime(claims, c.now(), sessionSkew); err != nil {
		return search.Principal{}, Info{}, false
	}
	rawRoles, ok := claims["roles"].([]any)
	if !ok || len(rawRoles) == 0 {
		return search.Principal{}, Info{}, false
	}
	roles := make([]string, 0, len(rawRoles))
	for _, v := range rawRoles {
		r, ok := v.(string)
		if !ok || !lti.RoleAllowed(r) {
			return search.Principal{}, Info{}, false
		}
		roles = append(roles, r)
	}
	username, _ := claims["sub"].(string)
	return search.Principal{Roles: roles}, Info{Username: username, Method: "lti"}, true
}

// LTISessionOnLaunch is the lti.Service OnLaunch hook (wired in
// cmd/ocng-core and in the e2e suite — one implementation, no copy): a
// VALIDATED launch is mapped to the bounded principal (lti.MapRoles — this
// is the ONLY place launch claims become roles), signed into the session
// cookie, and the browser is redirected into the target resource.
func LTISessionOnLaunch(c *SessionCodec) func(http.ResponseWriter, *http.Request, lti.Launch) {
	return func(w http.ResponseWriter, r *http.Request, l lti.Launch) {
		value, err := c.Mint(l.Subject, lti.MapRoles(l))
		if err != nil {
			// MapRoles output failing the bound would be a keystone break;
			// fail the launch loudly rather than issue anything.
			http.Error(w, "session minting failed", http.StatusInternalServerError)
			return
		}
		// Cross-site delivery (LMS iframe) requires SameSite=None+Secure,
		// which browsers only accept over TLS; the dev shape (plain HTTP)
		// gets Lax, which covers top-level navigation launches.
		sameSite, secure := http.SameSiteLaxMode, false
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			sameSite, secure = http.SameSiteNoneMode, true
		}
		http.SetCookie(w, &http.Cookie{
			Name: SessionCookie, Value: value, Path: "/",
			MaxAge: int(c.ttl().Seconds()), HttpOnly: true,
			SameSite: sameSite, Secure: secure,
		})
		// Redirect into the target resource by PATH only — the target URI
		// is platform-supplied; keeping the redirect relative removes the
		// open-redirect class entirely.
		target := "/"
		if u, err := url.Parse(l.TargetLinkURI); err == nil && u.Path != "" {
			target = u.Path
			if u.RawQuery != "" {
				target += "?" + u.RawQuery
			}
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
	}
}
