// Package authn is T1's single principal-extraction layer: the ONE place a
// request becomes a search.Principal.
//
// Increments 1–6 grew four seam shapes — a duplicated X-Roles parser in
// adminapi and searchapi, a Basic-auth bool shim in ingest, and none in serve
// (reference-as-capability delivery; serve authorization is T2's serve-read-set
// concern). T1 step 1 centralizes extraction here behind the stable interface
// (search.Principal); everything downstream of extraction is untouched.
//
// The resolution chain, fixed here even before all links exist:
//
//  1. OIDC bearer token (ADR-002 delegated authentication) — T1 step 4.
//  2. LTI 1.3 session minted by a validated launch (ADR-002 A1 platform
//     assertion) — T1 steps 2–3.
//  3. The dev seam — the X-Roles header and Basic service credentials —
//     ONLY when explicitly enabled (OCNG_DEV_AUTH). Never a production
//     mechanism; the production default is OFF, per ADR-012: core closes
//     the seam itself rather than trusting deployment discipline.
//
// NEVER consulted, on any path, regardless of configuration:
// X-RUN-AS-*, X-Opencast-Matterhorn-* — ocng-core rejects these
// identity-assumption headers itself, and the increment-5 §4.1 test is the
// standing regression. Acts-as impersonation is
// a signed-claim mechanism on authenticated principals (T1 step 5), not a
// header.
package authn

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"ocng/internal/oidcauth"
	"ocng/internal/search"
)

// Config wires an Authenticator. The LTI session hook is added by a later T1
// step; steps 1+4 carry the dev seam and OIDC bearer validation.
type Config struct {
	// OIDC validates Authorization: Bearer tokens against the ONE operated
	// issuer (ADR-002, T1 step 4). When a bearer is PRESENTED, it decides —
	// an invalid credential never falls through to the dev seam or to
	// anonymous-with-lesser-checks; the caller chose to authenticate and
	// failed.
	OIDC *oidcauth.Validator
	// ServiceRoles gates machine deposits (/ingest) on the OIDC path: a
	// valid bearer must carry one of these. Interim contract until the T5
	// operator-config surface; default ROLE_ADMIN / ROLE_GLOBAL_ADMIN /
	// ROLE_CAPTURE_AGENT (the legacy system's ingest population).
	ServiceRoles []string
	// DevSeam honours the X-Roles header (interactive principals) and HTTP
	// Basic against ServiceUsers (machine deposits on /ingest). Dev/test
	// only — the assembled binary defaults it OFF (OCNG_DEV_AUTH).
	DevSeam bool
	// ServiceUsers are the dev-seam machine credentials (/ingest shim,
	// unchanged semantics from increment 3's Options.Users).
	ServiceUsers map[string]string
	// Session resolves the stateless LTI session cookie (chain link 2,
	// serve-auth Phase B — session.go). Nil when no LTI surface is mounted.
	Session *SessionCodec
}

// Authenticator resolves inbound requests to principals. One instance is
// shared by every HTTP surface of a process.
type Authenticator struct {
	cfg Config
}

func New(cfg Config) *Authenticator { return &Authenticator{cfg: cfg} }

// DevSeam is the seam-enabled authenticator the 1–6 suites and dev harnesses
// run on: exactly the pre-T1 behaviour. Handler constructors default to it so
// in-process test construction (httptest over adminapi/searchapi/ingest)
// needs no change; the assembled binary overrides it from OCNG_DEV_AUTH.
func DevSeam(serviceUsers map[string]string) *Authenticator {
	return New(Config{DevSeam: true, ServiceUsers: serviceUsers})
}

// Info is the non-authorization half of a resolved identity: what
// /info/me.json displays. Username is empty under the dev seam — the caller
// keeps its existing roles-derived stand-in, so the increment-5 tier-1
// contract is byte-identical on the dev shape.
type Info struct {
	Username string
	Method   string // "oidc", "dev-seam", "anonymous" (LTI lands with its session step)
}

// Principal resolves the request's interactive identity.
// ok=false means anonymous: the caller decides whether the surface admits
// ROLE_ANONYMOUS (engage /search) or 403s (admin-ng, /api — the measured
// legacy behaviour).
func (a *Authenticator) Principal(r *http.Request) (search.Principal, bool) {
	p, _, ok := a.Resolve(r)
	return p, ok
}

// Resolve is Principal plus display identity (T1 step 6: me.json reports the
// authn-resolved principal).
func (a *Authenticator) Resolve(r *http.Request) (search.Principal, Info, bool) {
	// 1. OIDC bearer (T1 step 4): identity from the VALIDATED token only.
	//    A presented-but-invalid bearer is a hard anonymous — never a
	//    fallthrough to the seam.
	if token, ok := bearerToken(r); ok {
		if a.cfg.OIDC == nil {
			return anonymousResolved()
		}
		id, err := a.cfg.OIDC.Validate(r.Context(), token)
		if err != nil {
			return anonymousResolved()
		}
		// Acts-as gate (T1 step 5, ADR-002): the SIGNED assertion is
		// honoured only when the authenticated principal itself holds the
		// sudo grant. An ungranted impersonation attempt is a rejection of
		// the whole request — never a silent fallback to the caller's own
		// identity. Anonymous and LTI principals can never reach this
		// branch: the assertion exists only inside a validated bearer.
		if id.ActsAs != nil {
			if !hasRole(id.Roles, SudoRole) {
				return anonymousResolved()
			}
			return search.Principal{Roles: id.ActsAs.Roles}, Info{Username: id.ActsAs.Username, Method: "oidc"}, true
		}
		return search.Principal{Roles: id.Roles}, Info{Username: id.Username, Method: "oidc"}, true
	}
	// 2. LTI session (serve-auth Phase B, closing the T1 F-A placeholder):
	//    the signed stateless cookie carrying the launch-time BOUNDED
	//    principal — validated by pure computation, no DB read (that is
	//    what keeps the serve path on the ocng_serve pool). A PRESENTED
	//    cookie decides, same posture as the bearer above: tampered,
	//    expired or bound-violating sessions are a hard anonymous, never a
	//    fallthrough to the seam.
	if a.cfg.Session != nil {
		if ck, err := r.Cookie(SessionCookie); err == nil {
			if p, info, ok := a.cfg.Session.Validate(ck.Value); ok {
				return p, info, true
			}
			return anonymousResolved()
		}
	}
	// 3. Dev seam.
	if a.cfg.DevSeam {
		if hdr := r.Header.Get("X-Roles"); hdr != "" {
			var roles []string
			for _, x := range strings.Split(hdr, ",") {
				if x = strings.TrimSpace(x); x != "" {
					roles = append(roles, x)
				}
			}
			if len(roles) > 0 {
				return search.Principal{Roles: roles}, Info{Method: "dev-seam"}, true
			}
		}
	}
	return anonymousResolved()
}

func anonymousResolved() (search.Principal, Info, bool) {
	return search.Principal{Roles: []string{"ROLE_ANONYMOUS"}}, Info{Method: "anonymous"}, false
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:]), true
	}
	return "", false
}

// SudoRole is the grant that authorizes acts-as impersonation (ADR-002: the
// legacy system gated impersonation on global admin + sudo; ocng's
// redesign keeps the property under a cleaner primitive — the grant lives on
// the service principal's own token, the assertion inside the same
// signature).
const SudoRole = "ROLE_SUDO"

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

var defaultServiceRoles = []string{"ROLE_ADMIN", "ROLE_GLOBAL_ADMIN", "ROLE_CAPTURE_AGENT"}

// Service authorizes machine callers (/ingest). Production: an OIDC bearer
// (client-credentials or a user token) carrying one of ServiceRoles. Dev
// seam: HTTP Basic against ServiceUsers — increment 3's measured shim
// semantics, constant-time compare, any failure indistinguishable (the
// surface answers 403).
func (a *Authenticator) Service(r *http.Request) bool {
	if token, ok := bearerToken(r); ok {
		if a.cfg.OIDC == nil {
			return false
		}
		id, err := a.cfg.OIDC.Validate(r.Context(), token)
		if err != nil {
			return false
		}
		allowed := a.cfg.ServiceRoles
		if len(allowed) == 0 {
			allowed = defaultServiceRoles
		}
		for _, have := range id.Roles {
			for _, want := range allowed {
				if have == want {
					return true
				}
			}
		}
		return false
	}
	if a.cfg.DevSeam {
		user, pass, ok := r.BasicAuth()
		if !ok {
			return false
		}
		want, known := a.cfg.ServiceUsers[user]
		return known && subtle.ConstantTimeCompare([]byte(pass), []byte(want)) == 1
	}
	return false
}
