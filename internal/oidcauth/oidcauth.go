// Package oidcauth is ADR-002's delegated-authentication boundary: validate
// OIDC tokens from the ONE operated issuer, read claims, nothing more. All
// federation (SAML/Shibboleth, LDAP, BYO-SP) is the operator's business
// outside this boundary; ocng trusts exactly one issuer — the trust-anchor
// mirror image of internal/lti's per-platform registry, over the same
// internal/jose validation core (T1 step 4 inherits what step 2 proved).
//
// What ocng consumes is a BEARER token presented to its API by a client that
// already ran the login flow (the admin UI, a script). Validation is
// therefore token validation at a resource server: signature against the
// issuer's JWKS, exact issuer, audience (+azp), exp/iat/nbf with skew.
// A nonce is deliberately NOT expected here — OIDC Core §3.1.3.7 step 11
// binds the nonce to the authentication request the CLIENT sent; ocng never
// sent one on this path, so there is nothing to compare against. Where ocng
// itself runs a launch flow and mints the nonce, it is enforced and spent
// (internal/lti, T1 step 2).
//
// Roles come from a claim the operator's IdP is configured to emit (ADR-002:
// "role and attribute mapping moves to IdP configuration" — a Keycloak
// mapper, documented as a contract). A token WITHOUT the claim is a
// rejection, not an empty principal: the mapper is required configuration,
// and failing loudly at the first token beats every request 403ing with no
// explanation.
package oidcauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"ocng/internal/jose"
)

// Config is the delegated-auth trust anchor.
type Config struct {
	// IssuerURL is the ONE operated issuer (its discovery document is
	// resolved at {IssuerURL}/.well-known/openid-configuration).
	IssuerURL string
	// ClientID is the audience ocng requires in tokens (aud, with azp
	// checked when multiple audiences are present).
	ClientID string
	// RolesClaim names the claim carrying the role array. Dotted paths
	// descend into objects — "realm_access.roles" reads Keycloak's default
	// shape without a custom mapper. Default "roles".
	RolesClaim string
	// UsernameClaim names the display-identity claim (default
	// "preferred_username", the OIDC standard claim Keycloak emits).
	UsernameClaim string
	// Skew is the clock tolerance (default 60s).
	Skew time.Duration
}

// Identity is a validated token's projection: everything here has passed
// signature, issuer, audience and time checks.
type Identity struct {
	Subject  string
	Username string
	Roles    []string
	// ActsAs is the SIGNED acts-as assertion (ADR-002: "a service credential
	// plus a signed acts-as assertion", modelled as a distinct trust
	// relationship, never an OIDC flow and NEVER a header). It rides inside
	// the signed token as the `act_as` claim — {"username": ..., "roles":
	// [...]} — so the IdP's signature covers it. Parsing happens here;
	// GATING (the sudo grant) is authn's policy, T1 step 5.
	ActsAs *ActsAs
}

// ActsAs is the asserted effective identity a service principal executes as.
type ActsAs struct {
	Username string
	Roles    []string
}

// ClaimActsAs is the claim carrying the assertion.
const ClaimActsAs = "act_as"

var ErrNoRolesClaim = errors.New("oidcauth: token carries no roles claim — the IdP's role mapper is required configuration (ADR-002)")

// Validator validates bearer tokens against the operated issuer.
type Validator struct {
	cfg  Config
	keys *jose.Fetcher
	now  func() time.Time

	mu      sync.Mutex
	jwksURI string    // discovered
	fetched time.Time // discovery cache stamp
}

// New builds a Validator. Discovery is lazy (first token) and cached, so a
// core booting before its IdP does not crash — it rejects tokens until the
// issuer answers, which is the recoverable-not-HA posture (ADR-006).
func New(cfg Config) *Validator {
	if cfg.RolesClaim == "" {
		cfg.RolesClaim = "roles"
	}
	if cfg.UsernameClaim == "" {
		cfg.UsernameClaim = "preferred_username"
	}
	if cfg.Skew == 0 {
		cfg.Skew = 60 * time.Second
	}
	return &Validator{cfg: cfg, keys: &jose.Fetcher{}, now: time.Now}
}

// Validate checks a compact JWT bearer token and returns the identity.
// Order mirrors the LTI launch core: key resolution, signature (allowlist,
// none rejected — RFC 8725 §3.1), exact issuer (OIDC Core §3.1.3.7 step 2),
// audience+azp (steps 3–5), time with skew (steps 9–10), then claims.
func (v *Validator) Validate(ctx context.Context, token string) (Identity, error) {
	jwksURI, err := v.discoverJWKS(ctx)
	if err != nil {
		return Identity{}, err
	}
	hdr, err := jose.ParseHeader(token)
	if err != nil {
		return Identity{}, err
	}
	key, err := v.keys.Key(ctx, jwksURI, hdr.Kid)
	if err != nil {
		return Identity{}, err
	}
	claims, err := jose.Verify(token, key)
	if err != nil {
		return Identity{}, err
	}
	if err := jose.CheckIssuer(claims, v.cfg.IssuerURL); err != nil {
		return Identity{}, err
	}
	if err := jose.CheckAudience(claims, v.cfg.ClientID); err != nil {
		return Identity{}, err
	}
	if err := jose.CheckTime(claims, v.now(), v.cfg.Skew); err != nil {
		return Identity{}, err
	}

	roles, ok := rolesAt(claims, v.cfg.RolesClaim)
	if !ok || len(roles) == 0 {
		return Identity{}, ErrNoRolesClaim
	}
	id := Identity{Roles: roles}
	id.Subject, _ = claims["sub"].(string)
	id.Username, _ = claims[v.cfg.UsernameClaim].(string)
	if id.Username == "" {
		id.Username = id.Subject
	}
	if raw, present := claims[ClaimActsAs]; present {
		// a malformed assertion on a well-formed token is a rejection, not
		// an ignored claim — the caller is attempting impersonation and the
		// attempt must never be silently dropped
		obj, ok := raw.(map[string]any)
		if !ok {
			return Identity{}, errors.New("oidcauth: malformed act_as claim")
		}
		aa := &ActsAs{}
		aa.Username, _ = obj["username"].(string)
		if arr, ok := obj["roles"].([]any); ok {
			for _, x := range arr {
				if s, ok := x.(string); ok && s != "" {
					aa.Roles = append(aa.Roles, s)
				}
			}
		}
		if aa.Username == "" || len(aa.Roles) == 0 {
			return Identity{}, errors.New("oidcauth: act_as claim needs username and roles")
		}
		id.ActsAs = aa
	}
	return id, nil
}

// rolesAt reads a string array at a (possibly dotted) claim path.
func rolesAt(claims map[string]any, path string) ([]string, bool) {
	var cur any = claims
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[seg]
		if !ok {
			return nil, false
		}
	}
	arr, ok := cur.([]any)
	if !ok {
		return nil, false
	}
	var roles []string
	for _, x := range arr {
		if s, ok := x.(string); ok && s != "" {
			roles = append(roles, s)
		}
	}
	return roles, len(roles) > 0
}

// discoverJWKS resolves and caches the issuer's jwks_uri (OIDC Discovery
// §4). Re-resolved hourly; a live cached value beats a dead issuer.
func (v *Validator) discoverJWKS(ctx context.Context) (string, error) {
	v.mu.Lock()
	uri, fresh := v.jwksURI, time.Since(v.fetched) < time.Hour
	v.mu.Unlock()
	if uri != "" && fresh {
		return uri, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimSuffix(v.cfg.IssuerURL, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if uri != "" {
			return uri, nil // stale beats dead
		}
		return "", fmt.Errorf("oidcauth: discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if uri != "" {
			return uri, nil
		}
		return "", fmt.Errorf("oidcauth: discovery answered %d", resp.StatusCode)
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("oidcauth: unparseable discovery document: %w", err)
	}
	// the discovery document must name the issuer we trust (OIDC Discovery
	// §4.3 issuer validation — a mix-up here re-anchors all trust)
	if doc.Issuer != v.cfg.IssuerURL {
		return "", fmt.Errorf("oidcauth: discovery issuer %q is not the configured %q", doc.Issuer, v.cfg.IssuerURL)
	}
	if doc.JWKSURI == "" {
		return "", errors.New("oidcauth: discovery document has no jwks_uri")
	}
	v.mu.Lock()
	v.jwksURI, v.fetched = doc.JWKSURI, time.Now()
	v.mu.Unlock()
	return doc.JWKSURI, nil
}

// SetNow injects a clock for the conformance suite's time cases.
func (v *Validator) SetNow(now func() time.Time) { v.now = now }
