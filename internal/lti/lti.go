// Package lti is the tool half of LTI 1.3 core launch — ocng's SECOND trust
// model (ADR-002 A1: platform assertion; an LMS asserts a user into ocng via a
// signed launch, ocng never sees the user authenticate). Scope is the core
// launch ONLY: no AGS, no NRPS, Deep Linking on a named adopter use (D-043).
// LTI 1.1/OAuth1 is deliberately not carried (D-042).
//
// The reference is the SPEC TEXT itself (D-020):
// LTI 1.3 Core (https://www.imsglobal.org/spec/lti/v1p3) and the
// IMS Security Framework 1.0 (https://www.imsglobal.org/spec/security/v1p0).
// The in-repo conformance suite (lti_test.go) encodes it case by case,
// negatives first — under-rejection is the auth-bypass shape, so the
// rejections ARE the contract. Second tier: the saLTIre/lti-ri emulator pass
// (T1 step 7). No 1EdTech certification anywhere (ratified 2026-08-17;
// a stated limit).
//
// Trust boundary: the platform registry. Every launch resolves (issuer,
// client_id, deployment_id) against operator-configured registrations; an
// unknown value is a structural rejection — there is no default platform.
// Signature verification shares internal/jose with the OIDC path (same JWS
// core, different trust anchor: per-platform JWKS here, the one operated
// issuer there).
package lti

import (
	"fmt"
)

// LTI 1.3 claim URIs (LTI Core §5.3).
const (
	ClaimMessageType   = "https://purl.imsglobal.org/spec/lti/claim/message_type"
	ClaimVersion       = "https://purl.imsglobal.org/spec/lti/claim/version"
	ClaimDeploymentID  = "https://purl.imsglobal.org/spec/lti/claim/deployment_id"
	ClaimTargetLinkURI = "https://purl.imsglobal.org/spec/lti/claim/target_link_uri"
	ClaimResourceLink  = "https://purl.imsglobal.org/spec/lti/claim/resource_link"
	ClaimRoles         = "https://purl.imsglobal.org/spec/lti/claim/roles"
	ClaimContext       = "https://purl.imsglobal.org/spec/lti/claim/context"

	// MessageTypeResourceLink is the ONE message type in scope (D-043).
	MessageTypeResourceLink = "LtiResourceLinkRequest"
	// Version is the only accepted LTI version claim value (LTI Core §5.3).
	Version = "1.3.0"
)

// Platform is one registered LMS: operator-configured trust data with the
// same review weight as IdP configuration (ADR-002 A1).
type Platform struct {
	Issuer        string   `json:"issuer"`
	ClientID      string   `json:"client_id"`
	DeploymentIDs []string `json:"deployment_ids"`
	JWKSURI       string   `json:"jwks_uri"`
	AuthEndpoint  string   `json:"auth_endpoint"`
}

func (p Platform) hasDeployment(id string) bool {
	for _, d := range p.DeploymentIDs {
		if d == id {
			return true
		}
	}
	return false
}

// Registry is the assertion path's trust boundary. Unknown (issuer,
// client_id) is a REJECTION, never a lookup miss that falls through — there
// is no default platform.
type Registry struct {
	platforms []Platform
}

func NewRegistry(platforms []Platform) *Registry {
	return &Registry{platforms: platforms}
}

// Lookup resolves a registration. clientID may be empty (the OIDC login
// initiation's client_id parameter is OPTIONAL — LTI Core §5.1.1.1), in which
// case the issuer must have exactly one registration; ambiguity is a
// rejection, not a guess.
func (g *Registry) Lookup(issuer, clientID string) (Platform, error) {
	var found []Platform
	for _, p := range g.platforms {
		if p.Issuer != issuer {
			continue
		}
		if clientID == "" || p.ClientID == clientID {
			found = append(found, p)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return Platform{}, fmt.Errorf("lti: no registered platform for issuer %q client_id %q", issuer, clientID)
	default:
		return Platform{}, fmt.Errorf("lti: issuer %q has %d registrations; client_id required", issuer, len(found))
	}
}

// Launch is a VALIDATED resource-link launch: everything here has passed
// signature, issuer, audience, time, nonce, deployment and message-type
// checks. Raw claims are retained for the role mapper and future display.
type Launch struct {
	Issuer         string
	ClientID       string
	DeploymentID   string
	Subject        string // sub; may be empty (anonymous launch, LTI Core §5.3.3)
	RoleURIs       []string
	ContextID      string
	ContextLabel   string
	ResourceLinkID string
	TargetLinkURI  string
	Claims         map[string]any
}
