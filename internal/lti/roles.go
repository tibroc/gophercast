package lti

import (
	"regexp"
	"strings"
)

// Role mapping — THE security keystone of the assertion path (ADR-002 A1;
// the role-mapping bound). An external party asserts these values, so the
// bound is structural, not conventional:
//
//   - every emitted role lives in the ROLE_LTI_* namespace, enforced by a
//     final allowlist filter — the prefix makes collision with operator
//     authority impossible by construction: adminRoles is
//     {ROLE_ADMIN, ROLE_GLOBAL_ADMIN} (search/query.go:48) and the synthetic
//     episode grants match ^ROLE_EPISODE_.+_(READ|WRITE)$ (search/query.go's
//     episode-grant rewrite); neither can begin with ROLE_LTI_.
//   - only CONTEXT (membership) roles carry authority — they are what the
//     LMS asserts per course. Institution- and system-scoped role URIs are
//     deliberately not mapped: ocng has no reason to trust an LMS's claim
//     about a person's standing outside the launched context.
//   - a launch claim can therefore never confer operator/admin authority or
//     an episode grant, no matter what the platform sends. If a legitimate
//     LTI use ever needs a role outside this namespace, that is a
//     D-005/D-006 authorization-model change — stop-and-surface, do not
//     widen the filter.

// membershipPrefix is the LIS v2 context-role vocabulary (LTI Core §A.2).
const membershipPrefix = "http://purl.imsglobal.org/vocab/lis/v2/membership#"

// allowedRole is the structural bound: nothing leaves MapRoles that does not
// match it.
var allowedRole = regexp.MustCompile(`^ROLE_LTI_[A-Z0-9_]{1,64}$`)

// RoleAllowed reports whether r is inside the LTI namespace bound. Exported
// for the stateless session cookie (serve-auth Phase B): the cookie carries
// the BOUNDED principal, and validation re-enforces the bound — a session
// asserting any role outside ROLE_LTI_* is rejected whole, so the T1
// keystone holds through the stateless path even against a mint-side bug or
// a leaked signing key being used to forge wider authority.
func RoleAllowed(r string) bool { return allowedRole.MatchString(r) }

var sanitizeRe = regexp.MustCompile(`[^A-Z0-9]+`)

func sanitize(s string) string {
	s = sanitizeRe.ReplaceAllString(strings.ToUpper(s), "_")
	s = strings.Trim(s, "_")
	if len(s) > 48 {
		s = s[:48]
	}
	return s
}

// MapRoles projects a VALIDATED launch into ocng roles:
//
//	always:            ROLE_LTI_USER (authenticated-by-launch marker)
//	context roles:     …/membership#Instructor → ROLE_LTI_INSTRUCTOR, etc. —
//	                   any fragment of the membership vocabulary, sanitized;
//	                   unknown vocabularies (including bare strings an LMS
//	                   might inject) are IGNORED, not mapped
//	context scoping:   context.id C → ROLE_LTI_CONTEXT_<sanitized C>, the
//	                   per-course handle ACLs can bind to
//
// The returned set is passed through the allowlist filter as the LAST step —
// the bound holds even if a mapping rule above it is wrong.
func MapRoles(l Launch) []string {
	var out []string
	seen := map[string]bool{}
	emit := func(r string) {
		if allowedRole.MatchString(r) && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}

	emit("ROLE_LTI_USER")
	for _, uri := range l.RoleURIs {
		frag, ok := strings.CutPrefix(uri, membershipPrefix)
		if !ok {
			continue // institution/system/unknown vocab: no authority here
		}
		if s := sanitize(frag); s != "" {
			emit("ROLE_LTI_" + s)
		}
	}
	if l.ContextID != "" {
		if s := sanitize(l.ContextID); s != "" {
			emit("ROLE_LTI_CONTEXT_" + s)
		}
	}
	return out
}
