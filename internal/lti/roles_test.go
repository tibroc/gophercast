package lti

// The hostile-claims test — T1 step 3's stop-trigger check. An LMS asserts
// the roles claim, so the mapper is fed operator-authority strings, episode
// synthetics, and vocabulary games, and the output must come out BOUNDED:
// only ROLE_LTI_*, never adminRoles (ROLE_ADMIN/ROLE_GLOBAL_ADMIN — the
// IsAdmin gate, search/query.go:48-50), never the synthetic
// ROLE_EPISODE_{id}_{READ|WRITE} shapes (an asserted episode-write would be
// an ACL bypass, not just an unwanted admin grant).

import (
	"regexp"
	"strings"
	"testing"
)

var (
	ltiNamespace = regexp.MustCompile(`^ROLE_LTI_[A-Z0-9_]+$`)
	episodeShape = regexp.MustCompile(`^ROLE_EPISODE_.+_(READ|WRITE)$`)
)

func assertBounded(t *testing.T, roles []string) {
	t.Helper()
	for _, r := range roles {
		if !ltiNamespace.MatchString(r) {
			t.Errorf("role %q escapes the ROLE_LTI_ namespace", r)
		}
		if r == "ROLE_ADMIN" || r == "ROLE_GLOBAL_ADMIN" {
			t.Errorf("role %q is operator authority (adminRoles, search/query.go:48)", r)
		}
		if episodeShape.MatchString(r) {
			t.Errorf("role %q matches the synthetic episode-grant shape", r)
		}
	}
}

func TestMapRolesHostileClaims(t *testing.T) {
	hostile := Launch{
		RoleURIs: []string{
			// operator authority injected verbatim
			"ROLE_ADMIN",
			"ROLE_GLOBAL_ADMIN",
			// episode-grant synthetics (the ACL bypass shape)
			"ROLE_EPISODE_abc123_WRITE",
			"ROLE_EPISODE_abc123_READ",
			// vocabulary games: right-looking URIs outside the membership vocab
			"http://purl.imsglobal.org/vocab/lis/v2/system/person#Administrator",
			"http://purl.imsglobal.org/vocab/lis/v2/institution/person#Administrator",
			"http://evil.example/vocab#ROLE_ADMIN",
			// membership vocab with a hostile fragment — mapped, but prefixed
			membershipPrefix + "Administrator",
			membershipPrefix + "EPISODE_x_WRITE",
			// injection attempts through sanitization
			membershipPrefix + "../../ROLE_ADMIN",
			membershipPrefix + "Instructor,ROLE_ADMIN",
			// a legitimate role among the hostile ones
			membershipPrefix + "Instructor",
		},
		// hostile context ids: must come out prefixed, never as a bare role
		ContextID: "x_WRITE'; DROP TABLE lti_flow;--",
	}
	roles := MapRoles(hostile)
	assertBounded(t, roles)

	has := func(want string) bool {
		for _, r := range roles {
			if r == want {
				return true
			}
		}
		return false
	}
	if !has("ROLE_LTI_USER") {
		t.Error("ROLE_LTI_USER marker missing")
	}
	if !has("ROLE_LTI_INSTRUCTOR") {
		t.Errorf("legitimate Instructor role lost among hostile claims: %v", roles)
	}
	// the membership Administrator maps — as ROLE_LTI_ADMINISTRATOR, which
	// carries no operator authority (context-scoped by namespace)
	if !has("ROLE_LTI_ADMINISTRATOR") {
		t.Errorf("membership#Administrator should map inside the namespace: %v", roles)
	}
	// non-membership vocabularies must not have produced anything: count the
	// legitimate outputs and assert nothing else appeared
	for _, r := range roles {
		if strings.HasPrefix(r, "ROLE_LTI_CONTEXT_") {
			continue
		}
		switch r {
		case "ROLE_LTI_USER", "ROLE_LTI_INSTRUCTOR", "ROLE_LTI_ADMINISTRATOR",
			"ROLE_LTI_EPISODE_X_WRITE", "ROLE_LTI_ROLE_ADMIN", "ROLE_LTI_INSTRUCTOR_ROLE_ADMIN":
			// membership-vocab fragments, hostile but namespace-bounded
		default:
			t.Errorf("unexpected role %q emitted", r)
		}
	}
}

// The plain case: an Instructor launch in a course maps to the marker, the
// membership role, and the context handle — nothing else.
func TestMapRolesPlain(t *testing.T) {
	l := Launch{
		RoleURIs:  []string{membershipPrefix + "Learner"},
		ContextID: "course-7",
	}
	roles := MapRoles(l)
	assertBounded(t, roles)
	want := []string{"ROLE_LTI_USER", "ROLE_LTI_LEARNER", "ROLE_LTI_CONTEXT_COURSE_7"}
	if len(roles) != len(want) {
		t.Fatalf("got %v, want %v", roles, want)
	}
	for i := range want {
		if roles[i] != want[i] {
			t.Fatalf("got %v, want %v", roles, want)
		}
	}
}

// Empty roles claim (REQUIRED but MAY be empty — LTI Core §5.3.1): the
// principal is still a launch-authenticated user with the context handle,
// nothing more.
func TestMapRolesEmptyClaim(t *testing.T) {
	roles := MapRoles(Launch{ContextID: "course-7"})
	assertBounded(t, roles)
	if len(roles) != 2 || roles[0] != "ROLE_LTI_USER" || roles[1] != "ROLE_LTI_CONTEXT_COURSE_7" {
		t.Fatalf("got %v", roles)
	}
}
