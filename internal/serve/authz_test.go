package serve

import (
	"testing"

	"ocng/internal/search"
)

// The D-044 decision table. The pins passed in are what the serve-read set
// yields: acl_read already D-028-evaluated at publish time (denies
// subtracted), so a "deny" case here is a pin that EXCLUDES the role even
// though the archive ACL holds an allow for it.
func TestAuthorized(t *testing.T) {
	const mpA = "aaaaaaaa-0000-0000-0000-00000000000a"
	const mpB = "bbbbbbbb-0000-0000-0000-00000000000b"
	pub := func(mp string, roles ...string) PublicationPin {
		if roles == nil {
			roles = []string{}
		}
		return PublicationPin{MediapackageID: mp, ACLRead: roles}
	}
	p := func(roles ...string) search.Principal { return search.Principal{Roles: roles} }

	cases := []struct {
		name string
		pins []PublicationPin
		pr   search.Principal
		want bool
	}{
		// F-C: unpublished — no containing publication → refused, even to a
		// role-rich principal; admins bypass (operational access).
		{"unpublished anonymous", nil, p("ROLE_ANONYMOUS"), false},
		{"unpublished role-rich", nil, p("ROLE_VIEWER", "ROLE_USER"), false},
		{"unpublished admin", nil, p("ROLE_ADMIN"), true},

		// Public: ROLE_ANONYMOUS in the pin admits the anonymous principal
		// by plain intersection — no special case, no credential.
		{"public anonymous", []PublicationPin{pub(mpA, "ROLE_ANONYMOUS")}, p("ROLE_ANONYMOUS"), true},
		{"public authenticated", []PublicationPin{pub(mpA, "ROLE_ANONYMOUS")}, p("ROLE_LTI_LEARNER"), false},

		// Restricted: role required.
		{"restricted with role", []PublicationPin{pub(mpA, "ROLE_COURSE_7")}, p("ROLE_COURSE_7", "ROLE_USER"), true},
		{"restricted without role", []PublicationPin{pub(mpA, "ROLE_COURSE_7")}, p("ROLE_COURSE_8"), false},
		{"restricted anonymous", []PublicationPin{pub(mpA, "ROLE_COURSE_7")}, p("ROLE_ANONYMOUS"), false},

		// Denied-role shape: the archive ACL held allow+deny for ROLE_DENIED;
		// the pin therefore EXCLUDES it (denies are subtracted at publish).
		// The denied role must be refused — a deny never contributes access
		// (D-028).
		{"denied role refused", []PublicationPin{pub(mpA, "ROLE_VIEWER")}, p("ROLE_DENIED"), false},

		// D-032 three-state: ABSENT and EMPTY pins both refuse (fail-closed).
		{"ABSENT pin refused", []PublicationPin{{MediapackageID: mpA, ACLRead: []string{}, ACLState: "ABSENT"}}, p("ROLE_VIEWER"), false},
		{"EMPTY pin refused", []PublicationPin{{MediapackageID: mpA, ACLRead: []string{}, ACLState: "EMPTY"}}, p("ROLE_VIEWER"), false},
		{"ABSENT pin admin bypass", []PublicationPin{{MediapackageID: mpA, ACLRead: []string{}, ACLState: "ABSENT"}}, p("ROLE_GLOBAL_ADMIN"), true},

		// Any-publication-grants union (D-044): readable via EITHER
		// containing publication suffices.
		{"union second grants", []PublicationPin{pub(mpA, "ROLE_X"), pub(mpA, "ROLE_Y")}, p("ROLE_Y"), true},
		{"union neither grants", []PublicationPin{pub(mpA, "ROLE_X"), pub(mpA, "ROLE_Y")}, p("ROLE_Z"), false},

		// Episode-grant synthetic: parity with the EngageEpisode listing
		// surface — delivery and listing must agree.
		{"episode grant", []PublicationPin{pub(mpA)}, p("ROLE_EPISODE_" + mpA + "_READ"), true},
		{"episode grant wrong mp", []PublicationPin{pub(mpA)}, p("ROLE_EPISODE_" + mpB + "_READ"), false},
		{"episode WRITE is not read", []PublicationPin{pub(mpA)}, p("ROLE_EPISODE_" + mpA + "_WRITE"), false},

		// Admin bypass on populated pins too.
		{"admin restricted", []PublicationPin{pub(mpA, "ROLE_COURSE_7")}, p("ROLE_ADMIN"), true},
	}
	for _, c := range cases {
		if got := Authorized(c.pins, c.pr); got != c.want {
			t.Errorf("%s: Authorized(...) = %v, want %v", c.name, got, c.want)
		}
	}
}
