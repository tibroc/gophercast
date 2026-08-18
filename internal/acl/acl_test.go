// ACL core tests — red-first.
//
// The central case lives HERE, asserted directly rather than via a fixture
// diff (deliberate placement, not a coverage gap): a principal holding both
// an allowed role and a denied role for the same event is the one case where
// D-028 deny-vetoes changes a result set, and the migration fixtures happen
// not to contain such a principal. This test pins the semantics directly,
// where a fixture cannot.
//
// The storage-level proofs (allow+deny for the same pair coexisting,
// three-state read-back, wholesale replace) run against real Postgres and
// live in the integration suite, which is not part of this repository.
package acl

import "testing"

// D-028: a deny vetoes an allow held by the same principal — the exact case
// relocated from the fixture (see package comment).
func TestDenyVetoesAllowMixedPrincipal(t *testing.T) {
	entries := []Entry{
		{Role: "ROLE_COURSE", Action: "read", Allow: true},
		{Role: "ROLE_BANNED", Action: "read", Allow: false},
	}
	// holding only the allowed role: access
	if !Evaluate(entries, StatePopulated, []string{"ROLE_COURSE"}, "read") {
		t.Error("allow-only principal must read")
	}
	// holding only the denied role: no access — and CRUCIALLY the deny must
	// not be read as a grant: evaluation reads the stored allow/deny value,
	// never just the presence of a rule for the role
	if Evaluate(entries, StatePopulated, []string{"ROLE_BANNED"}, "read") {
		t.Error("deny-only principal must not read (a deny must never widen access)")
	}
	// holding BOTH: deny vetoes (D-028) — the non-constructible fixture case
	if Evaluate(entries, StatePopulated, []string{"ROLE_COURSE", "ROLE_BANNED"}, "read") {
		t.Error("deny must veto a held allow (D-028)")
	}
	// the deny is action-scoped: a read deny does not veto write
	entries = append(entries, Entry{Role: "ROLE_COURSE", Action: "write", Allow: true})
	if !Evaluate(entries, StatePopulated, []string{"ROLE_COURSE", "ROLE_BANNED"}, "write") {
		t.Error("read deny must not veto write")
	}
}
