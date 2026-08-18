// ACL core tests — red-first.
//
// The central case lives HERE, asserted directly rather than via a fixture
// diff (deliberate placement, not a coverage gap): a principal holding both
// an allowed role and a denied role for the same event is the one case where
// D-028 deny-vetoes changes a result set, and the migration fixtures happen
// not to contain such a principal. These tests pin the semantics directly,
// where a fixture cannot.
package acl

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("OCNG_E2E_PG")
	if url == "" {
		url = "postgres://ocng:ocng@127.0.0.1:15432/ocng"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Skipf("postgres not available: %v", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func set(t *testing.T, pool *pgxpool.Pool, scope Scope, id string, entries []Entry) {
	t.Helper()
	err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		return SetTx(context.Background(), tx, scope, id, entries)
	})
	if err != nil {
		t.Fatalf("SetTx: %v", err)
	}
}

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

// allow+deny for the SAME (role, action) must coexist in storage, so that
// authorization can never become order-dependent: the schema stores both
// and evaluation is order-independent (deny wins both ways).
func TestAllowDenySamePairBothStoredOrderIndependent(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	for name, ordered := range map[string][]Entry{
		"allow-then-deny": {{Role: "R", Action: "read", Allow: true}, {Role: "R", Action: "read", Allow: false}},
		"deny-then-allow": {{Role: "R", Action: "read", Allow: false}, {Role: "R", Action: "read", Allow: true}},
	} {
		id := "pair-" + name
		set(t, pool, ScopeEvent, id, ordered)
		got, state, err := Get(ctx, pool, ScopeEvent, id)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if state != StatePopulated || len(got) != 2 {
			t.Errorf("%s: want both entries stored (no collapse), got %v %v", name, state, got)
		}
		if Evaluate(got, state, []string{"R"}, "read") {
			t.Errorf("%s: deny must win regardless of write order", name)
		}
	}
}

// D-032: the three states are distinguishable, and both non-POPULATED
// states deny.
func TestD032ThreeStates(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	// ABSENT: no policy ever set
	entries, state, err := Get(ctx, pool, ScopeEvent, "d032-never-set")
	if err != nil {
		t.Fatal(err)
	}
	if state != StateAbsent || entries != nil {
		t.Errorf("want ABSENT/nil, got %v %v", state, entries)
	}
	if Evaluate(entries, state, []string{"ROLE_ANY"}, "read") {
		t.Error("ABSENT must deny")
	}

	// EMPTY: a policy set that grants nothing — distinguishable from ABSENT
	set(t, pool, ScopeEvent, "d032-lockdown", nil)
	entries, state, err = Get(ctx, pool, ScopeEvent, "d032-lockdown")
	if err != nil {
		t.Fatal(err)
	}
	if state != StateEmpty {
		t.Errorf("want EMPTY (deliberate lockdown ≠ never assigned), got %v", state)
	}
	if Evaluate(entries, state, []string{"ROLE_ANY"}, "read") {
		t.Error("EMPTY must deny")
	}

	// POPULATED evaluates
	set(t, pool, ScopeEvent, "d032-populated", []Entry{{Role: "R", Action: "read", Allow: true}})
	entries, state, _ = Get(ctx, pool, ScopeEvent, "d032-populated")
	if state != StatePopulated || !Evaluate(entries, state, []string{"R"}, "read") {
		t.Errorf("POPULATED must evaluate, got %v %v", state, entries)
	}
}

// Read-back returns exactly what was stored — a deny-only policy reads back
// as the deny, never as [], so operators can always inventory their policy.
func TestSymmetricReadBack(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	set(t, pool, ScopeEvent, "deny-only-readback", []Entry{{Role: "ROLE_X", Action: "read", Allow: false}})
	got, state, err := Get(ctx, pool, ScopeEvent, "deny-only-readback")
	if err != nil {
		t.Fatal(err)
	}
	if state != StatePopulated || len(got) != 1 || got[0].Allow {
		t.Errorf("stored deny must read back verbatim, got %v %v", state, got)
	}
}

// Full-replace semantics: a second SetTx replaces, never merges — a
// read-modify-write that merges instead would silently retain revoked rules.
func TestSetReplacesWholesale(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	set(t, pool, ScopeSeries, "replace-1", []Entry{
		{Role: "A", Action: "read", Allow: true},
		{Role: "B", Action: "write", Allow: true},
	})
	set(t, pool, ScopeSeries, "replace-1", []Entry{{Role: "C", Action: "read", Allow: true}})
	got, _, err := Get(ctx, pool, ScopeSeries, "replace-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Role != "C" {
		t.Errorf("replace must be wholesale, got %v", got)
	}
}
