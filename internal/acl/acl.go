// Package acl is the one ACL write-and-evaluate path: every ACL write in
// ocng funnels through this package, and every authorization decision reads
// what it stored. The semantics:
//
//   - D-028: one evaluation — deny vetoes. A deny NEVER widens access.
//   - D-032: three explicit states — ABSENT / EMPTY / POPULATED. ABSENT and
//     EMPTY both deny, but are distinguishable and reportable.
//   - Get returns exactly what Set stored, denies included.
//   - allow and deny for the same (role, action) coexist by construction:
//     allow is part of the primary key (see schema.sql).
package acl

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/schemastep"
)

//go:embed schema.sql
var schema string

// Migrate: ledger step 0 (T2 Option A) — applied once, skipped lock-free after.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := schemastep.Run(ctx, pool, "acl", MigrationSteps())
	return err
}

func MigrationSteps() []schemastep.Step {
	return []schemastep.Step{schemastep.TxDDL(0, "baseline", schema)}
}

type Scope string

const (
	ScopeEvent  Scope = "event"
	ScopeSeries Scope = "series"
)

type State string

const (
	StateAbsent    State = "ABSENT"    // no policy ever set → deny (all but platform admin)
	StateEmpty     State = "EMPTY"     // deliberate lockdown → deny
	StatePopulated State = "POPULATED" // evaluate, deny vetoes
)

type Entry struct {
	Role   string
	Action string
	Allow  bool
}

// SetTx replaces the full policy for (scope, id) — the External API's PUT is
// full-replace, and modelling it as anything else silently drops rules.
// Setting an empty entry list stores an EMPTY policy (deliberate lockdown),
// which is distinct from never calling SetTx (ABSENT).
//
// Deliberately transaction-scoped with no pool variant: an ACL write commits
// together with its projection refresh (so there is no window in which
// authorization and its index disagree), and that orchestration lives in
// the search package (search.SetACL). Nothing else should write these tables.
func SetTx(ctx context.Context, tx pgx.Tx, scope Scope, id string, entries []Entry) error {
	if _, err := tx.Exec(ctx, `
		insert into acl_policy (scope, scope_id) values ($1,$2)
		on conflict (scope, scope_id) do update set updated_at = now()`,
		scope, id); err != nil {
		return fmt.Errorf("acl set: %w", err)
	}
	if _, err := tx.Exec(ctx, `delete from acl_entry where scope=$1 and scope_id=$2`, scope, id); err != nil {
		return fmt.Errorf("acl set: %w", err)
	}
	for _, e := range entries {
		if e.Role == "" || e.Action == "" {
			return fmt.Errorf("acl set: empty role or action in %+v", e)
		}
		if _, err := tx.Exec(ctx, `
			insert into acl_entry (scope, scope_id, role, action, allow)
			values ($1,$2,$3,$4,$5) on conflict do nothing`,
			scope, id, e.Role, e.Action, e.Allow); err != nil {
			return fmt.Errorf("acl set: %w", err)
		}
	}
	return nil
}

// Get returns exactly what is stored — denies included — plus the explicit
// D-032 state. Read-back never masks any stored rule.
func Get(ctx context.Context, pool *pgxpool.Pool, scope Scope, id string) ([]Entry, State, error) {
	var exists bool
	if err := pool.QueryRow(ctx, `
		select exists (select 1 from acl_policy where scope=$1 and scope_id=$2)`,
		scope, id).Scan(&exists); err != nil {
		return nil, "", err
	}
	if !exists {
		return nil, StateAbsent, nil
	}
	rows, err := pool.Query(ctx, `
		select role, action, allow from acl_entry
		where scope=$1 and scope_id=$2 order by role, action, allow`, scope, id)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.Role, &e.Action, &e.Allow); err != nil {
			return nil, "", err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(out) == 0 {
		return nil, StateEmpty, nil
	}
	return out, StatePopulated, nil
}

// Evaluate is THE authorization decision (D-028): deny vetoes, reading the
// stored allow/deny boolean — never the role name alone. A deny always
// denies. ABSENT and EMPTY deny.
// Platform-admin bypass is the CALLER's concern (it is a property of the
// principal, not of the policy).
func Evaluate(entries []Entry, state State, roles []string, action string) bool {
	if state != StatePopulated {
		return false
	}
	held := make(map[string]bool, len(roles))
	for _, r := range roles {
		held[r] = true
	}
	allowed := false
	for _, e := range entries {
		if e.Action != action || !held[e.Role] {
			continue
		}
		if !e.Allow {
			return false // deny vetoes, regardless of any allow
		}
		allowed = true
	}
	return allowed
}
