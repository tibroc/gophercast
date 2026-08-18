// Package serveset is the serve-read set — the single authoritative list of
// database tables plane 1 (delivering video bytes: /elements, /publications,
// and the future url-map 301 surface) is allowed to read. Everything that
// enforces the T2 zero-downtime invariant derives from this list:
//
//   - the schemastep classifier refuses migrations that take a rewrite-class
//     ACCESS EXCLUSIVE lock on a table in this set (and requires the guarded
//     step type for metadata-class AEL on them),
//   - EnsureRole grants the ocng_serve database role SELECT on exactly this
//     set, so a serve query outside it fails at the database in every
//     environment (guard-as-structure),
//   - the static scan in internal/serve asserts its SQL reads only this set.
//
// Changing this list is a reviewed act: it widens or narrows what plane-1
// continuity protects. The why of each table is in READSET.md next to this
// file (derived with the zero-downtime migration design, ratified
// 2026-08-17). The search/engage gallery (search_event) is deliberately OUT
// — plane 3, with a recorded escape hatch if a pilot calls browsing
// presentation-critical.
package serveset

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Role is the Postgres role the serve handler's dedicated pool connects as.
const Role = "ocng_serve"

// Tables is the serve-read set. Order is cosmetic; membership is the
// contract.
var Tables = []string{
	"mp_element",          // the element row: sha256 (CAS key), size, mimetype, created_at
	"publication",         // publication listing + the publish-time ACL pin (acl_read, acl_state)
	"publication_element", // publication -> element join (and its reverse, for per-element auth)
	"migration_url_map",   // "links stay the same": the post-cutover 301 surface (designed, unwired — F3)
}

// Contains reports whether table (unqualified, lowercase) is in the
// serve-read set.
func Contains(table string) bool {
	for _, t := range Tables {
		if t == table {
			return true
		}
	}
	return false
}

// EnsureRole makes the ocng_serve role exist with LOGIN and exactly SELECT
// on the serve-read-set tables that exist in the current schema (plus USAGE
// on the schema). Idempotent and read-only at steady state: every mutation
// is preceded by a catalog check, so a second boot issues only SELECTs —
// this keeps the F2 fix intact (no DDL, no GRANT, no lock of any class on a
// serve table when nothing changed). Racing replicas are safe: the one
// CREATE ROLE loser tolerates duplicate_object.
func EnsureRole(ctx context.Context, pool *pgxpool.Pool, password string) error {
	var exists bool
	if err := pool.QueryRow(ctx,
		`select exists(select 1 from pg_roles where rolname = $1)`, Role).Scan(&exists); err != nil {
		return fmt.Errorf("serveset: role lookup: %w", err)
	}
	if !exists {
		// role names and passwords are not parameterizable; Role is a
		// constant and the password is quoted via the SQL literal rules.
		if _, err := pool.Exec(ctx,
			fmt.Sprintf(`create role %s login password '%s'`, Role, sqlEscape(password))); err != nil {
			if !isDuplicateObject(err) {
				return fmt.Errorf("serveset: create role: %w", err)
			}
		}
	}

	var schema string
	if err := pool.QueryRow(ctx, `select current_schema()`).Scan(&schema); err != nil {
		return err
	}
	var hasUsage bool
	if err := pool.QueryRow(ctx,
		`select has_schema_privilege($1, current_schema(), 'usage')`, Role).Scan(&hasUsage); err != nil {
		return err
	}
	if !hasUsage {
		if _, err := pool.Exec(ctx,
			fmt.Sprintf(`grant usage on schema %q to %s`, schema, Role)); err != nil {
			return fmt.Errorf("serveset: grant usage: %w", err)
		}
	}

	for _, t := range Tables {
		var tableExists bool
		if err := pool.QueryRow(ctx,
			`select to_regclass(quote_ident(current_schema()) || '.' || quote_ident($1)) is not null`, t).Scan(&tableExists); err != nil {
			return err
		}
		if !tableExists {
			continue // migration_url_map exists only where ocng-migrate ran (F3)
		}
		var granted bool
		if err := pool.QueryRow(ctx,
			`select has_table_privilege($1, quote_ident(current_schema()) || '.' || quote_ident($2), 'select')`,
			Role, t).Scan(&granted); err != nil {
			return err
		}
		if !granted {
			if _, err := pool.Exec(ctx,
				fmt.Sprintf(`grant select on %q.%q to %s`, schema, t, Role)); err != nil {
				return fmt.Errorf("serveset: grant select on %s: %w", t, err)
			}
		}
	}
	return nil
}

func sqlEscape(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '\'' {
			out = append(out, '\'')
		}
		out = append(out, r)
	}
	return string(out)
}

func isDuplicateObject(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42710"
}
