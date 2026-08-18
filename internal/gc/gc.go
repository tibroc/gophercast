// Package gc is the ADR-008 CAS mark-sweep collector — the reclaim half of
// content addressing that every reference-dropping write (T4 delete, future
// retention policies) hands its garbage to. Designed in increment 6
// (mark-sweep with grace: never inline, never refcounted) and BUILT in
// T4, because the approved archive-delete semantics are "drop the reference,
// let the collector reclaim" — a delete that removed bytes itself would
// bypass the grace and could destroy content a migration or an in-flight
// workflow still references.
//
// The model:
//
//   - MARK: an object is referenced iff its digest appears in mp_element
//     (live element rows), mp_snapshot (archive-version manifests, verbatim
//     source manifests included) or migration_url_map (the increment-6
//     repoint record — the migration's own claim on the bytes). The mark set
//     is re-derived from these tables on EVERY sweep; nothing is cached.
//   - GRACE FROM DEREFERENCE, not from object age: the first sweep that
//     finds an object unreferenced records it in cas_gc_candidate with a
//     timestamp. Reclaim happens only on a LATER sweep, when the candidate
//     has been continuously unreferenced for the full grace window. A sweep
//     that finds a candidate referenced again CLEARS its candidacy
//     (resurrection) — re-referencing inside the grace is always safe. This
//     is what makes "transiently-unreferenced content survives" provable:
//     grace is measured from the observed dereference, which no object-age
//     heuristic (S3 LastModified) can express.
//   - The grace window must be sized >= the restore horizon AND the longest
//     put-then-reference gap in any writer (ingest staging, worker output,
//     migration batches — the ADR-006 finding: grace >= restore horizon).
//
// ENABLEMENT GATE (recorded 2026-08-18, with the T4 commit): sweeping stays
// OFF by default (ocng-core enables it only when OCNG_GC_GRACE and
// OCNG_GC_INTERVAL are both set), and the PRECONDITION for ever enabling it
// in a deployment is a mid-migration-transient fixture — a test that deletes
// an object's references in the window between a migration's CAS put and its
// migration_url_map commit and proves the grace protects it. That case is
// argued today only by the grace-sizing rule below, not by a fixture; the
// fixture is written when reclamation is actually wanted, gating the
// capability it enables.
//
// Known residual window, stated rather than hidden: PutFile's dedup path
// returns an existing object without touching the candidate ledger, so a
// writer that re-references an object in the final moments of its grace
// races the sweep's delete. The per-object recheck below re-reads the
// reference tables immediately before each delete, shrinking the window to
// one query round-trip; closing it entirely needs a write-side ledger touch
// and is recorded in the package as the collector's known limit. Operate
// with a grace that dwarfs any write transaction (hours, not seconds).
package gc

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/cas"
	"ocng/internal/schemastep"
)

//go:embed schema.sql
var schema string

// Migrate: the candidate ledger, through the T2 mechanism like every other
// ocng table (new table = reader-safe; off the serve-read set).
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := schemastep.Run(ctx, pool, "gc", MigrationSteps())
	return err
}

func MigrationSteps() []schemastep.Step {
	return []schemastep.Step{schemastep.TxDDL(0, "baseline", schema)}
}

// Report is one sweep's outcome, for logs and tests.
type Report struct {
	Objects    int // objects enumerated
	Referenced int // in the mark set (untouchable)
	Candidates int // unreferenced, inside their grace window
	Swept      int // reclaimed (unreferenced for >= grace)
}

// markExistsSQL answers "is this digest referenced right now?" for one
// object — the pre-delete recheck. The migration_url_map clause is appended
// only where that table exists (a plain to_regclass guard inside one
// statement does not help: the planner rejects the whole statement when the
// relation is absent).
func markExistsSQL(hasURLMap bool) string {
	q := `select exists (select 1 from mp_element where sha256 = $1)
	          or exists (select 1 from mp_snapshot
	                     where manifest_sha256 = $1 or source_manifest_sha256 = $1)`
	if hasURLMap {
		q += ` or exists (select 1 from migration_url_map where sha256 = $1)`
	}
	return q
}

// markSet derives the full reference set. Fails closed if the reference
// tables are absent: sweeping a database without them would classify every
// object as garbage.
func markSet(ctx context.Context, pool *pgxpool.Pool) (map[string]bool, bool, error) {
	for _, tbl := range []string{"mp_element", "mp_snapshot"} {
		var ok bool
		if err := pool.QueryRow(ctx, `select to_regclass($1) is not null`, tbl).Scan(&ok); err != nil {
			return nil, false, err
		}
		if !ok {
			return nil, false, fmt.Errorf("gc: reference table %s absent — refusing to sweep (everything would look unreferenced)", tbl)
		}
	}
	q := `select sha256 from mp_element
	      union select manifest_sha256 from mp_snapshot
	      union select source_manifest_sha256 from mp_snapshot where source_manifest_sha256 is not null`
	var hasURLMap bool
	if err := pool.QueryRow(ctx, `select to_regclass('migration_url_map') is not null`).Scan(&hasURLMap); err != nil {
		return nil, false, err
	}
	if hasURLMap {
		q += ` union select sha256 from migration_url_map`
	}
	rows, err := pool.Query(ctx, q)
	if err != nil {
		return nil, false, fmt.Errorf("gc: mark: %w", err)
	}
	defer rows.Close()
	mark := map[string]bool{}
	for rows.Next() {
		var sha string
		if err := rows.Scan(&sha); err != nil {
			return nil, false, err
		}
		mark[sha] = true
	}
	return mark, hasURLMap, rows.Err()
}

// Sweep runs one mark-sweep pass: referenced objects are untouched (and any
// stale candidacy cleared); unreferenced objects become candidates; a
// candidate continuously unreferenced for >= grace is deleted, after a
// point-in-time recheck of the reference tables. Idempotent; safe to run
// concurrently with writers as long as grace exceeds their
// put-then-reference gap (package comment).
func Sweep(ctx context.Context, pool *pgxpool.Pool, store *cas.Store, grace time.Duration) (Report, error) {
	var rep Report
	mark, hasURLMap, err := markSet(ctx, pool)
	if err != nil {
		return rep, err
	}
	recheckSQL := markExistsSQL(hasURLMap)
	err = store.List(ctx, func(sha string) error {
		rep.Objects++
		if mark[sha] {
			rep.Referenced++
			// resurrection: a referenced object carries no candidacy
			_, err := pool.Exec(ctx, `delete from cas_gc_candidate where sha256 = $1`, sha)
			return err
		}
		if _, err := pool.Exec(ctx, `
			insert into cas_gc_candidate (sha256) values ($1)
			on conflict (sha256) do nothing`, sha); err != nil {
			return err
		}
		var expired bool
		if err := pool.QueryRow(ctx, `
			select now() - first_unreferenced_at >= $2
			from cas_gc_candidate where sha256 = $1`, sha, grace).Scan(&expired); err != nil {
			return err
		}
		if !expired {
			rep.Candidates++
			return nil
		}
		// pre-delete recheck: the mark set was computed at sweep start; a
		// reference committed since then must veto the delete
		var referenced bool
		if err := pool.QueryRow(ctx, recheckSQL, sha).Scan(&referenced); err != nil {
			return err
		}
		if referenced {
			rep.Referenced++
			_, err := pool.Exec(ctx, `delete from cas_gc_candidate where sha256 = $1`, sha)
			return err
		}
		if err := store.Delete(ctx, sha); err != nil {
			return err
		}
		if _, err := pool.Exec(ctx, `delete from cas_gc_candidate where sha256 = $1`, sha); err != nil {
			return err
		}
		rep.Swept++
		return nil
	})
	return rep, err
}
