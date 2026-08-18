// The run ledger and the D-010 fidelity report: everything migration drops,
// classifies, preserves-verbatim-only, or HOLDs is a queryable row — loss
// reported, never silent.
package migrate

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/schemastep"
)

//go:embed schema.sql
var schema string

// Migrate applies the migration-owned schema (ledger, report, url map) as
// ledger step 0 (T2 Option A) — applied once, skipped lock-free after.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := schemastep.Run(ctx, pool, "migrate", MigrationSteps())
	return err
}

func MigrationSteps() []schemastep.Step {
	return []schemastep.Step{schemastep.TxDDL(0, "baseline", schema)}
}

type reporter struct {
	pool  *pgxpool.Pool
	runID int64
	holds int
}

func newReporter(ctx context.Context, pool *pgxpool.Pool, org, source string) (*reporter, error) {
	r := &reporter{pool: pool}
	if err := pool.QueryRow(ctx, `
		insert into migration_run (org, source) values ($1,$2) returning id`,
		org, source).Scan(&r.runID); err != nil {
		return nil, fmt.Errorf("migration_run: %w", err)
	}
	return r, nil
}

func (r *reporter) line(ctx context.Context, class, recordID, detail string) error {
	_, err := r.pool.Exec(ctx, `
		insert into migration_report (run_id, class, record_id, detail)
		values ($1,$2,$3,nullif($4,''))`, r.runID, class, recordID, detail)
	return err
}

// hold records a per-record HOLD: the record's migration is incomplete and a
// human decides. The run continues — a HOLD is a report, not a crash — but
// the ledger carries the count and the caller's exit status reflects it.
func (r *reporter) hold(ctx context.Context, recordID, detail string) error {
	r.holds++
	return r.line(ctx, "hold", recordID, detail)
}

func (r *reporter) finish(ctx context.Context, res *Result, outcome string) error {
	_, err := r.pool.Exec(ctx, `
		update migration_run set finished_at=now(), n_events=$2, n_series=$3,
		       n_versions=$4, n_objects=$5, holds=$6, outcome=$7
		where id=$1`,
		r.runID, res.Events, res.Series, res.Versions, res.Objects, r.holds, outcome)
	return err
}
