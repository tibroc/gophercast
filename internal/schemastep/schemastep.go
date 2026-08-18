// Package schemastep is the T2 extension of the increment-1 migration
// mechanism: a ledger-skipped, multi-step, non-transaction-capable runner
// alongside engine.MigrateLocked (which stays untouched — this package only
// changes how the per-package Migrate one-liners are wired, ratified
// Option A, 2026-08-17).
//
// What it adds over the increment-1 replay:
//
//   - A schema_migration ledger: applied steps are SKIPPED on later boots
//     without acquiring any DDL lock — this retires F2 (the every-boot
//     ACCESS EXCLUSIVE replay on the serve-read set). Proven by
//     TestSecondBootTakesNoLockOnServeSet.
//   - The SAME advisory key as engine.migrateLocked (0x0c9e_0001), held as
//     a SESSION lock for the whole run — transaction-scoped locking cannot
//     span CREATE INDEX CONCURRENTLY, which refuses to run in a
//     transaction. Same key → serialises against every existing
//     migrateLocked user by construction: the I6 single-winner guarantee is
//     preserved, re-proven by TestParallelBootSingleWinner.
//   - Non-transactional step kinds: concurrent-index (with mandatory
//     INVALID-index cleanup on retry), batched-dml (re-check on resume),
//     guarded-metadata-ddl (lock_timeout + bounded retry, the only form in
//     which metadata-AEL is permitted on serve-read-set tables).
//   - The blocking-lock check (classify.go): Run refuses a plan that
//     fails Check. Crash mid-run = resume from the ledger; every step is
//     idempotent or cleanup-prefixed.
//
// The session lock is acquired by POLLING pg_try_advisory_lock rather than
// blocking in pg_advisory_lock: a session blocked inside pg_advisory_lock
// holds an open snapshot, and CREATE INDEX CONCURRENTLY in the lock-holding
// session waits out older snapshots — a blocking waiter would deadlock with
// the index build it is waiting to be allowed to run after.
package schemastep

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AdvisoryKey is the ocng migration lock. It MUST stay equal to the key in
// engine.migrateLocked (engine.go) — one key is what makes the two
// mechanisms mutually exclusive (I6).
const AdvisoryKey = 0x0c9e_0001

type Kind int

const (
	// KindTxDDL: transactional DDL, the increment-1 shape. DDL and its
	// ledger row commit atomically.
	KindTxDDL Kind = iota
	// KindGuardedDDL: transactional DDL under SET LOCAL lock_timeout with
	// bounded retry — the ONLY form in which a metadata-class ACCESS
	// EXCLUSIVE lock may touch a serve-read-set table (§5.3): the timeout
	// converts "queued behind a long reader, stalling every serve SELECT
	// behind us" into a bounded retry.
	KindGuardedDDL
	// KindConcurrentIndex: CREATE INDEX CONCURRENTLY, outside any
	// transaction, with INVALID-leftover cleanup before retry.
	KindConcurrentIndex
	// KindBatchedDML: a Go loop of bounded reader-safe DML batches; each
	// call must re-derive remaining work so a crashed run resumes by
	// re-running from scratch (idempotence is the step author's contract —
	// see docs/migration-discipline.md).
	KindBatchedDML
)

// BatchFunc executes ONE bounded batch and reports whether the step is
// done. It runs outside any wrapping transaction (each batch commits on
// its own).
type BatchFunc func(ctx context.Context, conn *pgxpool.Conn) (done bool, err error)

type Step struct {
	N     int    // step number within the package; the ledger key
	Name  string // human name recorded in the ledger
	Kind  Kind
	SQL   string    // TxDDL / GuardedDDL / ConcurrentIndex
	Index string    // ConcurrentIndex: the index name, for INVALID cleanup
	Batch BatchFunc // BatchedDML
}

func TxDDL(n int, name, sql string) Step {
	return Step{N: n, Name: name, Kind: KindTxDDL, SQL: sql}
}

func GuardedDDL(n int, name, sql string) Step {
	return Step{N: n, Name: name, Kind: KindGuardedDDL, SQL: sql}
}

func ConcurrentIndex(n int, name, index, sql string) Step {
	return Step{N: n, Name: name, Kind: KindConcurrentIndex, SQL: sql, Index: index}
}

func BatchedDML(n int, name string, batch BatchFunc) Step {
	return Step{N: n, Name: name, Kind: KindBatchedDML, Batch: batch}
}

const ledgerDDL = `
create table if not exists schema_migration (
    id         bigserial primary key,
    package    text not null,
    step       int  not null,
    name       text not null default '',
    sha256     text not null default '',
    applied_at timestamptz not null default now(),
    unique (package, step)
)`

// guarded-step retry envelope: worst case ~ attempts * (timeout + backoff).
const (
	guardLockTimeout = "500ms"
	guardAttempts    = 20
	guardBackoff     = 250 * time.Millisecond
)

// Run applies the not-yet-applied steps of one package's migration plan,
// in order, under the shared advisory key. It returns the number of steps
// actually executed (0 on a fully ledger-skipped boot — the F2 property).
//
// An applied DDL step whose SQL later changes is an ERROR, not a re-run:
// the ledger stores the SQL's sha256, and history must evolve by NEW steps
// (the baseline replay semantics of increment 1 — edit schema.sql, every
// boot re-applies — ends at the ledger boundary; see
// docs/migration-discipline.md).
func Run(ctx context.Context, pool *pgxpool.Pool, pkg string, steps []Step) (int, error) {
	if err := Check(steps); err != nil {
		return 0, fmt.Errorf("schemastep: %s: plan refused: %w", pkg, err)
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Release()

	// poll, never block (see package comment on the CIC snapshot deadlock)
	for {
		var got bool
		if err := conn.QueryRow(ctx, `select pg_try_advisory_lock($1)`, AdvisoryKey).Scan(&got); err != nil {
			return 0, err
		}
		if got {
			break
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	defer func() {
		// unlock on a context that survives cancellation; if the conn died,
		// the session lock died with it — either way it is released.
		_, _ = conn.Exec(context.WithoutCancel(ctx), `select pg_advisory_unlock($1)`, AdvisoryKey)
	}()

	if _, err := conn.Exec(ctx, ledgerDDL); err != nil {
		return 0, fmt.Errorf("schemastep: %s: ledger: %w", pkg, err)
	}

	applied := map[int]string{}
	rows, err := conn.Query(ctx, `select step, sha256 from schema_migration where package = $1`, pkg)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var n int
		var sum string
		if err := rows.Scan(&n, &sum); err != nil {
			rows.Close()
			return 0, err
		}
		applied[n] = sum
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	executed := 0
	for _, s := range steps {
		sum := stepSHA(s)
		if prev, ok := applied[s.N]; ok {
			if s.Kind != KindBatchedDML && prev != sum {
				return executed, fmt.Errorf(
					"schemastep: %s step %d %q: recorded sha256 %s != current %s — an applied step's SQL was edited; applied history is immutable, add a NEW step instead (docs/migration-discipline.md)",
					pkg, s.N, s.Name, short(prev), short(sum))
			}
			continue // the F2 fix: applied → skipped, zero DDL, zero locks
		}
		if err := runStep(ctx, conn, pkg, s, sum); err != nil {
			return executed, fmt.Errorf("schemastep: %s step %d %q: %w", pkg, s.N, s.Name, err)
		}
		executed++
	}
	return executed, nil
}

func runStep(ctx context.Context, conn *pgxpool.Conn, pkg string, s Step, sum string) error {
	switch s.Kind {
	case KindTxDDL:
		return runTxDDL(ctx, conn, pkg, s, sum, false)
	case KindGuardedDDL:
		return runTxDDL(ctx, conn, pkg, s, sum, true)
	case KindConcurrentIndex:
		return runConcurrentIndex(ctx, conn, pkg, s, sum)
	case KindBatchedDML:
		for {
			done, err := s.Batch(ctx, conn)
			if err != nil {
				return err
			}
			if done {
				return recordStep(ctx, conn, pkg, s, sum)
			}
		}
	}
	return fmt.Errorf("unknown step kind %d", s.Kind)
}

// runTxDDL commits the DDL and its ledger row atomically. Guarded steps
// additionally run under SET LOCAL lock_timeout with bounded retry, so an
// AEL that queues behind a long reader aborts and retries instead of
// stalling every serve SELECT behind it.
func runTxDDL(ctx context.Context, conn *pgxpool.Conn, pkg string, s Step, sum string, guarded bool) error {
	attempts := 1
	if guarded {
		attempts = guardAttempts
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(guardBackoff):
			}
		}
		err := func() error {
			tx, err := conn.Begin(ctx)
			if err != nil {
				return err
			}
			defer tx.Rollback(ctx)
			if guarded {
				if _, err := tx.Exec(ctx, `set local lock_timeout = '`+guardLockTimeout+`'`); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, s.SQL); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx,
				`insert into schema_migration (package, step, name, sha256) values ($1, $2, $3, $4)`,
				pkg, s.N, s.Name, sum); err != nil {
				return err
			}
			return tx.Commit(ctx)
		}()
		if err == nil {
			return nil
		}
		lastErr = err
		if !guarded || !isLockTimeout(err) {
			return err
		}
	}
	return fmt.Errorf("guarded DDL still lock-blocked after %d attempts of %s: %w", attempts, guardLockTimeout, lastErr)
}

// runConcurrentIndex executes CREATE INDEX CONCURRENTLY outside any
// transaction. A crashed prior attempt leaves an INVALID index under the
// step's name — mandatory cleanup drops it before retrying; a VALID index
// (crash after build, before the ledger write) is kept and only the ledger
// row is recorded.
func runConcurrentIndex(ctx context.Context, conn *pgxpool.Conn, pkg string, s Step, sum string) error {
	if s.Index == "" {
		return errors.New("concurrent-index step needs the index name for INVALID cleanup")
	}
	var state string // 'absent' | 'valid' | 'invalid'
	err := conn.QueryRow(ctx, `
		select case when i.indisvalid then 'valid' else 'invalid' end
		from pg_index i
		join pg_class c on c.oid = i.indexrelid
		join pg_namespace n on n.oid = c.relnamespace
		where c.relname = $1 and n.nspname = current_schema()`, s.Index).Scan(&state)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		state = "absent"
	}
	switch state {
	case "invalid":
		if _, err := conn.Exec(ctx, fmt.Sprintf(`drop index %q`, s.Index)); err != nil {
			return fmt.Errorf("dropping INVALID leftover index %s: %w", s.Index, err)
		}
		fallthrough
	case "absent":
		if _, err := conn.Exec(ctx, s.SQL); err != nil {
			return err
		}
	case "valid":
		// built, ledger write lost: record only
	}
	return recordStep(ctx, conn, pkg, s, sum)
}

func recordStep(ctx context.Context, conn *pgxpool.Conn, pkg string, s Step, sum string) error {
	_, err := conn.Exec(ctx,
		`insert into schema_migration (package, step, name, sha256) values ($1, $2, $3, $4)
		 on conflict (package, step) do nothing`,
		pkg, s.N, s.Name, sum)
	return err
}

func stepSHA(s Step) string {
	if s.Kind == KindBatchedDML {
		return "" // Go code has no stable byte form; the name is the identity
	}
	h := sha256.Sum256([]byte(s.SQL))
	return hex.EncodeToString(h[:])
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	if s == "" {
		return "(empty)"
	}
	return s
}

func isLockTimeout(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "55P03" // lock_not_available
}
