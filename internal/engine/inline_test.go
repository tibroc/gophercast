// The three deadlock tests — written RED before the inline executor exists
// (the failure detector before the thing that can fail; the
// concurrent-Migrate lesson relocated). Timeouts are the detector: a hang
// in any of these is the bug, and go test's deadline turns it into a
// failure. Test inline ops use REAL inline-class operation ids from the
// ADR-011 table ("hello-world", "defaults", "tag") so routing is exercised
// with no test-only class overrides.
package engine

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// smallPool returns a pool over the SAME test schema as base, capped at
// max_conns — the starvation harness.
func smallPool(t *testing.T, base *pgxpool.Pool, maxConns int32) *pgxpool.Pool {
	t.Helper()
	cfg := base.Config().Copy()
	cfg.MaxConns = maxConns
	p, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func mkInlineWorkflow(t *testing.T, e *Engine, ops ...string) int64 {
	t.Helper()
	var defs []OpDef
	for _, op := range ops {
		defs = append(defs, OpDef{Operation: op})
	}
	id, err := e.CreateWorkflow(context.Background(), "00000000-0000-0000-0000-000000000004", Definition{Operations: defs})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// driveAll steps until every workflow reaches a terminal state or the
// deadline passes — the deadline IS the deadlock detector.
func driveAll(t *testing.T, e *Engine, wfs []int64, timeout time.Duration) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(timeout)
	for {
		if err := e.Step(ctx); err != nil {
			t.Fatalf("step: %v", err)
		}
		done := 0
		for _, id := range wfs {
			state, err := e.WorkflowState(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			switch state {
			case "SUCCEEDED":
				done++
			case "FAILED":
				t.Fatalf("workflow %d FAILED", id)
			}
		}
		if done == len(wfs) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("DEADLOCK DETECTOR: %d/%d workflows terminal after %s", done, len(wfs), timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Deadlock test 1 — pool starvation. Inline ops must never hold a pool
// connection across their own work: with the pool capped at 2 connections
// and 5 concurrent inline workflows (2 ops each), an executor that pins a
// connection per op wedges — the Step loop and the completions starve each
// other.
func TestInlinePoolStarvation(t *testing.T) {
	ctx := context.Background()
	base := testPool(t)
	pool := smallPool(t, base, 2)

	var executed atomic.Int64
	runner := NewInlineRunner(pool, "core-test", 5*time.Second, map[string]InlineFunc{
		"hello-world": func(ctx context.Context, pool *pgxpool.Pool, task Task) (any, func(context.Context, pgx.Tx) error, error) {
			executed.Add(1)
			// touch the database mid-op, as real inline ops do
			var one int
			if err := pool.QueryRow(ctx, `select 1`).Scan(&one); err != nil {
				return nil, nil, err
			}
			return "hello", nil, nil
		},
		"defaults": func(ctx context.Context, pool *pgxpool.Pool, task Task) (any, func(context.Context, pgx.Tx) error, error) {
			executed.Add(1)
			return "ok", nil, nil
		},
	})
	e := New(pool, &nullProv{}, Options{Lease: 5 * time.Second, Inline: runner})

	var wfs []int64
	for i := 0; i < 5; i++ {
		wfs = append(wfs, mkInlineWorkflow(t, e, "hello-world", "defaults"))
	}
	driveAll(t, e, wfs, 30*time.Second)
	runner.Drain()
	if got := executed.Load(); got != 10 {
		t.Fatalf("inline ops executed %d times, want exactly 10", got)
	}
	_ = ctx
}

// Deadlock test 2 — a slow inline op under a fast Step loop, exactly-once.
// The op outlives several Step intervals and its own lease term; renewal
// must keep the reaper off it, and I2 must keep any over-provisioned twin
// from executing the body a second time.
func TestInlineSlowOpExactlyOnce(t *testing.T) {
	base := testPool(t)
	pool := smallPool(t, base, 4)

	var bodyRuns atomic.Int64
	runner := NewInlineRunner(pool, "core-test", 500*time.Millisecond, map[string]InlineFunc{
		"tag": func(ctx context.Context, pool *pgxpool.Pool, task Task) (any, func(context.Context, pgx.Tx) error, error) {
			bodyRuns.Add(1)
			select {
			case <-time.After(3 * time.Second): // 6 lease terms
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
			return "tagged", nil, nil
		},
	})
	e := New(pool, &nullProv{}, Options{Lease: 500 * time.Millisecond, Inline: runner})
	wf := mkInlineWorkflow(t, e, "tag")
	driveAll(t, e, []int64{wf}, 30*time.Second)
	runner.Drain()
	if got := bodyRuns.Load(); got != 1 {
		t.Fatalf("slow inline op body ran %d times, want exactly 1 (lease renewal must outpace the reaper)", got)
	}
}

// Deadlock test 3 — MigrateLocked concurrent with inline execution (the
// concurrent-Migrate lesson in its new place). A second core replica
// re-applying the schema (advisory lock + trigger DDL taking ACCESS
// EXCLUSIVE on task) must coexist with inline ops completing transactions
// on the same table. Inline completion transactions must stay short —
// mutation + terminal write only — or the DDL queue wedges everyone.
func TestInlineConcurrentMigrate(t *testing.T) {
	base := testPool(t)
	pool := smallPool(t, base, 6)

	runner := NewInlineRunner(pool, "core-test", 5*time.Second, map[string]InlineFunc{
		"hello-world": func(ctx context.Context, pool *pgxpool.Pool, task Task) (any, func(context.Context, pgx.Tx) error, error) {
			time.Sleep(20 * time.Millisecond) // work happens OUTSIDE any tx
			return "hello", nil, nil
		},
	})
	e := New(pool, &nullProv{}, Options{Lease: 5 * time.Second, Inline: runner})

	var wfs []int64
	for i := 0; i < 8; i++ {
		wfs = append(wfs, mkInlineWorkflow(t, e, "hello-world", "hello-world"))
	}

	var wg sync.WaitGroup
	migrateErr := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			if err := Migrate(context.Background(), pool); err != nil {
				select {
				case migrateErr <- err:
				default:
				}
				return
			}
		}
	}()

	driveAll(t, e, wfs, 45*time.Second)
	wg.Wait()
	runner.Drain()
	select {
	case err := <-migrateErr:
		t.Fatalf("concurrent migrate failed: %v", err)
	default:
	}
}
