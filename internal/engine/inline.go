// The inline execution class (ADR-011): operations that run IN the core
// process. The load-bearing design decision, per the increment-2 review:
// inline ops travel the IDENTICAL task lifecycle as worker ops — own task
// row, StartTask / lease renewal / CompleteTask, an owner string — so
// invariants I2–I5 hold for them by construction and a core process dying
// mid-inline-op is recovered by the same lease reap that recovers a dead
// container. There is no second lifecycle.
package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// InlineFunc is one inline operation: read what you need, do kilobyte-scale
// work, and return the result plus the mutation that commits WITH the task's
// terminal state (I3). It must not hold pool connections across its own
// work — acquire per statement, transact only inside the returned mutate.
type InlineFunc func(ctx context.Context, pool *pgxpool.Pool, task Task) (result any, mutate func(context.Context, pgx.Tx) error, err error)

// InlineRunner executes inline-class tasks in-process. It implements
// Provisioner: "provisioning" an inline task is spawning a goroutine that
// runs the standard task lifecycle.
type InlineRunner struct {
	pool  *pgxpool.Pool
	owner string
	lease time.Duration
	ops   map[string]InlineFunc
	wg    sync.WaitGroup
	seq   atomic.Int64 // distinct owner per execution, so I2 separates twins
}

func NewInlineRunner(pool *pgxpool.Pool, owner string, lease time.Duration, ops map[string]InlineFunc) *InlineRunner {
	return &InlineRunner{pool: pool, owner: owner, lease: lease, ops: ops}
}

// Drain waits for all in-flight inline executions to finish. Tests use it;
// a shutting-down core uses it to drain before exit (SIGTERM posture).
func (r *InlineRunner) Drain() { r.wg.Wait() }

// Provision spawns the inline execution for one assigned task and returns
// immediately (the engine's Step loop must never block on an op). The
// execution runs on its own background context: it belongs to the task's
// lease, not to whichever Step call happened to provision it.
func (r *InlineRunner) Provision(ctx context.Context, task Task) error {
	op, registered := r.ops[task.Operation]
	owner := fmt.Sprintf("%s-t%d-e%d", r.owner, task.ID, r.seq.Add(1))
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		bg := context.Background()
		if !registered {
			// inline-class per the table, but this core has no
			// implementation: fail loudly through the standard
			// single-winner transition, never silently strand
			if err := StartTask(bg, r.pool, task.ID, owner, r.lease); err != nil {
				return // raced/reaped/terminal — not ours to report
			}
			_ = FailTask(bg, r.pool, task.ID, owner,
				fmt.Sprintf("inline operation %q not implemented in this core", task.Operation))
			return
		}
		_ = ExecuteTask(bg, r.pool, task, owner, r.lease, func(ctx context.Context) (any, func(context.Context, pgx.Tx) error, error) {
			return op(ctx, r.pool, task)
		})
	}()
	return nil
}

// ExecuteTask is the ONE task lifecycle, shared verbatim by the worker
// binary and the inline runner: win ASSIGNED→RUNNING or exit silently,
// renew the lease while the body runs, then commit result+mutation with
// the terminal write (I3) — or report failure — honouring the lost-task
// posture: a lost task produces no side effects, not even a FAILED.
func ExecuteTask(ctx context.Context, pool *pgxpool.Pool, task Task, owner string, lease time.Duration, body func(ctx context.Context) (any, func(context.Context, pgx.Tx) error, error)) error {
	if err := StartTask(ctx, pool, task.ID, owner, lease); err != nil {
		if errors.Is(err, ErrTaskLost) {
			return nil // someone else won; exit silently, no side effects
		}
		return err
	}

	// lease renewal for liveness; losing the lease cancels the work
	workCtx, cancelWork := context.WithCancel(ctx)
	defer cancelWork()
	renewErr := make(chan error, 1)
	go func() {
		t := time.NewTicker(lease / 3)
		defer t.Stop()
		for {
			select {
			case <-workCtx.Done():
				return
			case <-t.C:
				if err := RenewLease(workCtx, pool, task.ID, owner, lease); err != nil {
					renewErr <- err
					cancelWork()
					return
				}
			}
		}
	}()

	result, mutate, err := body(workCtx)
	select {
	case <-renewErr:
		// reaped mid-work: the task belongs to someone else now; no side
		// effects, not even a FAILED report (the lost-task posture)
		return nil
	default:
	}
	if err != nil {
		if ferr := FailTask(ctx, pool, task.ID, owner, err.Error()); errors.Is(ferr, ErrTaskLost) {
			return nil
		}
		return err
	}
	if cerr := CompleteTask(ctx, pool, task.ID, owner, result, mutate); cerr != nil {
		if errors.Is(cerr, ErrTaskLost) {
			return nil // mutation rolled back with the lost completion
		}
		return cerr
	}
	return nil
}
