// Engine invariant tests, against real Postgres (the engine IS SQL; mocking
// the database would test nothing). Each test is one ADR-011 claim.
package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testPool gives each test its own Postgres schema. The engine's Step()
// operates on every workflow it can see, so tests sharing one schema with
// a concurrently-running package (e2e under `go test ./...`) would assign
// each other's tasks — observed as a flaky TestAssignCommitsBeforeProvision.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("OCNG_E2E_PG")
	if url == "" {
		url = "postgres://ocng:ocng@127.0.0.1:15432/ocng"
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	schemaName := fmt.Sprintf("ocng_t_%d", time.Now().UnixNano())
	cfg.ConnConfig.RuntimeParams["search_path"] = schemaName
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("postgres: %v", err)
	}
	if _, err := pool.Exec(context.Background(), "create schema "+schemaName); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), "drop schema "+schemaName+" cascade")
		pool.Close()
	})
	if err := Migrate(context.Background(), pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

type nullProv struct {
	mu    sync.Mutex
	tasks []Task
}

func (p *nullProv) Provision(ctx context.Context, task Task) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tasks = append(p.tasks, task)
	return nil
}

func mkWorkflow(t *testing.T, e *Engine) int64 {
	t.Helper()
	id, err := e.CreateWorkflow(context.Background(),
		"00000000-0000-0000-0000-000000000001",
		Definition{Operations: []OpDef{{Operation: "speechtotext", Config: map[string]string{"language": "en"}}}})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// Assignment is committed before provisioning, and the provisioner receives
// the already-persisted task identity.
func TestAssignCommitsBeforeProvision(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	prov := &nullProv{}
	e := New(pool, prov, Options{Lease: time.Minute})
	mkWorkflow(t, e)

	if err := e.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if len(prov.tasks) != 1 {
		t.Fatalf("provisioned %d tasks, want 1", len(prov.tasks))
	}
	got, err := GetTask(ctx, pool, prov.tasks[0].ID)
	if err != nil {
		t.Fatalf("task not readable by id at provision time: %v", err)
	}
	if got.State != "ASSIGNED" || got.Operation != "speechtotext" {
		t.Fatalf("task = %+v, want ASSIGNED speechtotext", got)
	}
	// second Step must not double-assign
	if err := e.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if len(prov.tasks) != 1 {
		t.Fatalf("second Step re-provisioned: %d tasks", len(prov.tasks))
	}
}

// ASSIGNED→RUNNING is single-row: of N racing starters exactly one wins,
// losers get ErrTaskLost (over-provision is safe by construction).
func TestOverProvisionExactlyOneWins(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	prov := &nullProv{}
	e := New(pool, prov, Options{Lease: time.Minute})
	mkWorkflow(t, e)
	if err := e.Step(ctx); err != nil {
		t.Fatal(err)
	}
	taskID := prov.tasks[0].ID

	const racers = 8
	var wins, losses int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			err := StartTask(ctx, pool, taskID, string(rune('a'+n)), time.Minute)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case errors.Is(err, ErrTaskLost):
				losses++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 || losses != racers-1 {
		t.Fatalf("wins=%d losses=%d, want 1/%d", wins, losses, racers-1)
	}
}

// Completion is transactional: when the terminal write loses (task reaped /
// wrong owner), the mutation in the same transaction rolls back — no orphan
// rows (the CAS-dedups-bytes-not-rows answer).
func TestCompletionTransactional(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	prov := &nullProv{}
	e := New(pool, prov, Options{Lease: time.Minute})
	mkWorkflow(t, e)
	if err := e.Step(ctx); err != nil {
		t.Fatal(err)
	}
	taskID := prov.tasks[0].ID
	if err := StartTask(ctx, pool, taskID, "owner-a", time.Minute); err != nil {
		t.Fatal(err)
	}

	pool.Exec(ctx, `create table if not exists tx_probe (task_id bigint)`)

	// wrong owner: mutation must roll back with the lost completion
	err := CompleteTask(ctx, pool, taskID, "owner-b", "r", func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `insert into tx_probe values ($1)`, taskID)
		return err
	})
	if !errors.Is(err, ErrTaskLost) {
		t.Fatalf("non-owner completion: err = %v, want ErrTaskLost", err)
	}
	var n int
	pool.QueryRow(ctx, `select count(*) from tx_probe where task_id=$1`, taskID).Scan(&n)
	if n != 0 {
		t.Fatalf("mutation survived a lost completion: %d probe rows", n)
	}

	// right owner: mutation and terminal state commit together
	err = CompleteTask(ctx, pool, taskID, "owner-a", "r", func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `insert into tx_probe values ($1)`, taskID)
		return err
	})
	if err != nil {
		t.Fatalf("owner completion failed: %v", err)
	}
	pool.QueryRow(ctx, `select count(*) from tx_probe where task_id=$1`, taskID).Scan(&n)
	if n != 1 {
		t.Fatalf("mutation missing after successful completion")
	}
}

// Terminal states are immutable — second completion, late FAILED from
// a zombie owner, and raw SQL all rejected; the database is the guard, not
// client discipline.
func TestU27TerminalImmutable(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	prov := &nullProv{}
	e := New(pool, prov, Options{Lease: time.Minute})
	mkWorkflow(t, e)
	if err := e.Step(ctx); err != nil {
		t.Fatal(err)
	}
	taskID := prov.tasks[0].ID
	if err := StartTask(ctx, pool, taskID, "owner-a", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := CompleteTask(ctx, pool, taskID, "owner-a", "v7", nil); err != nil {
		t.Fatal(err)
	}

	// the zombie's stale terminal write
	if err := CompleteTask(ctx, pool, taskID, "owner-a", "v8-stale", nil); !errors.Is(err, ErrTaskLost) {
		t.Fatalf("stale re-completion: err = %v, want ErrTaskLost", err)
	}
	if err := FailTask(ctx, pool, taskID, "owner-a", "late failure"); !errors.Is(err, ErrTaskLost) {
		t.Fatalf("late FAILED over FINISHED: err = %v, want ErrTaskLost", err)
	}
	// even raw SQL cannot flip a terminal row: the trigger fires
	if _, err := pool.Exec(ctx, `update task set state='RUNNING' where id=$1`, taskID); err == nil {
		t.Fatalf("raw update of terminal task succeeded; terminal-write guard absent")
	}
	var state, result string
	pool.QueryRow(ctx, `select state, result::text from task where id=$1`, taskID).Scan(&state, &result)
	if state != "FINISHED" || result != `"v7"` {
		t.Fatalf("terminal row mutated: state=%s result=%s", state, result)
	}
}

// Lease expiry is the recovery mechanism: an un-renewed task is reaped,
// re-assigned with attempt+1, and re-provisioned; at MaxAttempts it fails
// and the workflow fails with it.
func TestLeaseReapAndExhaustion(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	prov := &nullProv{}
	e := New(pool, prov, Options{Lease: 100 * time.Millisecond, MaxAttempts: 2})
	wfID := mkWorkflow(t, e)
	if err := e.Step(ctx); err != nil {
		t.Fatal(err)
	}
	taskID := prov.tasks[0].ID
	if err := StartTask(ctx, pool, taskID, "doomed", 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}

	time.Sleep(150 * time.Millisecond) // lease expires, no renewal
	if err := e.Step(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := GetTask(ctx, pool, taskID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "ASSIGNED" || got.Attempt != 2 {
		t.Fatalf("after reap: %+v, want ASSIGNED attempt 2", got)
	}
	if len(prov.tasks) != 2 {
		t.Fatalf("reap did not re-provision: %d provisions", len(prov.tasks))
	}
	// the reaped owner's writes are now rejected
	if err := RenewLease(ctx, pool, taskID, "doomed", time.Minute); !errors.Is(err, ErrTaskLost) {
		t.Fatalf("reaped owner renewed lease: %v", err)
	}
	if err := CompleteTask(ctx, pool, taskID, "doomed", "stale", nil); !errors.Is(err, ErrTaskLost) {
		t.Fatalf("reaped owner completed: %v", err)
	}

	time.Sleep(150 * time.Millisecond) // second lease expires → exhausted
	if err := e.Step(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ = GetTask(ctx, pool, taskID)
	if got.State != "FAILED" {
		t.Fatalf("exhausted task = %s, want FAILED", got.State)
	}
	state, _ := e.WorkflowState(ctx, wfID)
	if state != "FAILED" {
		t.Fatalf("workflow = %s, want FAILED after task exhaustion", state)
	}
}

// The happy path end-to-end at engine level: assign → start → complete →
// workflow SUCCEEDED.
func TestWorkflowSucceeds(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	prov := &nullProv{}
	e := New(pool, prov, Options{Lease: time.Minute})
	wfID := mkWorkflow(t, e)
	if err := e.Step(ctx); err != nil {
		t.Fatal(err)
	}
	taskID := prov.tasks[0].ID
	if err := StartTask(ctx, pool, taskID, "w", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := CompleteTask(ctx, pool, taskID, "w", "ok", nil); err != nil {
		t.Fatal(err)
	}
	if err := e.Step(ctx); err != nil {
		t.Fatal(err)
	}
	state, err := e.WorkflowState(ctx, wfID)
	if err != nil {
		t.Fatal(err)
	}
	if state != "SUCCEEDED" {
		t.Fatalf("workflow = %s, want SUCCEEDED", state)
	}
}
