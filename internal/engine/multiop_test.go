// Increment-2 engine-boundary tests — closing exactly what INVARIANTS.md
// names as unproven: the (workflow_id, op_index) uniqueness under concurrent
// orchestrators, and advance() for op count > 1 (sequencing, resume,
// definition pinning). Written RED-first against the increment-1 engine.
package engine

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// mkMultiWorkflow creates a workflow of n worker-class operations (real
// operation ids from the ADR-011 table, so no class overrides are needed).
func mkMultiWorkflow(t *testing.T, e *Engine, n int) int64 {
	t.Helper()
	names := []string{"inspect", "encode", "speechtotext"} // all ClassWorker
	var ops []OpDef
	for i := 0; i < n; i++ {
		ops = append(ops, OpDef{Operation: names[i%len(names)], Config: map[string]string{"step": string(rune('0' + i))}})
	}
	id, err := e.CreateWorkflow(context.Background(), "00000000-0000-0000-0000-000000000002", Definition{Operations: ops})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func completeTask(t *testing.T, pool *pgxpool.Pool, taskID int64, owner string) {
	t.Helper()
	ctx := context.Background()
	if err := StartTask(ctx, pool, taskID, owner, time.Minute); err != nil {
		t.Fatalf("start %d: %v", taskID, err)
	}
	if err := CompleteTask(ctx, pool, taskID, owner, "ok", nil); err != nil {
		t.Fatalf("complete %d: %v", taskID, err)
	}
}

// The concurrent-assign hole INVARIANTS.md boundary 1 names: two
// orchestrators stepping the same database must never create two task rows
// for one (workflow, op_index). The guard must be structural (a unique
// constraint), not the not-exists read — two overlapping insert-selects
// both pass that read.
func TestConcurrentOrchestratorsAssignOnce(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	provA, provB := &nullProv{}, &nullProv{}
	engA := New(pool, provA, Options{Lease: time.Minute})
	engB := New(pool, provB, Options{Lease: time.Minute})

	const workflows = 40
	for i := 0; i < workflows; i++ {
		mkMultiWorkflow(t, engA, 1)
	}

	// both orchestrators step concurrently, repeatedly — the assign
	// insert-selects overlap across the whole workflow set
	var wg sync.WaitGroup
	for _, e := range []*Engine{engA, engB} {
		e := e
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				if err := e.Step(ctx); err != nil {
					t.Errorf("step: %v", err)
				}
			}
		}()
	}
	wg.Wait()

	var dups int
	if err := pool.QueryRow(ctx, `
		select count(*) from (
			select workflow_id, op_index from task
			group by workflow_id, op_index having count(*) > 1) d`).Scan(&dups); err != nil {
		t.Fatal(err)
	}
	if dups != 0 {
		t.Fatalf("%d (workflow, op_index) pairs have duplicate task rows — double assignment", dups)
	}
	var total int
	pool.QueryRow(ctx, `select count(*) from task`).Scan(&total)
	if total != workflows {
		t.Fatalf("task rows = %d, want %d (one per workflow)", total, workflows)
	}
}

// The same hole, made deterministic: two explicit transactions run the
// engine's own assign statement concurrently. Under read committed each
// statement's not-exists snapshot misses the other's uncommitted insert, so
// without a structural guard BOTH insert and both commits succeed — the
// exact two-orchestrator interleave, with the race window held open by
// hand.
func TestAssignInsertRaceStructural(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	e := New(pool, &nullProv{}, Options{Lease: time.Minute})
	mkMultiWorkflow(t, e, 1)

	tx1, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx1.Rollback(ctx)
	tx2, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx2.Rollback(ctx)

	r1, err := tx1.Query(ctx, assignSQL, "1 minute")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scanTasks(r1); err != nil {
		t.Fatal(err)
	}
	// tx2's statement runs while tx1 is uncommitted; with the unique
	// constraint it BLOCKS on tx1's speculative insert, so commit tx1
	// from a goroutine to let tx2 resolve either way.
	done := make(chan error, 1)
	go func() {
		time.Sleep(200 * time.Millisecond)
		done <- tx1.Commit(ctx)
	}()
	r2, err := tx2.Query(ctx, assignSQL, "1 minute")
	var second []Task
	if err == nil {
		second, err = scanTasks(r2)
	}
	if err == nil {
		err = tx2.Commit(ctx)
	}
	if cerr := <-done; cerr != nil {
		t.Fatalf("tx1 commit: %v", cerr)
	}
	// tx2 may error (unique violation) or succeed inserting nothing —
	// both are correct; two committed rows are not.
	if err == nil && len(second) > 0 {
		t.Logf("tx2 also inserted %d rows", len(second))
	}
	var n int
	if err := pool.QueryRow(ctx, `select count(*) from task`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("committed task rows = %d, want 1 — the not-exists read is not a guard", n)
	}
}

// advance() for op count > 1: operations run strictly in definition order,
// each op's task created only after the previous finished, workflow
// SUCCEEDED after the last.
func TestMultiOpSequencing(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	prov := &nullProv{}
	e := New(pool, prov, Options{Lease: time.Minute})
	wfID := mkMultiWorkflow(t, e, 3)

	for step := 0; step < 3; step++ {
		if err := e.Step(ctx); err != nil {
			t.Fatal(err)
		}
		prov.mu.Lock()
		n := len(prov.tasks)
		var cur Task
		if n > 0 {
			cur = prov.tasks[n-1]
		}
		prov.mu.Unlock()
		if n != step+1 {
			t.Fatalf("after completing %d ops: %d tasks provisioned, want %d", step, n, step+1)
		}
		if cur.OpIndex != step {
			t.Fatalf("provisioned op_index %d, want %d — out of order", cur.OpIndex, step)
		}
		completeTask(t, pool, cur.ID, "w")
	}
	if err := e.Step(ctx); err != nil {
		t.Fatal(err)
	}
	state, err := e.WorkflowState(ctx, wfID)
	if err != nil {
		t.Fatal(err)
	}
	if state != "SUCCEEDED" {
		t.Fatalf("workflow = %s after last op, want SUCCEEDED", state)
	}
	prov.mu.Lock()
	defer prov.mu.Unlock()
	if len(prov.tasks) != 3 {
		t.Fatalf("%d tasks total, want exactly 3", len(prov.tasks))
	}
}

// Resume after crash mid-workflow: the orchestrator dies between op N and
// N+1 (nothing in memory survives); a FRESH engine on the same database
// resumes from the persisted position — op N is not re-run, op N+1 is next.
func TestResumeMidWorkflowAfterCrash(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	provA := &nullProv{}
	engA := New(pool, provA, Options{Lease: time.Minute})
	wfID := mkMultiWorkflow(t, engA, 3)

	if err := engA.Step(ctx); err != nil {
		t.Fatal(err)
	}
	completeTask(t, pool, provA.tasks[0].ID, "w")
	// crash: engA is never stepped again; a new orchestrator takes over
	provB := &nullProv{}
	engB := New(pool, provB, Options{Lease: time.Minute})
	for i := 0; i < 2; i++ {
		if err := engB.Step(ctx); err != nil {
			t.Fatal(err)
		}
		provB.mu.Lock()
		cur := provB.tasks[len(provB.tasks)-1]
		provB.mu.Unlock()
		want := i + 1 // ops 1 then 2 — op 0 must NOT reappear
		if cur.OpIndex != want {
			t.Fatalf("resumed at op_index %d, want %d", cur.OpIndex, want)
		}
		completeTask(t, pool, cur.ID, "w")
	}
	if err := engB.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if state, _ := engB.WorkflowState(ctx, wfID); state != "SUCCEEDED" {
		t.Fatalf("resumed workflow = %s, want SUCCEEDED", state)
	}
}

// Definition pinning: the definition executes as it was at CreateWorkflow.
// Mutating the caller's Definition value afterwards must change nothing —
// the database copy is what executes (ADR-009: bind mounts are authoring,
// the database is execution).
func TestDefinitionPinnedAtCreate(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	prov := &nullProv{}
	e := New(pool, prov, Options{Lease: time.Minute})

	def := Definition{Operations: []OpDef{
		{Operation: "inspect", Config: map[string]string{"k": "original"}},
		{Operation: "encode", Config: map[string]string{}},
	}}
	wfID, err := e.CreateWorkflow(ctx, "00000000-0000-0000-0000-000000000003", def)
	if err != nil {
		t.Fatal(err)
	}
	// the caller mutates everything it still holds
	def.Operations[0].Operation = "speechtotext"
	def.Operations[0].Config["k"] = "mutated"
	def.Operations = append(def.Operations[:1], OpDef{Operation: "encode"})

	if err := e.Step(ctx); err != nil {
		t.Fatal(err)
	}
	got := prov.tasks[0]
	if got.Operation != "inspect" || got.Config["k"] != "original" {
		t.Fatalf("first task = %s %v — definition not pinned at create", got.Operation, got.Config)
	}
	completeTask(t, pool, got.ID, "w")
	if err := e.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if op := prov.tasks[1].Operation; op != "encode" {
		t.Fatalf("second task = %s, want encode from the pinned definition", op)
	}
	completeTask(t, pool, prov.tasks[1].ID, "w")
	if err := e.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if state, _ := e.WorkflowState(ctx, wfID); state != "SUCCEEDED" {
		t.Fatalf("workflow = %s, want SUCCEEDED (two pinned ops)", state)
	}
}
