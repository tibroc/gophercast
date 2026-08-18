// T3's resource-spec migration — the FIRST new-increment schema through
// T2's mechanism (everything T2 checked was retroactive; this is the
// forward proof the fast-migration discipline works when ADDING schema).
package engine

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/schemastep"
	"ocng/internal/serveset"
)

// poolWithoutMigrate is testPool minus the Migrate call — part (4) below
// drives the migration steps explicitly to replay the T2-era→T3 boot
// sequence.
func poolWithoutMigrate(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("OCNG_E2E_PG")
	if url == "" {
		url = "postgres://ocng:ocng@127.0.0.1:15432/ocng"
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	schemaName := fmt.Sprintf("ocng_spec_t_%d", time.Now().UnixNano())
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
	return pool
}

// TestResourceSpecMigrationForwardProof is the forward proof, in four parts:
//
//  1. the classifier ACCEPTS the plan (not assumed: Check really runs);
//  2. it accepts it for the right REASON — every spec statement is
//     metadata-AEL targeting `task`, and `task` is off the serve-read set;
//  3. the acceptance is not vacuous: the same nullable-add aimed at a
//     serve-read-set table as a plain TxDDL step is REFUSED;
//  4. the live forward path works: a T2-era database (step 0 applied) picks
//     up exactly step 1 on the next boot, and the boot after that is a
//     zero-DDL ledger skip (the F2 property preserved through the addition).
func TestResourceSpecMigrationForwardProof(t *testing.T) {
	steps := MigrationSteps()

	// (1) the classifier accepts the plan
	if err := schemastep.Check(steps); err != nil {
		t.Fatalf("T2's classifier refused the T3 resource-spec plan: %v", err)
	}

	// (2) the reason: metadata-AEL on task, task off the serve-read set
	if serveset.Contains("task") {
		t.Fatal("task is in the serve-read set — the whole off-set premise of this migration is wrong")
	}
	spec := steps[1]
	if spec.Name != "task-resource-spec" {
		t.Fatalf("step 1 is %q, expected task-resource-spec", spec.Name)
	}
	stmts := schemastep.SplitStatements(spec.SQL)
	if len(stmts) != 4 {
		t.Fatalf("expected 4 ALTER statements, got %d", len(stmts))
	}
	for _, stmt := range stmts {
		class, table := schemastep.ClassifyStatement(stmt)
		if class != schemastep.ClassMetadataAEL || table != "task" {
			t.Fatalf("statement %q classified (%s, %q), want (metadata-AEL, task)", stmt, class, table)
		}
	}

	// (3) counterfactual: the identical shape on a serve-read-set table as a
	// plain (unguarded) step must be refused — proving Check has teeth here
	bad := []schemastep.Step{schemastep.TxDDL(0, "bad",
		`alter table mp_element add column if not exists spec_cpu_millis int`)}
	if err := schemastep.Check(bad); err == nil {
		t.Fatal("classifier accepted an unguarded metadata-AEL on mp_element — the pass in (1) proves nothing")
	}

	// (4) live forward path: T2-era DB (baseline only) → the T3-era boot
	// applies exactly the spec step → the boot after that is a full ledger
	// skip. Pinned to steps[:2] since T5 appended step 2 — this test replays
	// the T2→T3 history; the T5 step's own forward path is
	// TestWorkflowDefinitionMigrationForwardProof.
	pool := poolWithoutMigrate(t)
	n, err := schemastep.Run(context.Background(), pool, "engine", steps[:1])
	if err != nil {
		t.Fatalf("T2-era baseline: %v", err)
	}
	if n != 1 {
		t.Fatalf("baseline on a fresh schema should execute 1 step, executed %d", n)
	}
	n, err = schemastep.Run(context.Background(), pool, "engine", steps[:2])
	if err != nil {
		t.Fatalf("forward boot: %v", err)
	}
	if n != 1 {
		t.Fatalf("forward boot should execute exactly the spec step, executed %d", n)
	}
	n, err = schemastep.Run(context.Background(), pool, "engine", steps[:2])
	if err != nil {
		t.Fatalf("second boot: %v", err)
	}
	if n != 0 {
		t.Fatalf("second boot must be a zero-DDL ledger skip, executed %d", n)
	}
}

// TestWorkflowDefinitionMigrationForwardProof — the T5 definitions table
// through T2's mechanism, the THIRD forward use (after T3's spec columns
// and T4's write-surface steps). Same four-part shape as the T3 proof:
//
//  1. the classifier ACCEPTS the full engine plan (Check really runs);
//  2. for the right REASON — the step is a reader-safe CREATE TABLE and
//     workflow_definition is OFF the serve-read set;
//  3. not vacuously — the same table shape created and then rewritten on a
//     serve-read-set table is REFUSED;
//  4. live forward path: a T4-era database (steps 0–1 applied) picks up
//     exactly the definitions step on the next boot, and the boot after
//     that is a zero-DDL ledger skip.
func TestWorkflowDefinitionMigrationForwardProof(t *testing.T) {
	steps := MigrationSteps()

	// (1) the classifier accepts the plan
	if err := schemastep.Check(steps); err != nil {
		t.Fatalf("T2's classifier refused the T5 plan: %v", err)
	}

	// (2) the reason: reader-safe CREATE TABLE, off the serve-read set
	if serveset.Contains("workflow_definition") {
		t.Fatal("workflow_definition is in the serve-read set — the off-set premise is wrong")
	}
	def := steps[2]
	if def.Name != "workflow-definition" {
		t.Fatalf("step 2 is %q, expected workflow-definition", def.Name)
	}
	stmts := schemastep.SplitStatements(def.SQL)
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(stmts))
	}
	class, table := schemastep.ClassifyStatement(stmts[0])
	if class != schemastep.ClassReaderSafe || table != "workflow_definition" {
		t.Fatalf("statement classified (%s, %q), want (reader-safe, workflow_definition)", class, table)
	}

	// (3) counterfactual: a rewrite-class statement on a serve-read-set
	// table is refused — the pass in (1) is not vacuous
	bad := []schemastep.Step{schemastep.TxDDL(0, "bad",
		`alter table publication alter column acl_read set data type jsonb`)}
	if err := schemastep.Check(bad); err == nil {
		t.Fatal("classifier accepted a rewrite-AEL on publication")
	}

	// (4) live forward path: T4-era DB (steps 0–1) → next boot applies
	// exactly the definitions step → then a zero-DDL skip
	pool := poolWithoutMigrate(t)
	n, err := schemastep.Run(context.Background(), pool, "engine", steps[:2])
	if err != nil {
		t.Fatalf("T4-era history: %v", err)
	}
	if n != 2 {
		t.Fatalf("T4-era history should execute 2 steps, executed %d", n)
	}
	n, err = schemastep.Run(context.Background(), pool, "engine", steps)
	if err != nil {
		t.Fatalf("T5 boot: %v", err)
	}
	if n != 1 {
		t.Fatalf("T5 boot should execute exactly the definitions step, executed %d", n)
	}
	n, err = schemastep.Run(context.Background(), pool, "engine", steps)
	if err != nil {
		t.Fatalf("second boot: %v", err)
	}
	if n != 0 {
		t.Fatalf("second boot must be a zero-DDL ledger skip, executed %d", n)
	}
	// and the table is really there
	var one int
	if err := pool.QueryRow(context.Background(),
		`select count(*) from workflow_definition`).Scan(&one); err != nil {
		t.Fatalf("workflow_definition not queryable: %v", err)
	}
}

// TestAssignPopulatesSpec: a definition op with a spec lands its values in
// the task columns; one without leaves them null (GetSpec reads zeros).
func TestAssignPopulatesSpec(t *testing.T) {
	pool := testPool(t)
	prov := &nullProv{}
	e := New(pool, prov, Options{Lease: time.Minute})
	ctx := context.Background()

	withSpec, err := e.CreateWorkflow(ctx, "11111111-1111-1111-1111-111111111111", Definition{
		Operations: []OpDef{{
			Operation: "encode",
			Spec:      &Spec{CPUMillis: 2000, MemoryMB: 4096, GPU: 0, RuntimeS: 600},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	without, err := e.CreateWorkflow(ctx, "22222222-2222-2222-2222-222222222222", Definition{
		Operations: []OpDef{{Operation: "encode"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Step(ctx); err != nil {
		t.Fatal(err)
	}

	taskID := func(wf int64) int64 {
		var id int64
		if err := pool.QueryRow(ctx, `select id from task where workflow_id = $1`, wf).Scan(&id); err != nil {
			t.Fatalf("task for workflow %d: %v", wf, err)
		}
		return id
	}

	got, err := GetSpec(ctx, pool, taskID(withSpec))
	if err != nil {
		t.Fatal(err)
	}
	if got != (Spec{CPUMillis: 2000, MemoryMB: 4096, GPU: 0, RuntimeS: 600}) {
		t.Fatalf("spec did not survive assignment: %+v", got)
	}

	// absent spec: columns are NULL (not zero) — "not stated", and GetSpec
	// maps that to the zero Spec for consumers to default
	var nullCount int
	if err := pool.QueryRow(ctx, `
		select count(*) from task where workflow_id = $1
		and spec_cpu_millis is null and spec_memory_mb is null
		and spec_gpu is null and spec_runtime_s is null`, without).Scan(&nullCount); err != nil {
		t.Fatal(err)
	}
	if nullCount != 1 {
		t.Fatal("a spec-less op must leave the spec columns NULL")
	}
	got, err = GetSpec(ctx, pool, taskID(without))
	if err != nil {
		t.Fatal(err)
	}
	if got != (Spec{}) {
		t.Fatalf("GetSpec on null columns should be the zero Spec, got %+v", got)
	}
}
