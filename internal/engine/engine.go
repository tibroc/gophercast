// Package engine is the ADR-004 Postgres-backed durable engine, increment-1
// slice: one workflow running assigned operations on leased ephemeral
// workers (ADR-011 Solution A — assignment at creation, lease for liveness).
//
// Invariants carried from the ADRs, enforced here and tested in
// engine_test.go:
//
//   - Assignment is committed BEFORE provisioning (a worker can never start
//     and find its task absent).
//   - ASSIGNED→RUNNING is a single-row transition: of N over-provisioned
//     workers exactly one wins; losers get ErrTaskLost and exit cleanly.
//   - All lease arithmetic is Postgres now(); node clocks never enter it.
//   - Completion is TRANSACTIONAL: a task's mediapackage mutations commit in
//     the same transaction as its terminal write. This is what makes
//     re-execution of row-mutating operations safe (CAS dedups bytes, this
//     dedups rows) and is the engine-side answer for internal fan-out
//     (ADR-004 idempotency section).
//   - Terminal states are immutable at the database (guard trigger):
//     no stale owner, zombie, or future code path can overwrite a completed
//     task.
package engine

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/schemastep"
)

//go:embed schema.sql
var schema string

// ErrTaskLost is returned when a state transition finds the task no longer
// available to this owner: another worker won the ASSIGNED→RUNNING race,
// the lease was reaped, or the task is already terminal. The correct
// reaction is to stop silently — no side effects, no FAILED report (the
// a lost task belongs to someone else now).
var ErrTaskLost = errors.New("engine: task lost (raced, reaped, or terminal)")

// Task is what a provisioner receives: identity, never work-content — the
// worker reads everything else from the database by task id (ADR-011
// startup contract).
type Task struct {
	ID         int64
	WorkflowID int64
	OpIndex    int
	Operation  string
	Config     map[string]string
	State      string
	Attempt    int
}

// Provisioner is the provisioning port (ADR-011, environment-matched per
// A7/D-045): adapters live in internal/provision — None on VMs (the
// resident lease-worker discovers committed ASSIGNED rows; core holds no
// provisioning credential) and, deferred, a Kubernetes Job per task. Tests
// use a local exec adapter.
type Provisioner interface {
	Provision(ctx context.Context, task Task) error
}

// Spec is the per-task resource spec (ADR-011 A7's shared prerequisite —
// the ADR carried it as prose, never schema). The VM resident worker uses
// it as admission arithmetic; a future K8s Job adapter maps it to pod
// requests/limits. Zero values mean "not stated" — consumers apply their
// configured defaults.
type Spec struct {
	CPUMillis int `json:"cpu_millis,omitempty"` // 1000 = one core
	MemoryMB  int `json:"memory_mb,omitempty"`
	GPU       int `json:"gpu,omitempty"`
	RuntimeS  int `json:"runtime_s,omitempty"` // approx runtime; advisory, never admission
}

type OpDef struct {
	Operation string            `json:"operation"`
	Config    map[string]string `json:"config"`
	Spec      *Spec             `json:"spec,omitempty"` // optional per-op resource spec
}

type Definition struct {
	Operations []OpDef `json:"operations"`
}

type Options struct {
	Lease       time.Duration // lease granted at assignment and per renewal
	MaxAttempts int           // reap re-provisions until this; then task FAILED
	// Inline executes inline-class tasks in-process (ADR-011's second
	// execution class). Nil = no inline capability: inline-class tasks
	// fail loudly instead of silently waiting for a worker that will
	// never exist.
	Inline Provisioner
}

type Engine struct {
	pool *pgxpool.Pool
	prov Provisioner
	opts Options
}

// provision routes one assigned task to its execution class (ADR-011: the
// class is a property of the operation, from the static table in class.go).
// Unknown and unclear operations are failed LOUDLY and immediately — a task
// nobody will ever run must not sit ASSIGNED until lease exhaustion.
func (e *Engine) provision(ctx context.Context, t Task) {
	var p Provisioner
	switch ClassOf(t.Operation) {
	case ClassWorker:
		p = e.prov
	case ClassInline:
		p = e.opts.Inline
		if p == nil {
			e.failUnrunnable(ctx, t, "inline-class operation but engine has no inline runner")
			return
		}
	case ClassUnclear:
		e.failUnrunnable(ctx, t, "execution class UNCLEAR (one of the 4 undecided ops, CONTRACTS §3.2) — refusing to guess")
		return
	default:
		e.failUnrunnable(ctx, t, "not one of the 98 operations (no execution class)")
		return
	}
	// provisioning failure is not fatal: the lease is already running,
	// expiry will bring the task back through reap
	_ = p.Provision(ctx, t)
}

// failUnrunnable marks a task nobody can ever execute as FAILED, through the
// same single-winner transition every executor uses.
func (e *Engine) failUnrunnable(ctx context.Context, t Task, reason string) {
	owner := "engine-dispatch"
	if err := StartTask(ctx, e.pool, t.ID, owner, e.opts.Lease); err != nil {
		return // raced or already terminal: someone else owns the outcome
	}
	_ = FailTask(ctx, e.pool, t.ID, owner, fmt.Sprintf("operation %q: %s", t.Operation, reason))
}

// Migrate applies the engine schema: workflow + task tables, the
// single-row state transitions' constraints, and the terminal-write
// guard as a trigger. Serialised by an advisory lock: ADR-009 runs 1–2
// core replicas, so two processes migrating at once is a real deployment
// scenario, and the trigger DDL deadlocks without it (observed under
// parallel `go test ./...`).
//
// T2 (ratified Option A, 2026-08-17): the baseline is registered as ledger
// step 0 in the schemastep mechanism instead of being replayed every boot —
// an applied baseline is SKIPPED without acquiring any DDL lock. First-boot
// semantics are identical (the DDL runs once); the advisory key is the same
// (schemastep.AdvisoryKey == migrateLocked's literal), so the I6
// single-winner guarantee is unchanged. migrateLocked itself is untouched.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := schemastep.Run(ctx, pool, "engine", MigrationSteps())
	return err
}

// MigrationSteps is the engine's migration plan (exported so the boot-shape
// tests can run all packages' plans the way cmd/ocng-core does).
func MigrationSteps() []schemastep.Step {
	return []schemastep.Step{
		schemastep.TxDDL(0, "baseline", schema),
		// T3 (ADR-011 A7 shared prerequisite): per-task resource-spec
		// columns. Nullable adds — metadata-only AEL — and `task` is OFF
		// the serve-read set, so plain TxDDL is the correct step kind
		// (the classifier proves both; TestResourceSpecMigrationForwardProof).
		// This is the first NEW-increment schema through the T2 mechanism:
		// applied history is immutable, so these are a new step, not an
		// edit of the baseline.
		schemastep.TxDDL(1, "task-resource-spec", `
			alter table task add column if not exists spec_cpu_millis int;
			alter table task add column if not exists spec_memory_mb  int;
			alter table task add column if not exists spec_gpu        int;
			alter table task add column if not exists spec_runtime_s  int`),
		// T5 (ADR-009 workflow-definition authoring: bind mount authors,
		// database executes — internal/definitions). CREATE TABLE is
		// reader-safe and workflow_definition is OFF the serve-read set;
		// third forward use of the T2 mechanism (after T3's spec columns and
		// T4's gc/deleted_at), proven by
		// TestWorkflowDefinitionMigrationForwardProof.
		schemastep.TxDDL(2, "workflow-definition", `
			create table if not exists workflow_definition (
				id         text primary key,
				yaml       bytea not null,
				hash       text  not null,
				updated_at timestamptz not null default now()
			)`),
	}
}

func migrateLocked(ctx context.Context, pool *pgxpool.Pool, key int64, ddl string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `select pg_advisory_xact_lock($1)`, key); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, ddl); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// MigrateLocked is shared by other packages' schemas so every ocng
// migration serialises on the same advisory lock.
func MigrateLocked(ctx context.Context, pool *pgxpool.Pool, ddl string) error {
	return migrateLocked(ctx, pool, 0x0c9e_0001, ddl)
}

func New(pool *pgxpool.Pool, prov Provisioner, opts Options) *Engine {
	if opts.Lease <= 0 {
		opts.Lease = 60 * time.Second
	}
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = 3
	}
	return &Engine{pool: pool, prov: prov, opts: opts}
}

func (e *Engine) CreateWorkflow(ctx context.Context, mediapackageID string, def Definition) (int64, error) {
	if len(def.Operations) == 0 {
		return 0, fmt.Errorf("engine: workflow definition has no operations")
	}
	raw, err := json.Marshal(def)
	if err != nil {
		return 0, err
	}
	var id int64
	err = e.pool.QueryRow(ctx,
		`insert into workflow (mediapackage_id, definition) values ($1, $2) returning id`,
		mediapackageID, raw).Scan(&id)
	return id, err
}

func (e *Engine) WorkflowState(ctx context.Context, id int64) (string, error) {
	var s string
	err := e.pool.QueryRow(ctx, `select state from workflow where id = $1`, id).Scan(&s)
	return s, err
}

// Step runs one orchestrator pass:
//  1. reap tasks whose lease expired (re-assign or fail them),
//  2. advance workflows whose current task finished (or fail with it),
//  3. assign-and-provision the current operation of workflows lacking a task.
//
// Every mutation is guarded by state predicates, so concurrent Steps are
// safe; increment 1 runs one orchestrator.
func (e *Engine) Step(ctx context.Context) error {
	if err := e.reap(ctx); err != nil {
		return fmt.Errorf("reap: %w", err)
	}
	if err := e.advance(ctx); err != nil {
		return fmt.Errorf("advance: %w", err)
	}
	if err := e.assign(ctx); err != nil {
		return fmt.Errorf("assign: %w", err)
	}
	return nil
}

// reap handles lease expiry — the single recovery mechanism for both
// topologies (ADR-011: no platform watching, nothing resident to probe).
// An expired task below MaxAttempts returns to ASSIGNED for
// re-provisioning; at MaxAttempts it becomes FAILED.
func (e *Engine) reap(ctx context.Context) error {
	rows, err := e.pool.Query(ctx, `
		update task set state = 'ASSIGNED', owner = null,
		       attempt = attempt + 1,
		       lease_expires = now() + $1::interval,
		       updated_at = now()
		where state in ('ASSIGNED','RUNNING')
		  and lease_expires < now()
		  and attempt < $2
		returning id, workflow_id, op_index, operation, config, state, attempt`,
		e.opts.Lease.String(), e.opts.MaxAttempts)
	if err != nil {
		return err
	}
	reassigned, err := scanTasks(rows)
	if err != nil {
		return err
	}
	// out of attempts → the task fails (workflow follows in advance())
	if _, err := e.pool.Exec(ctx, `
		update task set state = 'FAILED', updated_at = now()
		where state in ('ASSIGNED','RUNNING')
		  and lease_expires < now()
		  and attempt >= $1`, e.opts.MaxAttempts); err != nil {
		return err
	}
	for _, t := range reassigned {
		e.provision(ctx, t)
	}
	return nil
}

// advance moves workflows forward past terminal tasks.
func (e *Engine) advance(ctx context.Context) error {
	// task FINISHED → next operation (or workflow SUCCEEDED)
	if _, err := e.pool.Exec(ctx, `
		update workflow w set
		    current_op = w.current_op + 1,
		    state = case
		        when w.current_op + 1 >= jsonb_array_length(w.definition->'operations')
		        then 'SUCCEEDED' else 'RUNNING' end,
		    updated_at = now()
		from task t
		where t.workflow_id = w.id
		  and t.op_index = w.current_op
		  and t.state = 'FINISHED'
		  and w.state = 'RUNNING'`); err != nil {
		return err
	}
	// task FAILED → workflow FAILED (retry-strategy none is the default;
	// per-operation retry is a later increment)
	_, err := e.pool.Exec(ctx, `
		update workflow w set state = 'FAILED', updated_at = now()
		from task t
		where t.workflow_id = w.id
		  and t.op_index = w.current_op
		  and t.state = 'FAILED'
		  and w.state = 'RUNNING'`)
	return err
}

// assignSQL is the single statement that creates task rows. The not-exists
// read is NOT the duplicate guard — two overlapping statements both pass it
// under read committed. The guard is the task_wf_op unique constraint; a
// racing loser inserts nothing (tested structurally in
// TestAssignInsertRaceStructural with two explicit transactions).
const assignSQL = `
	insert into task (workflow_id, op_index, operation, config, lease_expires,
	                  spec_cpu_millis, spec_memory_mb, spec_gpu, spec_runtime_s)
	select w.id, w.current_op,
	       w.definition->'operations'->w.current_op->>'operation',
	       coalesce(w.definition->'operations'->w.current_op->'config', '{}'::jsonb),
	       now() + $1::interval,
	       (w.definition->'operations'->w.current_op->'spec'->>'cpu_millis')::int,
	       (w.definition->'operations'->w.current_op->'spec'->>'memory_mb')::int,
	       (w.definition->'operations'->w.current_op->'spec'->>'gpu')::int,
	       (w.definition->'operations'->w.current_op->'spec'->>'runtime_s')::int
	from workflow w
	where w.state = 'RUNNING'
	  and not exists (select 1 from task t
	                  where t.workflow_id = w.id and t.op_index = w.current_op)
	on conflict (workflow_id, op_index) do nothing
	returning id, workflow_id, op_index, operation, config, state, attempt`

// assign creates the task row for each running workflow's current operation
// if none exists, COMMITS it, and only then provisions the worker with the
// task id (ADR-011 ordering).
func (e *Engine) assign(ctx context.Context) error {
	rows, err := e.pool.Query(ctx, assignSQL, e.opts.Lease.String())
	if err != nil {
		return err
	}
	created, err := scanTasks(rows)
	if err != nil {
		return err
	}
	for _, t := range created {
		e.provision(ctx, t)
	}
	return nil
}

func scanTasks(rows pgx.Rows) ([]Task, error) {
	defer rows.Close()
	var out []Task
	for rows.Next() {
		var t Task
		var cfg []byte
		if err := rows.Scan(&t.ID, &t.WorkflowID, &t.OpIndex, &t.Operation, &cfg, &t.State, &t.Attempt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(cfg, &t.Config); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ---- worker-side task client (the ADR-011 startup contract) ----

// GetTask reads a task by id — the only thing a worker is told at creation.
func GetTask(ctx context.Context, pool *pgxpool.Pool, id int64) (Task, error) {
	var t Task
	var cfg []byte
	err := pool.QueryRow(ctx, `
		select id, workflow_id, op_index, operation, config, state, attempt
		from task where id = $1`, id).
		Scan(&t.ID, &t.WorkflowID, &t.OpIndex, &t.Operation, &cfg, &t.State, &t.Attempt)
	if err != nil {
		return Task{}, err
	}
	return t, json.Unmarshal(cfg, &t.Config)
}

// GetSpec reads a task's resource spec. Absent (null) dimensions come back
// as zero — "not stated"; consumers apply their configured defaults. A
// separate read on purpose: the assignment/lease statements and Task struct
// stay exactly as increment 1 proved them; the spec is data ABOUT the task,
// not part of the protocol.
func GetSpec(ctx context.Context, pool *pgxpool.Pool, taskID int64) (Spec, error) {
	var s Spec
	err := pool.QueryRow(ctx, `
		select coalesce(spec_cpu_millis, 0), coalesce(spec_memory_mb, 0),
		       coalesce(spec_gpu, 0), coalesce(spec_runtime_s, 0)
		from task where id = $1`, taskID).
		Scan(&s.CPUMillis, &s.MemoryMB, &s.GPU, &s.RuntimeS)
	return s, err
}

// MediapackageID resolves the mediapackage a task operates on.
func MediapackageID(ctx context.Context, pool *pgxpool.Pool, taskID int64) (string, error) {
	var mp string
	err := pool.QueryRow(ctx, `
		select w.mediapackage_id::text from workflow w
		join task t on t.workflow_id = w.id where t.id = $1`, taskID).Scan(&mp)
	return mp, err
}

// StartTask is the single-row ASSIGNED→RUNNING transition. Exactly one of N
// over-provisioned workers wins; every other caller gets ErrTaskLost and
// must exit cleanly with no side effects.
func StartTask(ctx context.Context, pool *pgxpool.Pool, taskID int64, owner string, lease time.Duration) error {
	tag, err := pool.Exec(ctx, `
		update task set state = 'RUNNING', owner = $2,
		       lease_expires = now() + $3::interval, updated_at = now()
		where id = $1 and state = 'ASSIGNED'`,
		taskID, owner, lease.String())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrTaskLost
	}
	return nil
}

// RenewLease extends the lease while work is in progress. ErrTaskLost means
// the reaper took the task back: stop working, produce no side effects.
func RenewLease(ctx context.Context, pool *pgxpool.Pool, taskID int64, owner string, lease time.Duration) error {
	tag, err := pool.Exec(ctx, `
		update task set lease_expires = now() + $3::interval, updated_at = now()
		where id = $1 and owner = $2 and state = 'RUNNING'`,
		taskID, owner, lease.String())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrTaskLost
	}
	return nil
}

// CompleteTask commits the task's data mutations and its RUNNING→FINISHED
// transition in ONE transaction. mutate receives the transaction; whatever
// it writes (element rows, catalogs) becomes visible if and only if the
// completion wins. If the task was lost (reaped, raced, already terminal —
// a terminal task) the whole transaction rolls back: no orphan rows, no
// stale overwrite, ErrTaskLost.
func CompleteTask(ctx context.Context, pool *pgxpool.Pool, taskID int64, owner string, result any, mutate func(ctx context.Context, tx pgx.Tx) error) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if mutate != nil {
		if err := mutate(ctx, tx); err != nil {
			return err
		}
	}
	tag, err := tx.Exec(ctx, `
		update task set state = 'FINISHED', result = $3, updated_at = now()
		where id = $1 and owner = $2 and state = 'RUNNING'`,
		taskID, owner, raw)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrTaskLost // rollback discards mutate's writes
	}
	return tx.Commit(ctx)
}

// FailTask records a worker-detected failure. Guarded like CompleteTask:
// a lost task may not be failed by its former owner.
func FailTask(ctx context.Context, pool *pgxpool.Pool, taskID int64, owner string, reason string) error {
	raw, _ := json.Marshal(map[string]string{"error": reason})
	tag, err := pool.Exec(ctx, `
		update task set state = 'FAILED', result = $3, updated_at = now()
		where id = $1 and owner = $2 and state = 'RUNNING'`,
		taskID, owner, raw)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrTaskLost
	}
	return nil
}
