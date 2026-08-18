// Runner invariants against real Postgres. The two headline tests:
//
//   - TestSecondBootTakesNoLockOnServeSet — the F2 fix made executable: a
//     second boot's migration does ZERO DDL (ledger-skipped) and completes
//     while another session holds ACCESS SHARE on every serve-read-set
//     table. Before T2, the every-boot replay's ADD COLUMN IF NOT EXISTS
//     took ACCESS EXCLUSIVE there and would queue behind that reader.
//   - TestParallelBootSingleWinner — the I6 race re-proven on the extended
//     mechanism: two replicas booting concurrently, each step applied
//     exactly once, both boots succeed.
//
// These also execute the Postgres lock-behaviour claims against a live
// server rather than trusting the documentation summary (the "running
// corrects the plan" discipline): TestGuardedDDLRetries proves an AEL
// really does queue behind ACCESS SHARE and that lock_timeout bounds it.
package schemastep_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/acl"
	"ocng/internal/engine"
	"ocng/internal/lti"
	"ocng/internal/mediapackage"
	"ocng/internal/migrate"
	"ocng/internal/schemastep"
	"ocng/internal/search"
	"ocng/internal/serveset"
)

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
	schemaName := fmt.Sprintf("ocng_ss_%d", time.Now().UnixNano())
	// ",public" so extension objects (pg_trgm's gin_trgm_ops, used by the
	// search baseline) resolve — the same shape the e2e harness uses
	cfg.ConnConfig.RuntimeParams["search_path"] = schemaName + ",public"
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

// bootPlans mirrors cmd/ocng-core's migration list (plus ocng-migrate's, so
// migration_url_map — serve-read set member F3 — exists for the lock test).
func bootPlans() []struct {
	pkg   string
	steps []schemastep.Step
} {
	return []struct {
		pkg   string
		steps []schemastep.Step
	}{
		{"engine", engine.MigrationSteps()},
		{"mediapackage", mediapackage.MigrationSteps()},
		{"acl", acl.MigrationSteps()},
		{"search", search.MigrationSteps()},
		{"lti", lti.MigrationSteps()},
		{"migrate", migrate.MigrationSteps()},
	}
}

// boot runs every package plan the way a core replica does and returns the
// total number of steps actually executed.
func boot(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	total := 0
	for _, p := range bootPlans() {
		n, err := schemastep.Run(ctx, pool, p.pkg, p.steps)
		total += n
		if err != nil {
			return total, fmt.Errorf("%s: %w", p.pkg, err)
		}
	}
	return total, nil
}

// Every shipped plan must pass its own blocking-lock check — the mechanism
// refuses nothing it ships (and mediapackage's baseline HAS to be shipped
// guarded, or this fails).
func TestAllPackagesCheckClean(t *testing.T) {
	for _, p := range bootPlans() {
		if err := schemastep.Check(p.steps); err != nil {
			t.Errorf("%s: shipped plan fails its own check: %v", p.pkg, err)
		}
	}
}

// The F2 fix (done-condition 4). First boot applies everything; rows are
// inserted; then a second session takes ACCESS SHARE on the whole
// serve-read set and HOLDS it while the second boot runs. If any step
// acquired ACCESS EXCLUSIVE on those tables it would queue behind the
// reader and the boot would exceed the deadline; instead the ledger skips
// every step (executed == 0) and the boot completes with the reader open.
func TestSecondBootTakesNoLockOnServeSet(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	n, err := boot(ctx, pool)
	if err != nil {
		t.Fatalf("first boot: %v", err)
	}
	if n == 0 {
		t.Fatal("first boot executed zero steps — the fixture proves nothing")
	}

	// populate: a real element + publication so the tables are live data,
	// not empty shells
	if _, err := pool.Exec(ctx, `
		insert into mediapackage (id, title) values ('11111111-1111-1111-1111-111111111111', 't');
		insert into mp_element (id, mediapackage_id, kind, flavor, sha256, size_bytes)
		values ('22222222-2222-2222-2222-222222222222', '11111111-1111-1111-1111-111111111111',
		        'track', 'presenter/source', 'abc', 3);
		insert into publication (id, mediapackage_id, channel)
		values ('33333333-3333-3333-3333-333333333333', '11111111-1111-1111-1111-111111111111', 'engage-player');
		insert into publication_element (publication_id, element_id)
		values ('33333333-3333-3333-3333-333333333333', '22222222-2222-2222-2222-222222222222')`); err != nil {
		t.Fatalf("populate: %v", err)
	}

	// the long reader: ACCESS SHARE on every serve-read-set table, held open
	reader, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Release()
	tx, err := reader.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for _, tbl := range serveset.Tables {
		if _, err := tx.Exec(ctx, `lock table `+tbl+` in access share mode`); err != nil {
			t.Fatalf("reader lock on %s: %v", tbl, err)
		}
	}

	bootCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	n2, err := boot(bootCtx, pool)
	if err != nil {
		t.Fatalf("second boot did not complete under a held ACCESS SHARE reader — a DDL lock was taken on the serve-read set: %v", err)
	}
	if n2 != 0 {
		t.Fatalf("second boot executed %d steps; the ledger must skip ALL applied steps (zero DDL)", n2)
	}
}

// The F2 fixture bites: the OLD mechanism's replay shape (ADD COLUMN IF NOT
// EXISTS on an already-complete table — a no-op that still takes ACCESS
// EXCLUSIVE) really does queue behind the same held ACCESS SHARE reader the
// F2 test uses. Without this, "the second boot completes" could be
// vacuously true. [PG-SPEC verified live: the no-op DDL blocks.]
func TestF2FixtureWouldCatchOldReplay(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if _, err := boot(ctx, pool); err != nil {
		t.Fatal(err)
	}

	reader, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Release()
	tx, err := reader.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `lock table mp_element in access share mode`); err != nil {
		t.Fatal(err)
	}

	oldStyle, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err = pool.Exec(oldStyle, `alter table mp_element add column if not exists tech jsonb`)
	if err == nil {
		t.Fatal("the old replay shape did NOT block behind ACCESS SHARE — the F2 test's held-reader fixture proves nothing")
	}
}

// The I6 race, re-proven on the extended mechanism: two replicas boot
// concurrently; both succeed; the ledger holds each step exactly once and
// the concurrent index exists VALID.
func TestParallelBootSingleWinner(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = boot(ctx, pool)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("replica %d boot: %v", i, err)
		}
	}

	var dup int
	if err := pool.QueryRow(ctx, `
		select count(*) from (
		    select package, step from schema_migration group by package, step having count(*) > 1
		) d`).Scan(&dup); err != nil {
		t.Fatal(err)
	}
	if dup != 0 {
		t.Fatalf("%d (package, step) pairs applied more than once", dup)
	}

	var valid bool
	if err := pool.QueryRow(ctx, `
		select i.indisvalid from pg_index i
		join pg_class c on c.oid = i.indexrelid
		join pg_namespace n on n.oid = c.relnamespace
		where c.relname = 'mp_element_sha256_idx' and n.nspname = current_schema()`).Scan(&valid); err != nil {
		t.Fatalf("sha256 index missing after parallel boot: %v", err)
	}
	if !valid {
		t.Fatal("sha256 index exists but is INVALID after parallel boot")
	}
}

// Applied history is immutable: editing an applied step's SQL is an error
// pointing at the discipline doc, never a silent re-run.
func TestEditedAppliedStepRefused(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if _, err := schemastep.Run(ctx, pool, "x", []schemastep.Step{
		schemastep.TxDDL(0, "b", `create table if not exists x_t (id int)`)}); err != nil {
		t.Fatal(err)
	}
	_, err := schemastep.Run(ctx, pool, "x", []schemastep.Step{
		schemastep.TxDDL(0, "b", `create table if not exists x_t (id int, extra text)`)})
	if err == nil || !strings.Contains(err.Error(), "add a NEW step") {
		t.Fatalf("edited applied step must be refused with the add-a-new-step message; got: %v", err)
	}
}

// Crash-resume, concurrent-index: an INVALID leftover from a crashed build
// is dropped and rebuilt; a VALID index whose ledger row was lost is kept
// and only re-recorded.
func TestConcurrentIndexResume(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `create table ci_t (v text)`); err != nil {
		t.Fatal(err)
	}
	step := []schemastep.Step{schemastep.ConcurrentIndex(0, "idx", "ci_t_v_idx",
		`create index concurrently ci_t_v_idx on ci_t (v)`)}

	// simulate the crashed prior attempt's leftover: a same-named index
	// marked INVALID (what a failed CONCURRENTLY build leaves behind)
	if _, err := pool.Exec(ctx, `create index ci_t_v_idx on ci_t (v)`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		update pg_index set indisvalid = false
		where indexrelid = (select c.oid from pg_class c
		    join pg_namespace n on n.oid = c.relnamespace
		    where c.relname = 'ci_t_v_idx' and n.nspname = current_schema())`); err != nil {
		t.Skipf("cannot mark index INVALID (needs superuser): %v", err)
	}

	if n, err := schemastep.Run(ctx, pool, "ci", step); err != nil || n != 1 {
		t.Fatalf("resume over INVALID leftover: n=%d err=%v", n, err)
	}
	var valid bool
	if err := pool.QueryRow(ctx, `
		select i.indisvalid from pg_index i join pg_class c on c.oid = i.indexrelid
		join pg_namespace n on n.oid = c.relnamespace
		where c.relname = 'ci_t_v_idx' and n.nspname = current_schema()`).Scan(&valid); err != nil || !valid {
		t.Fatalf("index not rebuilt VALID: valid=%v err=%v", valid, err)
	}

	// crash between build and ledger write: lose the ledger row, re-run
	if _, err := pool.Exec(ctx, `delete from schema_migration where package = 'ci'`); err != nil {
		t.Fatal(err)
	}
	if n, err := schemastep.Run(ctx, pool, "ci", step); err != nil || n != 1 {
		t.Fatalf("re-record of a VALID index: n=%d err=%v", n, err)
	}
}

// Crash-resume, batched-dml: a failure mid-walk leaves no ledger row; the
// re-run re-derives remaining work and completes.
func TestBatchedDMLResume(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `create table bd_t (id int primary key, touched int not null default 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `insert into bd_t (id) select generate_series(1, 950)`); err != nil {
		t.Fatal(err)
	}

	mkStep := func(failAfter int) []schemastep.Step {
		batches := 0
		return []schemastep.Step{schemastep.BatchedDML(0, "touch", func(ctx context.Context, conn *pgxpool.Conn) (bool, error) {
			if failAfter > 0 && batches >= failAfter {
				return false, errors.New("injected crash")
			}
			batches++
			tag, err := conn.Exec(ctx, `
				update bd_t set touched = touched + 1
				where id in (select id from bd_t where touched = 0 order by id limit 400)`)
			if err != nil {
				return false, err
			}
			return tag.RowsAffected() == 0, nil
		})}
	}

	if _, err := schemastep.Run(ctx, pool, "bd", mkStep(1)); err == nil {
		t.Fatal("injected crash must surface")
	}
	var ledgered int
	pool.QueryRow(ctx, `select count(*) from schema_migration where package='bd'`).Scan(&ledgered)
	if ledgered != 0 {
		t.Fatal("a crashed batched step must not be ledgered")
	}
	var touched int
	pool.QueryRow(ctx, `select count(*) from bd_t where touched > 0`).Scan(&touched)
	if touched == 0 {
		t.Fatal("fixture: the crash must land mid-walk (some rows touched)")
	}

	if n, err := schemastep.Run(ctx, pool, "bd", mkStep(0)); err != nil || n != 1 {
		t.Fatalf("resume: n=%d err=%v", n, err)
	}
	var untouched int
	pool.QueryRow(ctx, `select count(*) from bd_t where touched = 0`).Scan(&untouched)
	if untouched != 0 {
		t.Fatalf("%d rows never touched — the resume did not re-derive remaining work", untouched)
	}
}

// The guarded step type, executed against the lock reality it exists for:
// a held ACCESS SHARE really does block the ALTER's ACCESS EXCLUSIVE
// [PG-SPEC verified live here]; lock_timeout + retry turns the unbounded
// stall into a bounded wait that succeeds once the reader finishes.
func TestGuardedDDLRetries(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `create table gd_t (id int)`); err != nil {
		t.Fatal(err)
	}

	reader, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Release()
	tx, err := reader.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `lock table gd_t in access share mode`); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(2 * time.Second)
		tx.Commit(ctx) // the long reader finishes; the next retry wins
	}()

	start := time.Now()
	n, err := schemastep.Run(ctx, pool, "gd", []schemastep.Step{
		schemastep.GuardedDDL(0, "add-col", `alter table gd_t add column note text`)})
	if err != nil || n != 1 {
		t.Fatalf("guarded DDL must succeed after the reader releases: n=%d err=%v", n, err)
	}
	if time.Since(start) < 1500*time.Millisecond {
		t.Fatalf("guarded DDL finished in %v — it never actually waited on the reader; the fixture proves nothing", time.Since(start))
	}
}
