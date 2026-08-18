// Loader + Registry invariants against real Postgres: the ADR-009 mechanism
// end to end at package level (the e2e suite proves it through the binary).
//
//   - boot load is fail-loud (unparseable file, duplicate id → error);
//   - a runtime re-load of a now-malformed file keeps the LAST-GOOD row
//     serving and does not error the pass;
//   - an edit is picked up and the hash changes (drift detectability);
//   - racing loaders (two replicas) converge on identical rows;
//   - the Registry reads what the Loader wrote, and negative lookups say no.
package definitions

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/engine"
	"ocng/internal/schemastep"
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
	schemaName := fmt.Sprintf("ocng_defs_%d", time.Now().UnixNano())
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
	// the workflow_definition table arrives via the engine plan (T5 step 2
	// of MigrationSteps) — the same path the binary takes
	if _, err := schemastep.Run(context.Background(), pool, "engine", engine.MigrationSteps()); err != nil {
		t.Fatalf("engine migrate: %v", err)
	}
	return pool
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func testLog() *slog.Logger { return slog.New(slog.NewTextHandler(os.Stderr, nil)) }

func rowHash(t *testing.T, pool *pgxpool.Pool, id string) string {
	t.Helper()
	var h string
	if err := pool.QueryRow(context.Background(),
		`select hash from workflow_definition where id = $1`, id).Scan(&h); err != nil {
		t.Fatalf("row %q: %v", id, err)
	}
	return h
}

func TestLoaderAuthoringLifecycle(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	dir := t.TempDir()
	writeFile(t, dir, "eval2.yaml", goodYAML)
	writeFile(t, dir, "ignored.txt", "not yaml, not read")

	l := &Loader{Pool: pool, Dir: dir, Log: testLog()}
	if err := l.LoadOnce(ctx); err != nil {
		t.Fatalf("boot load: %v", err)
	}
	h1 := rowHash(t, pool, "ocng-eval-2")
	if h1 != Hash([]byte(goodYAML)) {
		t.Fatalf("stored hash %s is not the content hash", h1)
	}

	// the registry serves what the loader wrote
	reg := &Registry{Pool: pool, TTL: time.Millisecond}
	def, ok, err := reg.Definition(ctx, "ocng-eval-2")
	if err != nil || !ok {
		t.Fatalf("registry lookup: ok=%v err=%v", ok, err)
	}
	if len(def.Operations) != 3 || def.Operations[1].Operation != "encode" {
		t.Fatalf("registry returned wrong definition: %+v", def)
	}
	if _, ok, err := reg.Definition(ctx, "no-such"); err != nil || ok {
		t.Fatalf("negative lookup: ok=%v err=%v", ok, err)
	}

	// EDIT: picked up on the next pass, hash changes (drift detectability —
	// disagreement between replicas is a query over this column)
	edited := strings.Replace(goodYAML, "cpu_millis: 2000", "cpu_millis: 3000", 1)
	writeFile(t, dir, "eval2.yaml", edited)
	if err := l.load(ctx, false); err != nil {
		t.Fatalf("runtime reload: %v", err)
	}
	h2 := rowHash(t, pool, "ocng-eval-2")
	if h2 == h1 || h2 != Hash([]byte(edited)) {
		t.Fatalf("edit not picked up: %s -> %s", h1, h2)
	}
	def, ok, err = reg.Definition(ctx, "ocng-eval-2")
	if err != nil || !ok || def.Operations[1].Spec.CPUMillis != 3000 {
		t.Fatalf("registry did not see the edit: %+v ok=%v err=%v", def, ok, err)
	}

	// MALFORMED EDIT at runtime: last-good keeps serving, pass does not error
	writeFile(t, dir, "eval2.yaml", "id: ocng-eval-2\noperations: []\n")
	if err := l.load(ctx, false); err != nil {
		t.Fatalf("runtime pass errored on a malformed file: %v", err)
	}
	if got := rowHash(t, pool, "ocng-eval-2"); got != h2 {
		t.Fatalf("malformed edit replaced the last-good row: %s -> %s", h2, got)
	}

	// a NEW file appears at runtime
	second := "id: second\noperations:\n  - operation: inspect\n    config: {}\n"
	writeFile(t, dir, "second.yml", second)
	if err := l.load(ctx, false); err != nil {
		t.Fatal(err)
	}
	if rowHash(t, pool, "second") != Hash([]byte(second)) {
		t.Fatal("new runtime file not loaded")
	}

	// REMOVING a file does not delete the row (stated non-behaviour)
	os.Remove(filepath.Join(dir, "second.yml"))
	if err := l.load(ctx, false); err != nil {
		t.Fatal(err)
	}
	if rowHash(t, pool, "second") != Hash([]byte(second)) {
		t.Fatal("file removal deleted the definition row")
	}
}

func TestLoaderBootFailLoud(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)

	// unparseable file at boot
	dir := t.TempDir()
	writeFile(t, dir, "bad.yaml", "id: x\noperations: []\n")
	l := &Loader{Pool: pool, Dir: dir, Log: testLog()}
	if err := l.LoadOnce(ctx); err == nil || !strings.Contains(err.Error(), "bad.yaml") {
		t.Fatalf("boot accepted an unparseable file: %v", err)
	}

	// unreadable directory at boot
	l2 := &Loader{Pool: pool, Dir: filepath.Join(dir, "nope"), Log: testLog()}
	if err := l2.LoadOnce(ctx); err == nil {
		t.Fatal("boot accepted a missing directory")
	}

	// duplicate id across files at boot
	dir3 := t.TempDir()
	one := "id: dup\noperations:\n  - operation: inspect\n    config: {}\n"
	writeFile(t, dir3, "a.yaml", one)
	writeFile(t, dir3, "b.yaml", one+"# same id, different bytes\n")
	l3 := &Loader{Pool: pool, Dir: dir3, Log: testLog()}
	if err := l3.LoadOnce(ctx); err == nil || !strings.Contains(err.Error(), "dup") {
		t.Fatalf("boot accepted a duplicate id: %v", err)
	}

	// include at boot names the stated limit
	dir4 := t.TempDir()
	writeFile(t, dir4, "inc.yaml", "id: inc\noperations:\n  - operation: include\n    config: {}\n")
	l4 := &Loader{Pool: pool, Dir: dir4, Log: testLog()}
	if err := l4.LoadOnce(ctx); err == nil || !strings.Contains(err.Error(), "stated limit") {
		t.Fatalf("boot include rejection wrong: %v", err)
	}
}

// Two replicas run the loader against the same database (ADR-009: both
// watch their mounts). Idempotent upserts on (id, hash): identical bytes
// converge on one row; a genuine divergence is last-write-wins in the DB
// and detectable by hash.
func TestLoaderTwoReplicasConverge(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	dirA, dirB := t.TempDir(), t.TempDir()
	writeFile(t, dirA, "d.yaml", goodYAML)
	writeFile(t, dirB, "d.yaml", goodYAML)

	la := &Loader{Pool: pool, Dir: dirA, Log: testLog()}
	lb := &Loader{Pool: pool, Dir: dirB, Log: testLog()}
	errs := make(chan error, 2)
	go func() { errs <- la.LoadOnce(ctx) }()
	go func() { errs <- lb.LoadOnce(ctx) }()
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("replica load: %v", err)
		}
	}
	var n int
	if err := pool.QueryRow(ctx, `select count(*) from workflow_definition`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 row, got %d", n)
	}
	if rowHash(t, pool, "ocng-eval-2") != Hash([]byte(goodYAML)) {
		t.Fatal("converged row has wrong hash")
	}
}
