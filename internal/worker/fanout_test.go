// Fan-out proofs (T3, ADR-011 A7). Real Postgres for everything touching
// the task protocol — the engine IS SQL; a mocked database would prove
// nothing about the single-winner transition the fan-out claims to
// preserve. The per-slot body is stubbed (no media tools): the stub drives
// the REAL engine transitions (StartTask/CompleteTask), so what these
// tests exercise is exactly the assignment-and-lease path.
package worker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/cas"
	"ocng/internal/engine"
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
	schemaName := fmt.Sprintf("ocng_fan_t_%d", time.Now().UnixNano())
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
	if err := engine.Migrate(context.Background(), pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

// assignedTask inserts a workflow + an ASSIGNED task row with the given
// spec (0 = NULL column, "not stated").
func assignedTask(t *testing.T, pool *pgxpool.Pool, op string, spec engine.Spec) int64 {
	t.Helper()
	ctx := context.Background()
	var wfID int64
	if err := pool.QueryRow(ctx, `
		insert into workflow (mediapackage_id, definition)
		values (gen_random_uuid(), '{"operations":[{"operation":"stub"}]}')
		returning id`).Scan(&wfID); err != nil {
		t.Fatal(err)
	}
	toCol := func(v int) *int {
		if v == 0 {
			return nil
		}
		return &v
	}
	var taskID int64
	if err := pool.QueryRow(ctx, `
		insert into task (workflow_id, op_index, operation, lease_expires,
		                  spec_cpu_millis, spec_memory_mb, spec_gpu, spec_runtime_s)
		values ($1, 0, $2, now() + interval '5 minutes', $3, $4, $5, $6)
		returning id`,
		wfID, op, toCol(spec.CPUMillis), toCol(spec.MemoryMB), toCol(spec.GPU), toCol(spec.RuntimeS)).
		Scan(&taskID); err != nil {
		t.Fatal(err)
	}
	return taskID
}

func TestAdmissionArithmetic(t *testing.T) {
	a := &admitter{cap: engine.Spec{CPUMillis: 2000, MemoryMB: 1024, GPU: 0}}

	if !a.tryAdmit(engine.Spec{CPUMillis: 1500, MemoryMB: 512}) {
		t.Fatal("first task fits capacity, must be admitted")
	}
	if a.tryAdmit(engine.Spec{CPUMillis: 1000, MemoryMB: 100}) {
		t.Fatal("1500+1000 > 2000 cpu: over-capacity candidate must wait")
	}
	if !a.tryAdmit(engine.Spec{CPUMillis: 500, MemoryMB: 512}) {
		t.Fatal("a fitting candidate must start even while a larger one waits")
	}
	if a.tryAdmit(engine.Spec{CPUMillis: 1, MemoryMB: 1}) {
		t.Fatal("memory exhausted: must refuse")
	}
	a.release(engine.Spec{CPUMillis: 1500, MemoryMB: 512})
	if !a.tryAdmit(engine.Spec{CPUMillis: 1000, MemoryMB: 100}) {
		t.Fatal("released capacity must re-admit")
	}

	// gpu: capacity 0 means NO gpu — a gpu task is never admitted here,
	// unlike cpu/mem where 0 means unconstrained
	free := &admitter{cap: engine.Spec{}}
	if !free.tryAdmit(engine.Spec{CPUMillis: 99999, MemoryMB: 99999}) {
		t.Fatal("zero cpu/mem capacity means unconstrained")
	}
	if free.tryAdmit(engine.Spec{GPU: 1}) {
		t.Fatal("zero gpu capacity means no gpu, not unconstrained")
	}
}

// TestFanoutSpecAdmissionLive is the done-condition proof: with capacity
// cpu=1000, task A(800) starts, task B(800) WAITS (over capacity), task
// C(200) STARTS beside A (a fitting candidate is not blocked by a waiting
// larger one). When A finishes, B starts. All three complete through the
// real engine transitions.
func TestFanoutSpecAdmissionLive(t *testing.T) {
	pool := testPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	idA := assignedTask(t, pool, "stub", engine.Spec{CPUMillis: 800})
	idB := assignedTask(t, pool, "stub", engine.Spec{CPUMillis: 800})
	idC := assignedTask(t, pool, "stub", engine.Spec{CPUMillis: 200})

	var mu sync.Mutex
	running := map[int64]bool{}
	started := map[int64]time.Time{}
	release := map[int64]chan struct{}{idA: make(chan struct{}), idB: make(chan struct{}), idC: make(chan struct{})}

	stub := func(ctx context.Context, pool *pgxpool.Pool, store *cas.Store, cfg Config) error {
		if err := engine.StartTask(ctx, pool, cfg.TaskID, cfg.Owner, cfg.Lease); err != nil {
			return nil // lost: clean exit, the one-shot posture
		}
		mu.Lock()
		running[cfg.TaskID] = true
		started[cfg.TaskID] = time.Now()
		ch := release[cfg.TaskID]
		mu.Unlock()
		<-ch
		mu.Lock()
		running[cfg.TaskID] = false
		mu.Unlock()
		return engine.CompleteTask(ctx, pool, cfg.TaskID, cfg.Owner, map[string]string{"ok": "1"}, nil)
	}

	base := Config{Owner: "fan-test", Lease: time.Minute}
	fan := Fanout{
		Capacity:    engine.Spec{CPUMillis: 1000},
		Default:     engine.Spec{CPUMillis: 1000},
		MaxSlots:    4,
		Poll:        25 * time.Millisecond,
		Implemented: []string{"stub"},
		run:         stub,
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = RunFanout(ctx, pool, nil, base, fan) }()

	waitFor := func(desc string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			ok := cond()
			mu.Unlock()
			if ok {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for: %s", desc)
	}

	// A (800) and C (200) run concurrently; B (800) waits
	waitFor("A and C running", func() bool { return running[idA] && running[idC] })
	time.Sleep(150 * time.Millisecond) // several polls: B must still not have started
	mu.Lock()
	if running[idB] || !started[idB].IsZero() {
		mu.Unlock()
		t.Fatal("B (800) started while A (800) held the capacity — admission arithmetic failed")
	}
	mu.Unlock()

	// A finishes → B admitted
	close(release[idA])
	waitFor("B running after A released", func() bool { return running[idB] })
	close(release[idB])
	close(release[idC])
	waitFor("all stopped", func() bool { return !running[idA] && !running[idB] && !running[idC] })

	// all three complete through the real protocol
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		if err := pool.QueryRow(context.Background(),
			`select count(*) from task where state = 'FINISHED'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 3 {
			cancel()
			<-done
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("not all tasks reached FINISHED")
}

// TestFanoutOverProvisionSafety: TWO resident workers polling the same
// queue, one task — exactly one execution body runs; the loser's slot
// exits cleanly on ErrTaskLost. This is the ADR-011 over-provision
// invariant, unchanged under fan-out.
func TestFanoutOverProvisionSafety(t *testing.T) {
	pool := testPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	id := assignedTask(t, pool, "stub", engine.Spec{CPUMillis: 100})

	var wins, attempts atomic.Int64
	stub := func(ctx context.Context, pool *pgxpool.Pool, store *cas.Store, cfg Config) error {
		attempts.Add(1)
		if err := engine.StartTask(ctx, pool, cfg.TaskID, cfg.Owner, cfg.Lease); err != nil {
			return nil // ErrTaskLost: clean silent exit, no side effects
		}
		wins.Add(1)
		time.Sleep(50 * time.Millisecond) // hold RUNNING so the twin's poll sees it
		return engine.CompleteTask(ctx, pool, cfg.TaskID, cfg.Owner, map[string]string{"ok": "1"}, nil)
	}

	fan := Fanout{
		Capacity:    engine.Spec{},
		Default:     engine.Spec{CPUMillis: 100},
		MaxSlots:    2,
		Poll:        10 * time.Millisecond,
		Implemented: []string{"stub"},
		run:         stub,
	}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			base := Config{Owner: fmt.Sprintf("twin-%d", i), Lease: time.Minute}
			_ = RunFanout(ctx, pool, nil, base, fan)
		}(i)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var state string
		if err := pool.QueryRow(context.Background(),
			`select state from task where id = $1`, id).Scan(&state); err != nil {
			t.Fatal(err)
		}
		if state == "FINISHED" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	wg.Wait()

	if w := wins.Load(); w != 1 {
		t.Fatalf("exactly one worker must win ASSIGNED→RUNNING, got %d wins (%d attempts)", w, attempts.Load())
	}
	var state string
	if err := pool.QueryRow(context.Background(),
		`select state from task where id = $1`, id).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "FINISHED" {
		t.Fatalf("task should be FINISHED, is %s", state)
	}
}

// TestCommandScopes: the exec wrapper. Caps off (default) = the plain
// pinned invocation; caps on = the same structured argv under
// `systemd-run --user --scope` with CPUQuota/MemoryMax. Never a shell.
func TestCommandScopes(t *testing.T) {
	ctx := context.Background()

	plain := Config{}.Command(ctx, "/opt/tools/ffmpeg", "-i", "in.mp4", "out.mp4")
	if plain.Path != "/opt/tools/ffmpeg" || len(plain.Args) != 4 {
		t.Fatalf("caps off must exec the tool directly: %v", plain.Args)
	}

	capped := Config{CapScopes: true, TaskSpec: engine.Spec{CPUMillis: 1500, MemoryMB: 512}}.
		Command(ctx, "/opt/tools/ffmpeg", "-i", "in.mp4", "out.mp4")
	got := strings.Join(capped.Args, " ")
	want := "systemd-run --user --scope --collect --quiet -p CPUQuota=150% -p MemoryMax=512M -- /opt/tools/ffmpeg -i in.mp4 out.mp4"
	if got != want {
		t.Fatalf("scope argv:\n got  %q\n want %q", got, want)
	}

	// caps flag on but no stated dimensions: nothing to enforce, run plain
	noSpec := Config{CapScopes: true}.Command(ctx, "/opt/tools/ffprobe", "-v", "error")
	if noSpec.Path != "/opt/tools/ffprobe" {
		t.Fatalf("caps with an empty spec must exec the tool directly: %v", noSpec.Args)
	}
}

// TestSystemdScopeLive actually runs a capped command under the user
// manager — skipped where no systemd user session exists (containers, CI).
func TestSystemdScopeLive(t *testing.T) {
	if _, err := exec.LookPath("systemd-run"); err != nil {
		t.Skip("systemd-run not on PATH")
	}
	if err := exec.Command("systemd-run", "--user", "--scope", "--quiet", "--", "/bin/true").Run(); err != nil {
		t.Skipf("no usable systemd user manager: %v", err)
	}
	cfg := Config{CapScopes: true, TaskSpec: engine.Spec{CPUMillis: 500, MemoryMB: 64}}
	cmd := cfg.Command(context.Background(), "/bin/true")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("capped invocation failed: %v\n%s", err, out)
	}
}
