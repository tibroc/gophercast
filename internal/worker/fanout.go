// T3 (ADR-011 A7): the VM resident lease-worker's subprocess fan-out.
//
// N concurrent task slots, each a goroutine running the UNCHANGED one-shot
// path (worker.Run → engine.ExecuteTask). Assignment-and-lease is
// IDENTICAL to the one-shot worker: every slot leases its task through the
// engine's single-winner ASSIGNED→RUNNING transition, renews its own
// lease, and exits its slot on completion; a redundant assignment (another
// worker, another slot) finds the task taken, gets ErrTaskLost, and exits
// cleanly — over-provision safety unchanged. No pool, no claim-balancing,
// no registration: discovery is a poll for ASSIGNED tasks (a query, not a
// protocol — the A7 survey's Question A).
//
// Admission is spec arithmetic over the T3 resource-spec columns: a
// candidate starts only if sum(specs of running slots) + candidate fits
// the worker's configured VM capacity. A candidate that does not fit
// simply stays ASSIGNED — it waits for capacity here, or for another
// worker. Dimension semantics:
//
//   - cpu/memory capacity 0 = unconstrained (dev shape);
//   - gpu is ALWAYS constrained: capacity 0 means "no GPU here", so a task
//     stating gpu > 0 is never admitted on a GPU-less worker;
//   - runtime_s is advisory (never admission arithmetic).
//
// Tasks whose spec columns are NULL cost the configured Default spec.
package worker

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/cas"
	"ocng/internal/engine"
)

type Fanout struct {
	Capacity engine.Spec // VM capacity (cpu/mem 0 = unconstrained; gpu literal)
	Default  engine.Spec // assumed cost of a task with NULL spec columns
	MaxSlots int         // hard bound on concurrent slots; default 1
	Poll     time.Duration
	CapScopes   bool     // wrap tool subprocesses in systemd-run --user scopes
	Implemented []string // operations this worker claims

	// run is the per-slot body — worker.Run by default; tests substitute a
	// stub to prove admission/lease behaviour without media tools.
	run func(ctx context.Context, pool *pgxpool.Pool, store *cas.Store, cfg Config) error
}

// admitter is the spec-arithmetic admission ledger.
type admitter struct {
	mu   sync.Mutex
	cap  engine.Spec
	used engine.Spec
}

func fits(used, candidate, capacity int, zeroUnconstrained bool) bool {
	if capacity <= 0 {
		return zeroUnconstrained || candidate <= 0
	}
	return used+candidate <= capacity
}

func (a *admitter) tryAdmit(s engine.Spec) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !fits(a.used.CPUMillis, s.CPUMillis, a.cap.CPUMillis, true) ||
		!fits(a.used.MemoryMB, s.MemoryMB, a.cap.MemoryMB, true) ||
		!fits(a.used.GPU, s.GPU, a.cap.GPU, false) { // gpu: 0 capacity = none
		return false
	}
	a.used.CPUMillis += s.CPUMillis
	a.used.MemoryMB += s.MemoryMB
	a.used.GPU += s.GPU
	return true
}

func (a *admitter) release(s engine.Spec) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.used.CPUMillis -= s.CPUMillis
	a.used.MemoryMB -= s.MemoryMB
	a.used.GPU -= s.GPU
}

// defaulted fills unstated (zero) dimensions from the configured default.
func defaulted(s, def engine.Spec) engine.Spec {
	if s.CPUMillis == 0 {
		s.CPUMillis = def.CPUMillis
	}
	if s.MemoryMB == 0 {
		s.MemoryMB = def.MemoryMB
	}
	if s.GPU == 0 {
		s.GPU = def.GPU
	}
	return s
}

// RunFanout is the resident worker's loop: discover ASSIGNED tasks, admit
// by spec arithmetic, run each admitted task in its own slot through the
// unchanged one-shot path. Returns only when ctx is done.
func RunFanout(ctx context.Context, pool *pgxpool.Pool, store *cas.Store, base Config, f Fanout) error {
	if f.MaxSlots <= 0 {
		f.MaxSlots = 1
	}
	if f.Poll <= 0 {
		f.Poll = time.Second
	}
	runFn := f.run
	if runFn == nil {
		runFn = Run
	}
	log := base.Log

	adm := &admitter{cap: f.Capacity}
	slots := make(chan struct{}, f.MaxSlots)
	var mu sync.Mutex
	inflight := map[int64]bool{}   // tasks a local slot is already on
	cooldown := map[int64]time.Time{} // recently failed pre-claim: don't spin
	var wg sync.WaitGroup

	for ctx.Err() == nil {
		rows, err := pool.Query(ctx, `
			select id,
			       coalesce(spec_cpu_millis, 0), coalesce(spec_memory_mb, 0),
			       coalesce(spec_gpu, 0)
			from task
			where state = 'ASSIGNED' and operation = any($1)
			order by id limit 50`, f.Implemented)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			time.Sleep(f.Poll)
			continue
		}
		type cand struct {
			id   int64
			spec engine.Spec
		}
		var cands []cand
		for rows.Next() {
			var c cand
			if err := rows.Scan(&c.id, &c.spec.CPUMillis, &c.spec.MemoryMB, &c.spec.GPU); err != nil {
				break
			}
			cands = append(cands, c)
		}
		rows.Close()

		admitted := 0
		for _, c := range cands {
			mu.Lock()
			busy := inflight[c.id] || time.Now().Before(cooldown[c.id])
			mu.Unlock()
			if busy {
				continue
			}
			spec := defaulted(c.spec, f.Default)
			if !adm.tryAdmit(spec) {
				continue // over capacity: this candidate waits; a smaller one may still start
			}
			select {
			case slots <- struct{}{}:
			default:
				adm.release(spec)
				continue // all slots taken
			}
			mu.Lock()
			inflight[c.id] = true
			mu.Unlock()
			admitted++

			cfg := base
			cfg.TaskID = c.id
			cfg.Owner = fmt.Sprintf("%s-task%d", base.Owner, c.id)
			cfg.TaskSpec = spec
			cfg.CapScopes = f.CapScopes
			wg.Add(1)
			go func(c cand, spec engine.Spec, cfg Config) {
				defer wg.Done()
				defer func() {
					adm.release(spec)
					<-slots
					mu.Lock()
					delete(inflight, c.id)
					mu.Unlock()
				}()
				if err := runFn(ctx, pool, store, cfg); err != nil {
					if log != nil {
						log.Error("task run failed", "task", c.id, "err", err)
					}
					// a pre-claim failure leaves the task ASSIGNED; back off
					// instead of re-admitting it every poll
					mu.Lock()
					cooldown[c.id] = time.Now().Add(f.Poll)
					mu.Unlock()
				}
			}(c, spec, cfg)
		}
		if admitted == 0 {
			select {
			case <-ctx.Done():
			case <-time.After(f.Poll):
			}
		}
	}
	wg.Wait()
	return ctx.Err()
}
