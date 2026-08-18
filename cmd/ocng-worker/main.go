// ocng-worker: the capability worker, in one of two lifecycles (ADR-011
// as amended by A7/D-045 — environment-matched, one task/lease protocol).
//
// One-shot: created for exactly one assigned task, identified by
// OCNG_TASK_ID — the only work-identity it is ever given; everything else
// is read from the database (the startup contract). Renews a Postgres
// lease while working; download → process → upload (ADR-008); completes
// its task in the same transaction as its mediapackage mutation; exits.
// This is the shape a future K8s Job adapter provisions per task.
//
// CLAIM MODE — the VM resident lease-worker (T3): with OCNG_TASK_ID unset,
// the binary runs resident. It discovers ASSIGNED worker-class tasks (a
// poll — a query, not a protocol; no registration, no heartbeat, no pool
// state) and runs up to OCNG_SLOTS of them concurrently via subprocess
// fan-out, admission by spec arithmetic over the task resource-spec
// columns (worker.RunFanout). Each slot runs the UNCHANGED one-shot path;
// the engine's single-winner ASSIGNED→RUNNING transition resolves races
// between concurrent workers and slots alike, so scaling workers or slots
// is safe by the same invariant the e2e tests prove. This is the ADR-004
// pull posture (D-027 kept claim mode); core holds no provisioning
// credential on VMs (D-045; the amendment-6 broker is dissolved, D-046).
//
// At startup it ASSERTS the pinned toolchain (whisper-cli, model, ffmpeg —
// hashes pinned in internal/worker/pins.go) and refuses to run on drift:
// the byte-level output checks are only meaningful for the pinned
// invocation.
//
// T5: the env surface validates in ONE pass (internal/config) before
// anything connects — all missing/invalid vars in one exit message, and
// integer parse errors are FATAL (the F-1 fix: pre-T5,
// OCNG_CAPACITY_MEMORY_MB=8G silently became 0 = unconstrained, a capacity
// typo silently removing the admission bound).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/cas"
	"ocng/internal/config"
	"ocng/internal/engine"
	"ocng/internal/worker"
)

func run() error {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	var s config.Set
	dbURL := s.Require("OCNG_DB_URL")
	casEndpoint := s.Require("OCNG_CAS_ENDPOINT")
	casKey := s.Require("OCNG_CAS_KEY")
	casSecret := s.Require("OCNG_CAS_SECRET")
	casBucket := s.Require("OCNG_CAS_BUCKET")
	toolsDir := s.Require("OCNG_TOOLS_DIR")
	scratch := s.String("OCNG_SCRATCH", "") // empty = system temp
	taskID, oneShot := s.Int64("OCNG_TASK_ID")
	fan := worker.Fanout{
		Capacity: engine.Spec{
			CPUMillis: s.Int("OCNG_CAPACITY_CPU_MILLIS", 0), // 0 = unconstrained
			MemoryMB:  s.Int("OCNG_CAPACITY_MEMORY_MB", 0),  // 0 = unconstrained
			GPU:       s.Int("OCNG_CAPACITY_GPU", 0),        // 0 = NO gpu here
		},
		Default: engine.Spec{
			CPUMillis: s.Int("OCNG_DEFAULT_CPU_MILLIS", 1000),
			MemoryMB:  s.Int("OCNG_DEFAULT_MEMORY_MB", 0),
		},
		MaxSlots:    s.Int("OCNG_SLOTS", 1),
		CapScopes:   s.String("OCNG_SYSTEMD_SCOPES", "") == "1",
		Implemented: []string{"speechtotext", "encode", "inspect"},
	}
	if err := s.Err(); err != nil {
		return err
	}

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	store, err := cas.New(ctx, casEndpoint, casKey, casSecret, casBucket)
	if err != nil {
		return err
	}

	host, _ := os.Hostname()
	cfg := worker.Config{
		Owner:    fmt.Sprintf("%s-pid%d", host, os.Getpid()),
		ToolsDir: toolsDir,
		Scratch:  scratch,
		Lease:    30 * time.Second,
		Log:      log,
	}

	// One-shot mode: provisioned for exactly one task (ADR-011).
	if oneShot {
		cfg.TaskID = taskID
		return worker.Run(ctx, pool, store, cfg)
	}

	// Claim mode — the VM resident lease-worker (T3, ADR-011 A7). Discovery
	// is advisory; claiming stays the engine's single-winner transition
	// inside worker.Run, so a stale or raced discovery costs one clean
	// ErrTaskLost exit and nothing else. Fan-out adds N concurrent slots
	// with spec-arithmetic admission over the T3 resource-spec columns —
	// the task/lease protocol is untouched. Defaults keep the assembly-era
	// shape: 1 slot, unconstrained cpu/mem, no cgroup caps.
	log.Info("claim mode: resident lease-worker",
		"slots", fan.MaxSlots, "capacity", fan.Capacity, "systemd_scopes", fan.CapScopes)
	return worker.RunFanout(ctx, pool, store, cfg, fan)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ocng-worker:", err)
		os.Exit(1)
	}
}
