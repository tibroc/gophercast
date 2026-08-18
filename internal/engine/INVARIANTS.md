# Engine invariants — what increment 2 is allowed to rely on

Written 2026-08-14, at the start of increment 2, before any increment-2 code.
These are the six guarantees increment 1 **proved** — each enforced in
`engine.go`/`schema.sql` and demonstrated by a named test in `engine_test.go`
against real Postgres (the engine is SQL; nothing here is mock-verified).
Increment 2 builds on all six. If a change would weaken one, that is an
engine change requiring its test to fail first, not a side effect to absorb.

Line numbers below were located by `grep -n` of the exact token, not by
estimate, on the tree at commit `3fd4161`.

---

## I1 — Assignment is committed before provisioning

A task row is inserted and **committed** (`assign`, `engine.go:239`; the
insert is its own statement, completed before any `Provision` call) and only
then is compute created with the task id in its spec. A worker can never
start and find its task absent. Re-provisioning after reap has the same
ordering (`engine.go:171-204`).

Proof: `TestAssignCommitsBeforeProvision` (`engine_test.go:73`) — the
provisioner reads the task back by id at provision time, and a second
`Step()` does not double-assign.

## I2 — ASSIGNED→RUNNING has exactly one winner

`StartTask` (`engine.go:313`) is a single-row conditional update
(`where id = $1 and state = 'ASSIGNED'`, `engine.go:317`); zero rows
affected returns `ErrTaskLost` (`engine.go:322`). Of N over-provisioned
workers exactly one wins; losers must exit silently with no side effects.
Over-provisioning is therefore safe by construction.

Proof: `TestOverProvisionExactlyOneWins` (`engine_test.go:104`) — 8 racers,
1 win, 7 `ErrTaskLost`.

## I3 — Completion is transactional, in both directions

`CompleteTask` (`engine.go:350`) runs the caller's `mutate` (element rows,
catalogs) and the RUNNING→FINISHED terminal write **in one transaction**.
If the terminal write loses — reaped, raced, wrong owner, already terminal —
the whole transaction rolls back (`engine.go:373-374`): no orphan rows, no
stale data, `ErrTaskLost`. If it wins, the data mutation and the terminal
state become visible atomically. This is the engine-side half of the
idempotency answer: CAS dedups bytes, transactional completion dedups rows
(ADR-004 idempotency section).

Proof: `TestCompletionTransactional` (`engine_test.go:145`) — a probe row
written by `mutate` vanishes with a lost completion and survives a won one.

## I4 — Terminal states are immutable at the database

The `task_terminal_guard` trigger (`schema.sql:43-59`) raises on **any**
UPDATE or DELETE of a row whose old state is FINISHED or FAILED. This is
structural: no client code path — present or future, including raw SQL —
can overwrite a completed task. A zombie owner's late overwrite of a
completed task is impossible here by schema, not by discipline.

Proof: `TestU27TerminalImmutable` (`engine_test.go:192`) — stale
re-completion, late FAILED, and a raw `update task set state='RUNNING'`
all rejected.

## I5 — Lease expiry is the recovery mechanism, with an attempt cap

All lease arithmetic is Postgres `now()`; node clocks never enter it
(S3's clock-skew exclusion). An expired ASSIGNED/RUNNING task below
`MaxAttempts` returns to ASSIGNED with `attempt + 1` and is re-provisioned
(`engine.go:171-181`); at the cap it becomes FAILED (`engine.go:190-194`)
and the workflow fails with it via `advance` (`engine.go:226-233`). A
reaped owner's subsequent renew/complete/fail all get `ErrTaskLost`.

Proof: `TestLeaseReapAndExhaustion` (`engine_test.go:230`).

## I6 — Migration is serialised by one advisory lock

Every ocng schema migration runs inside `pg_advisory_xact_lock` on the
single key `0x0c9e_0001` (`migrateLocked`, `engine.go:95-108`; shared with
other packages' schemas via `MigrateLocked`, `engine.go:112`). Two
processes migrating concurrently — a real ADR-009 scenario with 1–2 core
replicas — serialise instead of deadlocking on trigger DDL. This was found
by *running* the suite in parallel (commit `3fd4161`), not by review.

Proof: no dedicated test; the enforcement is the parallel `go test ./...`
run itself, which deadlocked before the lock and passes after. Any new
schema **must** go through `MigrateLocked` — a package that ships its own
`Migrate` with a different key or none reintroduces the deadlock.

---

## Boundaries — updated at increment 2

Two of the increment-1 boundaries are now CLOSED (2026-08-14, red-first):

- ~~Single orchestrator~~ → **I7: one task per (workflow_id, op_index),
  enforced by the database.** The hole was real and demonstrated — two
  transactions running `assignSQL` both passed the not-exists read and
  committed two rows (`TestAssignInsertRaceStructural`, red before the
  fix). Guard: `task_wf_op_uidx` unique index + on-conflict-do-nothing.
  Concurrent orchestrators also exercised end-to-end in
  `TestConcurrentOrchestratorsAssignOnce`.
- ~~Multi-operation sequencing~~ → **proven**: strict definition order
  (`TestMultiOpSequencing`), resume-after-crash by a fresh orchestrator
  mid-chain (`TestResumeMidWorkflowAfterCrash`), definition pinned by
  value at create (`TestDefinitionPinnedAtCreate`).

New in increment 2, relied on going forward:

- **I8: one task lifecycle for both execution classes.**
  `ExecuteTask` (`inline.go`) is the single implementation of
  start-or-exit-silently / renew at lease÷3 / transactional complete-fail;
  the worker binary and the `InlineRunner` both call it. I2–I5 therefore
  hold for inline ops by construction. Guarded by the three deadlock tests
  (`inline_test.go`: pool starvation at max_conns=2, slow op across 6
  lease terms exactly-once, `Migrate` DDL concurrent with inline
  completions), all written red before the executor existed.
- **Execution class is a property of the operation** (`class.go`, the
  98-op ADR-011 table, split verified by `TestClassTableCounts`).
  Unknown/unclear/unregistered operations fail loudly through the standard
  transition — nothing ever strands ASSIGNED waiting for an executor that
  cannot exist.

Still open — do not lean on these:

- **No per-operation retry.** Task FAILED → workflow FAILED unconditionally
  (retry-strategy NONE, matching the legacy system's shipped default).
  The reap/attempt cycle in I5 is *lease* recovery, not operation retry.
- **`FailTask` carries no mutation** (`FailTask`, engine.go) — failure is
  transactional only with itself. Fine while failures write no data; an
  operation whose failure must record partial state has no supported path.
- **Terminal workflows are not immutable.** The terminal-write trigger guards `task`
  only; the `workflow` row has no such guard.
