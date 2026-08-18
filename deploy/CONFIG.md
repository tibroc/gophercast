# ocng operator configuration

Configuration is **environment variables in your deployment definitions** —
quadlet `Environment=`/`Secret=` lines, compose `environment:` blocks, K8s
manifests (ADR-009). There is no config file read by the binaries. The one
file-based surface is **workflow definitions** (YAML on a bind mount — see
below), because operators edit those at runtime.

Both binaries validate the whole surface in **one pass before anything
connects**: every missing and invalid variable is reported in a single exit
message, and a parse error (a bad integer or duration) is **fatal, never a
silent default**. After validation, core prints a **boot report** naming
every dev-grade posture in effect; a production-shaped configuration prints
`boot report: no dev-grade postures in effect` instead. If your boot report
is not empty, read this table.

## The pilot-gate table — read this before any real deployment

| Item | Must | Why |
|---|---|---|
| `OCNG_SERVE_DB_URL` | **SET** | Without it, T2's structural least-privilege boundary is **disabled**: serve runs on the general pool instead of the `ocng_serve` role (SELECT on exactly the serve-read set), so an out-of-set serve query succeeds instead of failing at the database. This is a disabled security boundary, not a tuning default — the boot report names it in its own block. |
| `OCNG_SERVE_DB_PASSWORD` | **SET (own value)** | The dev default (`ocng_serve`) is public knowledge — it is in this repository. |
| `OCNG_DB_URL`, `OCNG_CAS_*` | **SET (real values)** | The compose file's values are dev values, also public. Inject secrets as podman secrets (`Secret=` lines — see the quadlets), never `Environment=` plaintext. |
| An identity path: `OCNG_OIDC_ISSUER` and/or `OCNG_LTI_PLATFORMS_FILE` | **SET** | With neither, the system boots and every authenticated surface answers 403 — nobody can log in. The boot report says so. |
| `OCNG_LTI_SESSION_SECRET` (when LTI is on) | **SET (≥32 bytes)** | Shared by **all** replicas — login, launch and delivery may hit different processes. Never generated: a per-process secret would mint sessions no other replica accepts. |
| `OCNG_DEV_AUTH` | **NOT SET** | The dev auth seam (X-Roles principals, Basic ingest credentials). The binary defaults it off; production must never set it (T1, ADR-012). |
| `OCNG_DEFINITIONS_DIR` | **SET** | Without it (and without rows already in the database) no workflow can start. |
| `OCNG_GC_GRACE` / `OCNG_GC_INTERVAL` | **NOT SET — gated** | The T4 CAS collector. **Do not set.** Enablement requires the mid-migration-transient fixture (a migration paused between CAS write and reference insert, proving grace covers the longest put-then-reference gap) — **it does not exist yet**. Grace must also be ≥ the deployment's restore horizon (ADR-006). These are listed here so nobody mistakes them for tunables. |

## Process supervision is part of the deployment contract

From ADR-009 (Consequences), verbatim:

> Crash-only is an acceptable design; an *undeclared* dependency on someone
> else's restart policy is not. **All three supervision styles must restart
> the engine, and the operator documentation must say so.**

The engine exits on loss of database connectivity **by design**. It resumes
without operator intervention *only because* something restarts it: the
quadlets carry `Restart=always`, Kubernetes restarts pods, and the compose
file sets `restart: on-failure`. If you run the binaries any other way, you
own the restart policy.

## Variable reference — ocng-core

| Var | Required | Default | Notes |
|---|---|---|---|
| `OCNG_DB_URL` | yes | — | Postgres URL, the general pool |
| `OCNG_CAS_ENDPOINT` | yes | — | S3 endpoint host:port (the contract is the S3 API; MinIO is a dev stand-in) |
| `OCNG_CAS_KEY` / `OCNG_CAS_SECRET` | yes | — | S3 credentials |
| `OCNG_CAS_BUCKET` | yes | — | CAS bucket |
| `OCNG_LISTEN` | no | `:8085` | listen address |
| `OCNG_SERVE_DB_URL` | **pilot gate** | unset | serve's dedicated pool as the `ocng_serve` role; unset = enforcement OFF (boots, loudly reported — dev on-ramp only) |
| `OCNG_SERVE_DB_PASSWORD` | **pilot gate** | `ocng_serve` | password EnsureRole gives `ocng_serve` on first creation |
| `OCNG_DEFINITIONS_DIR` | see gate table | unset | the workflow-definition authoring mount (below). Replaces the retired `OCNG_DEFINITIONS_FILE` — setting the old var is a fatal error naming the new one |
| `OCNG_DEV_AUTH` | **must not set** | off | dev auth seam |
| `OCNG_INGEST_USER` / `OCNG_INGEST_PASS` | no | `admin`/`opencast` | dev-seam ingest credentials; inert unless `OCNG_DEV_AUTH=1` |
| `OCNG_OIDC_ISSUER` | identity gate | unset | the ONE operated OIDC issuer (ADR-002) |
| `OCNG_OIDC_CLIENT_ID` | with issuer | — | required whenever the issuer is set |
| `OCNG_OIDC_ROLES_CLAIM` | no | `roles` | claim path for the role array; dotted paths descend |
| `OCNG_LTI_PLATFORMS_FILE` | identity gate | unset | JSON array of LTI 1.3 platform registrations; without it `/lti` is not mounted |
| `OCNG_LTI_SESSION_SECRET` | with platforms | — | ≥32 bytes, shared across replicas |
| `OCNG_GC_GRACE` / `OCNG_GC_INTERVAL` | **must not set** | off | the T4 gate (table above). Both-or-nothing; durations (`90s`, `24h`); a bad value is fatal |

## Variable reference — ocng-worker

| Var | Required | Default | Notes |
|---|---|---|---|
| `OCNG_DB_URL`, `OCNG_CAS_*` | yes | — | as core |
| `OCNG_TOOLS_DIR` | yes | — | the pinned toolchain; hash-asserted at startup, refuses to run on drift |
| `OCNG_SCRATCH` | no | system temp | working space |
| `OCNG_TASK_ID` | no | unset | set = one-shot mode for exactly that task (the K8s Job shape); unset = resident claim mode |
| `OCNG_SLOTS` | no | 1 | concurrent task slots in claim mode |
| `OCNG_CAPACITY_CPU_MILLIS` | no | 0 = unconstrained | admission budget: sum of running task specs must fit. Set to what the VM actually has |
| `OCNG_CAPACITY_MEMORY_MB` | no | 0 = unconstrained | as above. **A typo here is fatal at boot** — pre-T5 it silently removed the admission bound |
| `OCNG_CAPACITY_GPU` | no | 0 = no GPU | GPU slots; 0 means GPU tasks are never admitted here |
| `OCNG_DEFAULT_CPU_MILLIS` | no | 1000 | cost assumed for tasks without a spec |
| `OCNG_DEFAULT_MEMORY_MB` | no | 0 | as above |
| `OCNG_SYSTEMD_SCOPES` | no | off | `1` = per-task cgroup hard caps (bare-process deployments with a reachable systemd user manager only) |

`ocng-migrate` (one-shot): `OCNG_DB_URL`, `OCNG_CAS_*`, flags `-source`,
`-org`.

## Workflow definitions: authoring how-to

The mechanism (ADR-009): **bind mount authors, database executes.**

1. Put one YAML file per definition in the mounted directory
   (`OCNG_DEFINITIONS_DIR`; `deploy/definitions/` in the compose shape):

   ```yaml
   id: my-workflow
   operations:
     - operation: encode
       config:
         source-flavor: "*/source"
         target-flavor: "*/preview"
         encoding-profile: fast.http
       spec:            # optional per-op resource spec
         cpu_millis: 2000
         memory_mb: 1024
   ```

2. Core polls the mount (every 2 s) and loads changed files into the
   database with a **content hash** — edit with an editor, manage with
   Ansible, no restart needed. Every replica logs
   `definition loaded … hash=…`; two replicas disagreeing on a definition is
   a **query** (`select id, hash from workflow_definition`), not an
   intermittent behaviour change.
3. The **database** is what executes. All replicas run what was last loaded,
   whichever mount it came from; a replica without the mount still executes
   what the database holds. Running workflows are unaffected by edits — the
   definition is pinned into the workflow row at start.
4. Failure posture: at **boot**, an unreadable directory or a file that does
   not parse is fatal (fix it before you have traffic). At **runtime**, a
   file that stops parsing keeps its **last-good** version serving and logs
   `ERROR … file rejected` — a typo cannot take the core down.
5. Removing a file does **not** delete the definition from the database.
6. **Stated limit**: definitions containing an `include` operation are
   rejected at load time. Orchestrator-side include expansion (ADR-009) is
   deferred until a definition actually needs it — inline the operations.

Authoring errors are strict on purpose: unknown fields (typos), a missing
`id`, an empty operation list and a nameless operation are all rejected with
the file named.

## Fixed operational constants (deliberately not configurable)

| Constant | Value |
|---|---|
| Engine task lease | 60 s |
| Engine max attempts per task | 3 |
| Orchestrator tick | 500 ms |
| Worker lease renewal | 30 s |
| Definitions poll interval | 2 s |
| Definitions registry read cache | 2 s |

No increment has needed these configurable; they stay hard-coded until one
does (T5 mandate: consolidation, not new configurability).
