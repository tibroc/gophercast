# The serve-read set

The tables plane 1 — delivering the video bytes (`/elements/`,
`/publications/`, and the future `migration_url_map` 301 surface) — is
allowed to read. Derived and audited alongside the zero-downtime migration design
§1; boundary and invariant ratified 2026-08-17. `serveset.go` is the
machine-read form; this file is the why. **Changing the set is a reviewed
act** — it changes what the zero-downtime invariant protects.

| Table | Why it is in |
|---|---|
| `mp_element` | The element row read per delivery (`mediapackage.GetElement`): sha256 (the CAS key), size, mimetype, created_at (Last-Modified, D-041). |
| `publication` | The publication listing joins it, and it carries the publish-time ACL pin (`acl_read`, `acl_state`) that delivery authorization will evaluate (delivery filters on the pin, never the archive ACL). The pin being in-set already means building serve-auth later does not grow the set. |
| `publication_element` | Publication → element join, and the reverse join a per-element authorization check needs. |
| `migration_url_map` | "Links stay the same": the post-cutover 301 surface (designed, currently unwired — finding F3). An old LMS URL resolving to a video is plane-1 traffic. |

CAS (the S3 bucket) is also plane-1 but is content-addressed and immutable
(ADR-008) — outside the schema-migration problem by construction.

**Explicitly out:** `mediapackage`, `mp_metadata`, `series`,
`mp_element_tag`, `mp_snapshot` (archive/metadata surfaces);
`search_event`, `search_series` (the engage/admin *listing* surface —
**plane 3**, ratified 2026-08-17: a search blip during an update is a
control-plane blip. Escape hatch, revisitable: if a pilot says
browsing-is-presentation, `search_event` joins the set and its evolution
becomes constrained); `acl_policy`/`acl_entry` (the archive ACL);
`workflow`/`task` (engine); `lti_flow`; `migration_run`/`migration_report`.

## The three-way invariant (§5.3, ratified 2026-08-17)

- **rewrite-class ACCESS EXCLUSIVE on a set table → FORBIDDEN** (in-place
  `ALTER TYPE`, `ADD COLUMN` with volatile default, `SET NOT NULL` without a
  valid-constraint path, `CLUSTER`, `VACUUM FULL`, `TRUNCATE`, `DROP`/rename
  of a live column).
- **metadata-class AEL on a set table → permitted ONLY as a guarded step**
  (`SET lock_timeout` + bounded retry): even a brief AEL queues behind a
  long reader and stalls every serve SELECT behind *it*.
- **Anything off the set → unconstrained on duration** (slow-but-safe is
  explicitly allowed).

Enforced by `internal/schemastep` (`Check`); the fix for a rejected
migration is in `docs/migration-discipline.md`.

## Enforcement layers

1. **Structural:** the `ocng_serve` role (`EnsureRole`) has SELECT on
   exactly this set; `cmd/ocng-core` connects the serve handler's pool as it
   (`OCNG_SERVE_DB_URL`). An out-of-set serve query fails in every
   environment.
2. **Static:** `internal/serve/readset_test.go` walks the serve package's
   SQL and asserts referenced tables ⊆ set.
3. **Migration-time:** `schemastep.Check` classifies every step against the
   set before the runner will execute a plan.
