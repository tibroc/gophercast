# ocng single-node evaluation stack (increment 5.5 — assembly)

One command, one URL:

```bash
# one-time: stage the admin-interface bundle (a build artifact of the
# legacy Opencast admin UI; copied here so :z relabelling stays inside
# deploy/)
mkdir -p admin-ui-bundle && cp -r /path/to/opencast/modules/admin/build/. admin-ui-bundle/
mkdir -p data/postgres data/minio

podman compose -f compose.yaml up -d --build     # dev target (rootless, SELinux enforcing)
# or: docker compose -f compose.yaml up -d --build
```

Then open **http://localhost:8800/** — the real admin-interface bundle
rendering data served by `ocng-core` through the Caddy edge.

Proven on: podman 5.8.4 rootless (uid 1000), SELinux **Enforcing**,
Fedora 44 host. The compose file uses only compose-spec keys; docker
compose is compatible by construction but was not runnable on the dev box
(docker not installed) — treat that half as unexercised.

## Components

| service | what | notes |
|---|---|---|
| `edge` | Caddy reverse proxy | the routes are the contract (Ingress-expressible); strips inbound identity-assumption headers; injects the DEV admin session stand-in when no `X-Roles` arrives |
| `admin-interface` | Caddy static server + the real bundle | bundle bind-mounted in dev; own image built by the frontend repo is the shipping path (ADR-012) |
| `ocng-core`, `ocng-core-b` | the assembled core binary, 2 replicas | migrations race at every `up` and serialise on the engine's advisory lock (ADR-009) |
| `ocng-worker` | claim-mode capability worker | polls for ASSIGNED worker-class tasks; the engine's single-winner transition makes scaling safe; pinned tools bind-mounted read-only (hash-asserted at startup) |
| `postgres`, `minio` | estate stand-ins | MinIO is a dev S3 stand-in — the storage contract is the S3 API, never MinIO behaviour |

## Dev seams (never production; each is a named successor increment)

- **Auth**: `X-Roles` header (e2e principal seam) + edge admin stand-in +
  ingest basic-auth. Replaced wholesale by the OIDC increment.
- ~~**Workflow definitions**: `definitions.json` (env-pointed JSON).~~
  **Closed by T5**: `deploy/definitions/` is the ADR-009 YAML bind-mount +
  DB-hash authoring surface (`OCNG_DEFINITIONS_DIR`); see CONFIG.md.
- **Provisioning**: the claim-loop worker container is the dev stub for the
  ADR-011 provisioning port (podman transient units / K8s Jobs).
- **Loopback ports 15433/19001**: for the e2e edge-composition harness only.

## Verifying the composed stack

```bash
OCNG_EDGE_URL=http://localhost:8800 \
OCNG_COMPOSE_PG=postgres://ocng:ocng@127.0.0.1:15433/ocng \
OCNG_COMPOSE_MINIO=127.0.0.1:19001 \
go test ./e2e/ -run TestAssembly_EdgeComposition -count=1
```

Loads the increment-4 corpus (idempotent), then runs the increment-5 tier-1
contract, the serve conformance checks (all range exchanges through the real proxy) and
the identity-header non-elevation check through the composed edge+core pair.

## Known findings

- **A1**: `/admin-ng/event/events.json` + `/admin-ng/series/series.json` are
  implemented divergently by increments 4 and 5; `adminapi` owns them here,
  so filtered/sorted admin-ng queries lose filter/sort semantics.
- **A3**: events deposited via `/ingest` do not appear in any list surface
  (missing search-projection hook); `search.Rebuild` derives them, proving
  the data is complete.
- Full teardown: `podman compose -f compose.yaml down -v && podman unshare rm -rf data`.
