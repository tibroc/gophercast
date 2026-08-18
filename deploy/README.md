# ocng single-node evaluation stack

One command, one URL:

```bash
# one-time: stage the admin-interface bundle (a build artifact of the
# Opencast admin UI; copied here so :z relabelling stays inside deploy/)
mkdir -p admin-ui-bundle && cp -r /path/to/opencast/modules/admin/build/. admin-ui-bundle/
mkdir -p data/postgres data/minio

podman compose -f compose.yaml up -d --build     # dev target (rootless, SELinux enforcing)
# or: docker compose -f compose.yaml up -d --build
```

Then open **http://localhost:8800/** — the real admin-interface bundle
rendering data served by `ocng-core` through the Caddy edge.

## Paella bundle (the player; adopter-staged, NEVER redistributed — D-048)

The watch page (`/play/{event-id}`, served by ocng-core) embeds the
[paella-opencast](https://github.com/polimediaupv/paella-opencast) web
component via the DATAPASS pattern: the page fetches
`/api/events/{id}?withpublications=true` itself (same-origin, the session
cookie flows) and hands the JSON to `<paella-opencast-player>`.

**License notice (D-048, required reading before staging):** the
paella-opencast repository and its npm packages declare **no license**
(checked 2026-08-18, v2.0.5 — no LICENSE file, `license` field absent/None;
the underlying `@asicupv/paella-core` is ECL-2.0). Undeclared means
all-rights-reserved by default. ocng therefore never ships or tracks these
files: **you** obtain them from upstream, under upstream's terms, and stage
them here. If your legal review needs a declared license, ask upstream for
one before deploying the player.

Staging (pinned version: **@asicupv/paella-opencast-component 2.0.5** —
newer 2.x may work but is unexercised; re-run the player checks after any
bump):

```bash
mkdir -p paella-bundle
npm pack @asicupv/paella-opencast-component@2.0.5
tar xzf asicupv-paella-opencast-component-2.0.5.tgz
cp package/dist/paella-opencast-component.es.js \
   package/dist/paella-opencast-component.css paella-bundle/
rm -r package asicupv-paella-opencast-component-2.0.5.tgz
# a paella config (plugins/layout); the upstream component example's config
# is a working start:
curl -sL -o paella-bundle/config.json https://raw.githubusercontent.com/polimediaupv/paella-opencast/main/examples/opencast-component-example/src/paella_config.json
```

The bundle is bind-mounted at `/srv/paella` on the admin-interface static
server and reached as `/paella/*` through the edge. Without it, `/play/...`
renders a plain-text pointer to this section instead of a player.

Proven on: podman 5.8.4 rootless (uid 1000), SELinux **Enforcing**,
Fedora 44 host. The compose file uses only compose-spec keys; docker
compose is compatible by construction but was not runnable on the dev box
(docker not installed) — treat that half as unexercised.

Note: `podman compose up --build` rebuilds images but does not always
recreate running containers from them; after changing code, `down` first.

## Components

| service | what | notes |
|---|---|---|
| `edge` | Caddy reverse proxy | the routes are the contract (Ingress-expressible); strips inbound identity-assumption headers; injects the DEV admin session stand-in when no `X-Roles` arrives |
| `admin-interface` | Caddy static server + the real bundle | bundle bind-mounted in dev; own image built by the frontend repo is the shipping path (ADR-012) |
| `ocng-core`, `ocng-core-b` | the assembled core binary, 2 replicas | migrations race at every `up` and serialise on the shared advisory lock (ADR-009); applied steps are ledger-skipped on later boots |
| `ocng-worker` | claim-mode capability worker | polls for ASSIGNED worker-class tasks; the engine's single-winner transition makes scaling safe; pinned tools bind-mounted read-only (hash-asserted at startup) |
| `keycloak` | dev OIDC issuer | realm imported from `keycloak-realm.json`; the ONE operated issuer (ADR-002) — production points `OCNG_OIDC_ISSUER` at its own IdP |
| `postgres`, `minio` | estate stand-ins | MinIO is a dev S3 stand-in — the storage contract is the S3 API, never MinIO behaviour |

## Auth in this stack

OIDC bearer auth (against the compose Keycloak) and LTI 1.3 are the real,
built identity paths; both are wired here. In addition the dev compose
opts in to the dev seam (`OCNG_DEV_AUTH=1`): `X-Roles` header principals,
the edge admin stand-in for browser sessions, and basic-auth `/ingest`.
The binary ships with the seam **default OFF** — it exists only where a
deployment sets the variable, and this stack sets it. The compose LTI
session secret is dev-grade; production sets its own (see CONFIG.md).

## Workflow definitions

`deploy/definitions/` is the YAML authoring surface, bind-mounted into
core (`OCNG_DEFINITIONS_DIR`). Edit files while the stack runs — core
polls the mount and upserts changes into the database with a content
hash; execution reads the DB (ADR-009: bind mount authors, database
executes). A file that stops parsing keeps its last-good version serving.
See CONFIG.md "Workflow definitions".

## Verifying the composed stack

```bash
curl -s http://localhost:8800/ocng/version        # core, through the edge
curl -s http://localhost:8800/admin-ng/event/events.json | head -c 200
```

Then open the UI and confirm events/series render. (The full e2e
edge-composition harness lives outside this tree; loopback ports
15433/19001 exist for it.)

## Operational notes

- Migration into this stack: run `ocng-migrate` as a one-shot container
  against the same database and bucket (see CONFIG.md and the top-level
  README's migration section).
- Full teardown: `podman compose -f compose.yaml down -v && podman unshare rm -rf data`.
