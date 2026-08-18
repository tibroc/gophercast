-- Migration-owned tables (increment 6). These never carry
-- operable state — they are the run ledger, the D-010 fidelity report, and
-- the repoint record ("links stay the same": the edge serves redirects from
-- migration_url_map).

create table if not exists migration_run (
    id          bigserial primary key,
    org         text not null,          -- the source organisation this run migrated (dropped from all target rows per ADR-010, reported in migration_report)
    source      text not null,          -- source identity label (fixture dir / DSN)
    started_at  timestamptz not null default now(),
    finished_at timestamptz,
    n_events    int not null default 0,
    n_series    int not null default 0,
    n_versions  int not null default 0,
    n_objects   int not null default 0, -- CAS puts performed (informational)
    holds       int not null default 0, -- per-record HOLDs (each has a report line)
    outcome     text not null default 'running'
);

create table if not exists migration_report (
    id         bigserial primary key,
    run_id     bigint not null references migration_run(id),
    class      text not null,           -- organization-dropped | acl-absent | hold | managed-acl-template | ...
    record_id  text,
    detail     text,
    created_at timestamptz not null default now()
);
create index if not exists migration_report_class_idx on migration_report (class);
create index if not exists migration_report_run_idx   on migration_report (run_id);

-- The repoint record: every source element URL (any version, archival urn
-- and /static distribution shapes alike) mapped to its content hash. This is
-- what keeps every migrated byte referenced, and what the edge serves 301s
-- from after cutover.
create table if not exists migration_url_map (
    old_url         text primary key,
    mediapackage_id text not null,
    version         int,
    element_id      text,
    kind            text,
    flavor          text,
    sha256          text not null,
    run_id          bigint not null references migration_run(id)
);
create index if not exists migration_url_map_sha_idx on migration_url_map (sha256);
