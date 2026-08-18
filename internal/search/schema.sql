-- Search projection (increment 4, S2 verdict applied).
--
-- One projection table per aggregate, derived ENTIRELY from the
-- authoritative tables (mediapackage, mp_metadata, series, acl_policy,
-- acl_entry, publication) and maintained in the writer's transaction —
-- never a second store, never a materialised view (S2: add those when a
-- measurement demands; none has).
--
-- ACL columns are the S2 strategy-A denormalisation: role ARRAYS on the row,
-- GIN-indexed, overlap predicates (measured: worst cell 58 ms p95 at 100k vs
-- the join table's 373 ms; the join table collapses at 1M). acl_entry stays
-- the write model; these arrays are the query model.
--
-- Two ACL projections per event, NOT one: acl_read/acl_write mirror the
-- ARCHIVE policy (admin/API surfaces); pub_read is the publish-time PIN
-- (engage surface). They legitimately diverge.
--
-- Synthetic ROLE_EPISODE_<id>_* roles are NEVER stored (per-event role
-- injection would make the GIN vocabulary grow with the corpus — a measured
-- cost driver). Principals holding such roles get them
-- rewritten query-side into direct id grants (query.go).

create table if not exists search_event (
    mediapackage_id uuid primary key,
    title           text,
    series_id       text,
    series_title    text,
    status          text,
    presenters      text[] not null default '{}',
    contributors    text[] not null default '{}',
    location        text,
    language        text,
    description     text,
    subjects        text[] not null default '{}',
    license         text,
    start_date      timestamptz,
    created         timestamptz,
    duration_ms     bigint,
    acl_state       text not null default 'ABSENT',
    acl_read        text[] not null default '{}',
    acl_write       text[] not null default '{}',
    published       boolean not null default false,
    pub_read        text[] not null default '{}',
    fts             tsvector,
    updated_at      timestamptz not null default now()
);

create index if not exists search_event_acl_read_gin  on search_event using gin (acl_read);
create index if not exists search_event_acl_write_gin on search_event using gin (acl_write);
create index if not exists search_event_pub_read_gin  on search_event using gin (pub_read);
create index if not exists search_event_fts_gin       on search_event using gin (fts);
create index if not exists search_event_start_idx     on search_event (start_date desc);
create index if not exists search_event_title_idx     on search_event (title);
create index if not exists search_event_series_idx    on search_event (series_id);

create extension if not exists pg_trgm;
create index if not exists search_event_title_trgm on search_event using gin (title gin_trgm_ops);

create table if not exists search_series (
    series_id     text primary key,
    title         text,
    contributors  text[] not null default '{}',
    organizers    text[] not null default '{}',
    language      text,
    description   text,
    subjects      text[] not null default '{}',
    created       timestamptz,
    acl_state     text not null default 'ABSENT',
    acl_read      text[] not null default '{}',
    acl_write     text[] not null default '{}',
    -- engage visibility: union of the published episodes' pinned read roles
    -- (the series doc ACL is the union of its episodes' ACLs)
    pub_read      text[] not null default '{}',
    has_published boolean not null default false,
    fts           tsvector,
    updated_at    timestamptz not null default now()
);

create index if not exists search_series_acl_read_gin  on search_series using gin (acl_read);
create index if not exists search_series_acl_write_gin on search_series using gin (acl_write);
create index if not exists search_series_pub_read_gin  on search_series using gin (pub_read);
create index if not exists search_series_fts_gin       on search_series using gin (fts);
