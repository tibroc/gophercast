-- Internal MediaPackage representation, increment-1 slice (ADR-007):
-- typed relational rows, elements referencing CAS objects by SHA-256.
-- The flat element table with tags; publications and the bounded JSONB
-- 'extra' arrive with the increments that need them (D-010 strict
-- preservation is a migration concern, not a loader concern).

create table if not exists mediapackage (
    id          uuid primary key,
    title       text,
    start_time  timestamptz,
    duration_ms bigint,
    created_at  timestamptz not null default now()
);

create table if not exists mp_element (
    id              uuid primary key,
    mediapackage_id uuid not null references mediapackage(id),
    kind            text not null check (kind in ('track','catalog','attachment')),
    flavor          text not null,
    mimetype        text,
    sha256          text not null,   -- the CAS reference: sharing = rows pointing at one hash (ADR-008)
    size_bytes      bigint not null default 0,
    source_url      text,            -- provenance: where the manifest said the bytes lived
    created_at      timestamptz not null default now()
);

create index if not exists mp_element_mp_idx on mp_element (mediapackage_id);

create table if not exists mp_element_tag (
    element_id uuid not null references mp_element(id),
    tag        text not null,
    primary key (element_id, tag)
);

-- Increment 2: technical metadata written by the inspect operation.
-- Bounded JSONB per ADR-007 (a fixed small key set: duration_ms, width,
-- height, framecount, framerate, channels, samplerate) — typed columns for
-- what the system queries, JSONB for what it only carries.
alter table mp_element add column if not exists tech jsonb;

-- Increment 2: archive versions (snapshot operation, decision B — one row
-- APPENDED per snapshot call, preserving the legacy system's observable
-- every-call-is-a-version semantics; the manifest payload is
-- content-deduped in CAS, so identical states share bytes, ADR-008).
-- No idempotency key: I3/I4 make the write exactly-once per task
-- (ADR-004 closure note, 2026-08-14).
create table if not exists mp_snapshot (
    id              bigserial primary key,
    mediapackage_id uuid not null references mediapackage(id),
    version         int  not null,
    manifest_sha256 text not null,  -- CAS ref of the serialized manifest
    created_at      timestamptz not null default now(),
    unique (mediapackage_id, version)
);

-- Increment 2: reference-based publication (ADR-008 — rows pointing at
-- elements, never byte copies; CONTRACTS §3.2's inline classification of
-- the publish family depends on this staying reference-based).
create table if not exists publication (
    id              uuid primary key,
    mediapackage_id uuid not null references mediapackage(id),
    channel         text not null,
    created_at      timestamptz not null default now(),
    unique (mediapackage_id, channel)
);

create table if not exists publication_element (
    publication_id uuid not null references publication(id) on delete cascade,
    element_id     uuid not null references mp_element(id),
    primary key (publication_id, element_id)
);

-- Increment 4: the stored-model extension (approved 2026-08-14).
-- Typed relational per ADR-007; no new JSONB (S2: no query shape forces it).

-- Series are their own aggregate (ids are NOT uuids in the wild —
-- ids like "orga-iso-series-1" occur in real deployments — hence text).
create table if not exists series (
    id           text primary key,
    title        text,
    contributors text[] not null default '{}',
    organizers   text[] not null default '{}',
    language     text,
    description  text,
    subjects     text[] not null default '{}',
    created      timestamptz,
    created_at   timestamptz not null default now()
);

alter table mediapackage add column if not exists series_id text references series(id);

-- Typed episode-DC metadata, written by the same paths that parse the DC
-- catalog (ingest) or carry canonical state (loader/migration). One row per
-- mediapackage; the mediapackage row keeps title/start as the archive facts,
-- this carries the queryable field set (contract §6).
create table if not exists mp_metadata (
    mediapackage_id uuid primary key references mediapackage(id),
    creators        text[] not null default '{}',
    contributors    text[] not null default '{}',
    language        text,
    description     text,
    subjects        text[] not null default '{}',
    location        text,
    license         text,
    created         timestamptz,
    status          text,
    updated_at      timestamptz not null default now()
);

-- Publish-time ACL pin (archive ACL and published ACL are different
-- data classes that legitimately diverge; the engage surface filters on the
-- PIN, never on the live archive ACL). Captured at publish, immutable until
-- republish.
alter table publication add column if not exists acl_read text[] not null default '{}';

-- Increment 6 (migration): two additive pieces, ratified 2026-08-16.
-- source_manifest_sha256 stores the legacy system's snapshot XML VERBATIM in CAS —
-- D-010 strict preservation for content the flat manifest cannot represent
-- (nested in-snapshot publications, ref attributes, security attachments).
-- NULL for natively-created snapshots; the system OPERATES on manifest_sha256.
alter table mp_snapshot add column if not exists source_manifest_sha256 text;

-- D-032's three states for the PUBLISHED ACL class: pub pin {} alone cannot
-- distinguish EMPTY from ABSENT, and in migrated data NULL and empty carry
-- different read semantics — the STATE must survive migration even
-- though D-028 unifies the semantics on deny. Native Publish() leaves the
-- default; migration sets it from OC_SEARCH.ACCESS_CONTROL.
alter table publication add column if not exists acl_state text not null default 'ABSENT'
    check (acl_state in ('ABSENT','EMPTY','POPULATED'));
