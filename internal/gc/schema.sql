-- The GC candidate ledger (ADR-008 mark-sweep, T4): one row per CAS object
-- OBSERVED unreferenced, stamped when the dereference was first seen. Grace
-- is measured from this timestamp — never from object age — so transiently-
-- unreferenced content (mid-migration, mid-workflow, mid-ingest) provably
-- survives, and a re-reference inside the grace clears the row (resurrection).
-- Off the serve-read set; only the collector reads or writes it.

create table if not exists cas_gc_candidate (
    sha256                text primary key,
    first_unreferenced_at timestamptz not null default now()
);
