-- ACL model — the D-028/D-032 core.
--
-- Design constraints:
--   * ALL entries are stored, allow and deny alike; the primary key INCLUDES
--     the allow flag, so an allow and a deny for the same (role, action) can
--     coexist and can never collapse into whichever was written last —
--     guaranteed by schema, not by discipline.
--   * The policy row is separate from the entries so ABSENT (no policy ever
--     set) and EMPTY (a policy set that grants nothing) are distinguishable
--     states (D-032). ABSENT = no acl_policy row; EMPTY = policy row with
--     zero entries; POPULATED = policy row with entries.
--   * Read-back is a plain select of what is stored — write and read are
--     symmetric by construction.

create table if not exists acl_policy (
    scope     text not null check (scope in ('event','series')),
    scope_id  text not null,
    updated_at timestamptz not null default now(),
    primary key (scope, scope_id)
);

create table if not exists acl_entry (
    scope     text not null,
    scope_id  text not null,
    role      text not null,
    action    text not null,
    allow     boolean not null,
    primary key (scope, scope_id, role, action, allow),
    foreign key (scope, scope_id) references acl_policy (scope, scope_id) on delete cascade
);

create index if not exists acl_entry_scope_idx on acl_entry (scope, scope_id);
-- the role-pruning vocabulary read (S2 §4.3): distinct roles, small, indexed
create index if not exists acl_entry_role_idx on acl_entry (role);
