-- Engine schema, increment-1 slice (ADR-004 orchestration, ADR-011
-- assignment + lease). All lease arithmetic uses Postgres now() — node
-- clocks never enter it (S3's clock-skew exclusion, kept).

create table if not exists workflow (
    id              bigserial primary key,
    mediapackage_id uuid        not null,
    definition      jsonb       not null,
    state           text        not null default 'RUNNING'
                    check (state in ('RUNNING','SUCCEEDED','FAILED')),
    current_op      int         not null default 0,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now()
);

create table if not exists task (
    id            bigserial primary key,
    workflow_id   bigint      not null references workflow(id),
    op_index      int         not null,
    operation     text        not null,
    config        jsonb       not null default '{}',
    -- ASSIGNED: committed before any worker is provisioned (ADR-011
    -- ordering — a worker can never start and find its task absent).
    state         text        not null default 'ASSIGNED'
                  check (state in ('ASSIGNED','RUNNING','FINISHED','FAILED')),
    owner         text,
    lease_expires timestamptz not null,
    result        jsonb,
    attempt       int         not null default 1,
    created_at    timestamptz not null default now(),
    updated_at    timestamptz not null default now()
);

create index if not exists task_lease_idx on task (lease_expires)
    where state in ('ASSIGNED','RUNNING');

-- Increment 2: the double-assignment guard. Two orchestrators' assign
-- statements can both pass the not-exists read (read committed); the
-- database, not the read, guarantees one task per (workflow, op_index).
-- Demonstrated red-first in TestAssignInsertRaceStructural.
create unique index if not exists task_wf_op_uidx on task (workflow_id, op_index);

-- Terminal-write guard, structural and in the first schema: a task that has
-- reached a terminal state is immutable. Optimistic version locks guard
-- concurrent writers, not stale owners — a resurrected zombie worker could
-- otherwise overwrite a completed job. Here the database itself rejects any
-- write to a terminal row, so no client code path — present or future — can
-- perform such an overwrite.
create or replace function task_terminal_guard() returns trigger as $$
begin
    if old.state in ('FINISHED','FAILED') then
        raise exception 'task % is terminal (%) and immutable [terminal-write guard]',
            old.id, old.state;
    end if;
    if tg_op = 'DELETE' then
        return old; -- returning new (null on delete) would silently cancel
    end if;
    return new;
end
$$ language plpgsql;

drop trigger if exists task_terminal_guard on task;
create trigger task_terminal_guard
    before update or delete on task
    for each row execute function task_terminal_guard();
