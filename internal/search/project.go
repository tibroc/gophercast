// Package search is the increment-4 projection and query layer (S2 verdict:
// PostgreSQL, role arrays + GIN; D-020: the fulltext contract is semantics
// and reachability, not rank order).
package search

import (
	"context"
	_ "embed"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/acl"
	"ocng/internal/schemastep"
)

//go:embed schema.sql
var schema string

// Migrate: ledger step 0 (T2 Option A) — applied once, skipped lock-free after.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := schemastep.Run(ctx, pool, "search", MigrationSteps())
	return err
}

func MigrationSteps() []schemastep.Step {
	return []schemastep.Step{schemastep.TxDDL(0, "baseline", schema)}
}

// projectEventSQL derives one search_event row from the authoritative
// tables. Every piece of it is a plain SQL re-derivation — nothing is
// carried over from the previous projection row, so a projection can never
// drift from what a rebuild would produce.
//
// ACL arrays are D-028-evaluated at projection time: a role appears in
// acl_read only if it holds a read allow AND no read deny (deny vetoes).
// The row still records acl_state so ABSENT stays reportable (D-032).
const projectEventSQL = `
insert into search_event (mediapackage_id, title, series_id, series_title,
    status, presenters, contributors, location, language, description,
    subjects, license, start_date, created, duration_ms,
    acl_state, acl_read, acl_write, published, pub_read, fts, updated_at)
select mp.id, mp.title, mp.series_id, s.title,
       md.status, coalesce(md.creators,'{}'), coalesce(md.contributors,'{}'),
       md.location, md.language, md.description,
       coalesce(md.subjects,'{}'), md.license,
       coalesce(mp.start_time, md.created), md.created, mp.duration_ms,
       case when p.scope_id is null then 'ABSENT'
            when not exists (select 1 from acl_entry e
                             where e.scope='event' and e.scope_id=mp.id::text)
                 then 'EMPTY'
            else 'POPULATED' end,
       coalesce((select array_agg(distinct a.role) from acl_entry a
                 where a.scope='event' and a.scope_id=mp.id::text
                   and a.action='read' and a.allow
                   and not exists (select 1 from acl_entry d
                        where d.scope=a.scope and d.scope_id=a.scope_id
                          and d.role=a.role and d.action='read' and not d.allow)), '{}'),
       coalesce((select array_agg(distinct a.role) from acl_entry a
                 where a.scope='event' and a.scope_id=mp.id::text
                   and a.action='write' and a.allow
                   and not exists (select 1 from acl_entry d
                        where d.scope=a.scope and d.scope_id=a.scope_id
                          and d.role=a.role and d.action='write' and not d.allow)), '{}'),
       exists (select 1 from publication pub where pub.mediapackage_id = mp.id),
       coalesce((select pub.acl_read from publication pub
                 where pub.mediapackage_id = mp.id and pub.channel = 'engage-player'), '{}'),
       to_tsvector('english',
           coalesce(mp.title,'') || ' ' ||
           array_to_string(coalesce(md.creators,'{}'),' ') || ' ' ||
           array_to_string(coalesce(md.contributors,'{}'),' ') || ' ' ||
           coalesce(md.description,'') || ' ' ||
           array_to_string(coalesce(md.subjects,'{}'),' ') || ' ' ||
           coalesce(md.location,'') || ' ' ||
           coalesce(s.title,'')),
       now()
from mediapackage mp
left join mp_metadata md on md.mediapackage_id = mp.id
left join series s on s.id = mp.series_id
left join acl_policy p on p.scope = 'event' and p.scope_id = mp.id::text
where mp.id = $1
on conflict (mediapackage_id) do update set
    title=excluded.title, series_id=excluded.series_id,
    series_title=excluded.series_title, status=excluded.status,
    presenters=excluded.presenters, contributors=excluded.contributors,
    location=excluded.location, language=excluded.language,
    description=excluded.description, subjects=excluded.subjects,
    license=excluded.license, start_date=excluded.start_date,
    created=excluded.created, duration_ms=excluded.duration_ms,
    acl_state=excluded.acl_state, acl_read=excluded.acl_read,
    acl_write=excluded.acl_write, published=excluded.published,
    pub_read=excluded.pub_read, fts=excluded.fts, updated_at=now()`

const projectSeriesSQL = `
insert into search_series (series_id, title, contributors, organizers,
    language, description, subjects, created,
    acl_state, acl_read, acl_write, pub_read, has_published, fts, updated_at)
select s.id, s.title, s.contributors, s.organizers,
       s.language, s.description, s.subjects, s.created,
       case when p.scope_id is null then 'ABSENT'
            when not exists (select 1 from acl_entry e
                             where e.scope='series' and e.scope_id=s.id)
                 then 'EMPTY'
            else 'POPULATED' end,
       coalesce((select array_agg(distinct a.role) from acl_entry a
                 where a.scope='series' and a.scope_id=s.id
                   and a.action='read' and a.allow
                   and not exists (select 1 from acl_entry d
                        where d.scope=a.scope and d.scope_id=a.scope_id
                          and d.role=a.role and d.action='read' and not d.allow)), '{}'),
       coalesce((select array_agg(distinct a.role) from acl_entry a
                 where a.scope='series' and a.scope_id=s.id
                   and a.action='write' and a.allow
                   and not exists (select 1 from acl_entry d
                        where d.scope=a.scope and d.scope_id=a.scope_id
                          and d.role=a.role and d.action='write' and not d.allow)), '{}'),
       coalesce((select array_agg(distinct role) from (
                   select unnest(se.pub_read) as role from search_event se
                   where se.series_id = s.id and se.published) u), '{}'),
       exists (select 1 from search_event se
               where se.series_id = s.id and se.published),
       to_tsvector('english',
           coalesce(s.title,'') || ' ' ||
           array_to_string(s.contributors,' ') || ' ' ||
           array_to_string(s.organizers,' ') || ' ' ||
           coalesce(s.description,'') || ' ' ||
           array_to_string(s.subjects,' ')),
       now()
from series s
left join acl_policy p on p.scope = 'series' and p.scope_id = s.id
where s.id = $1
on conflict (series_id) do update set
    title=excluded.title, contributors=excluded.contributors,
    organizers=excluded.organizers, language=excluded.language,
    description=excluded.description, subjects=excluded.subjects,
    created=excluded.created, acl_state=excluded.acl_state,
    acl_read=excluded.acl_read, acl_write=excluded.acl_write,
    pub_read=excluded.pub_read, has_published=excluded.has_published,
    fts=excluded.fts, updated_at=now()`

// ProjectEvent refreshes one event's projection row inside the writer's
// transaction, then its series row (whose published-union may have changed).
// A tombstoned event (T4 delete, deleted_at set) has NO projection row — it
// drops from every list surface while the authoritative row keeps the dated
// retraction signal.
func ProjectEvent(ctx context.Context, tx pgx.Tx, mpID string) error {
	var deleted bool
	var seriesID *string
	if err := tx.QueryRow(ctx, `select deleted_at is not null, series_id from mediapackage where id=$1`, mpID).
		Scan(&deleted, &seriesID); err != nil {
		return fmt.Errorf("project event %s: %w", mpID, err)
	}
	if deleted {
		if _, err := tx.Exec(ctx, `delete from search_event where mediapackage_id=$1`, mpID); err != nil {
			return fmt.Errorf("project event %s: %w", mpID, err)
		}
	} else if _, err := tx.Exec(ctx, projectEventSQL, mpID); err != nil {
		return fmt.Errorf("project event %s: %w", mpID, err)
	}
	if seriesID != nil {
		return projectSeries(ctx, tx, *seriesID)
	}
	return nil
}

// ProjectSeries refreshes one series row and every episode row that
// denormalises its title — all in the caller's transaction.
func ProjectSeries(ctx context.Context, tx pgx.Tx, seriesID string) error {
	rows, err := tx.Query(ctx, `select id from mediapackage where series_id=$1 and deleted_at is null`, seriesID)
	if err != nil {
		return err
	}
	var eventIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		eventIDs = append(eventIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range eventIDs {
		if _, err := tx.Exec(ctx, projectEventSQL, id); err != nil {
			return fmt.Errorf("project series %s event %s: %w", seriesID, id, err)
		}
	}
	return projectSeries(ctx, tx, seriesID)
}

func projectSeries(ctx context.Context, tx pgx.Tx, seriesID string) error {
	var deleted bool
	err := tx.QueryRow(ctx, `select deleted_at is not null from series where id=$1`, seriesID).Scan(&deleted)
	if err != nil || deleted {
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("project series %s: %w", seriesID, err)
		}
		// tombstoned (or vanished) series: no projection row (T4 delete)
		if _, err := tx.Exec(ctx, `delete from search_series where series_id=$1`, seriesID); err != nil {
			return fmt.Errorf("project series %s: %w", seriesID, err)
		}
		return nil
	}
	if _, err := tx.Exec(ctx, projectSeriesSQL, seriesID); err != nil {
		return fmt.Errorf("project series %s: %w", seriesID, err)
	}
	return nil
}

// SetSeriesACL is the series ACL write with the override blast-radius flag
// (T4; the two-button override control — CONTRACTS §4.5):
// override=false replaces the series policy only; override=true additionally
// full-replaces every LIVE member event's policy with the same entries. One
// transaction: every policy row and every projection refresh commit together
// (S2 §4.5 — no window in which authorization and its index disagree).
func SetSeriesACL(ctx context.Context, pool *pgxpool.Pool, id string, entries []acl.Entry, override bool) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if err := acl.SetTx(ctx, tx, acl.ScopeSeries, id, entries); err != nil {
			return err
		}
		if override {
			rows, err := tx.Query(ctx, `select id from mediapackage where series_id=$1 and deleted_at is null`, id)
			if err != nil {
				return err
			}
			var eventIDs []string
			for rows.Next() {
				var eid string
				if err := rows.Scan(&eid); err != nil {
					rows.Close()
					return err
				}
				eventIDs = append(eventIDs, eid)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			for _, eid := range eventIDs {
				if err := acl.SetTx(ctx, tx, acl.ScopeEvent, eid, entries); err != nil {
					return err
				}
			}
		}
		// re-projects the series row and every live member event's row —
		// which covers both the override and no-override cases
		return ProjectSeries(ctx, tx, id)
	})
}

// SetACL is the one ACL write path (HAZARDS: one filter, one semantics):
// full-replace the policy and refresh the projection, atomically.
func SetACL(ctx context.Context, pool *pgxpool.Pool, scope acl.Scope, id string, entries []acl.Entry) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if err := acl.SetTx(ctx, tx, scope, id, entries); err != nil {
			return err
		}
		switch scope {
		case acl.ScopeEvent:
			return ProjectEvent(ctx, tx, id)
		case acl.ScopeSeries:
			return ProjectSeries(ctx, tx, id)
		}
		return fmt.Errorf("unknown scope %q", scope)
	})
}

// Rebuild re-derives the ENTIRE projection from the authoritative tables in
// one transaction. Not an operational reindex — nothing drifts to repair —
// but migration's verification lever (increment 6 proves projection ≡
// authoritative state before trusting the inventory) and the proof that
// incremental maintenance and re-derivation agree (asserted by the e2e test).
func Rebuild(ctx context.Context, pool *pgxpool.Pool) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `delete from search_event`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `delete from search_series`); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `select id from mediapackage where deleted_at is null`)
		if err != nil {
			return err
		}
		var eventIDs []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			eventIDs = append(eventIDs, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range eventIDs {
			if _, err := tx.Exec(ctx, projectEventSQL, id); err != nil {
				return err
			}
		}
		srows, err := tx.Query(ctx, `select id from series where deleted_at is null`)
		if err != nil {
			return err
		}
		var seriesIDs []string
		for srows.Next() {
			var id string
			if err := srows.Scan(&id); err != nil {
				srows.Close()
				return err
			}
			seriesIDs = append(seriesIDs, id)
		}
		srows.Close()
		if err := srows.Err(); err != nil {
			return err
		}
		for _, id := range seriesIDs {
			if _, err := tx.Exec(ctx, projectSeriesSQL, id); err != nil {
				return err
			}
		}
		return nil
	})
}
