// Increment-4 stored-model extension: typed episode metadata, series, and
// the publish-time ACL pin (schema.sql, increment-4 section). Every write
// here refreshes the search projection IN THE SAME TRANSACTION (S2 §4.5 —
// with a single store and a same-transaction refresh there is no second
// store and no cross-node index-writer race window).
package mediapackage

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/search"
)

type Metadata struct {
	Creators     []string
	Contributors []string
	Language     string
	Description  string
	Subjects     []string
	Location     string
	License      string
	Created      *time.Time
	SeriesID     string
	Status       string
}

type SeriesMetadata struct {
	Title        string
	Contributors []string
	Organizers   []string
	Language     string
	Description  string
	Subjects     []string
	Created      *time.Time
}

func emptyNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// SetMetadata upserts the typed episode metadata (full replace — the DC
// catalog is one document, partial merges would invent state) and refreshes
// the projection in the same transaction.
func SetMetadata(ctx context.Context, pool *pgxpool.Pool, mpID string, md Metadata) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			insert into mp_metadata (mediapackage_id, creators, contributors, language,
			                         description, subjects, location, license, created, status)
			values ($1,$2,$3,nullif($4,''),nullif($5,''),$6,nullif($7,''),nullif($8,''),$9,nullif($10,''))
			on conflict (mediapackage_id) do update set
			  creators=excluded.creators, contributors=excluded.contributors,
			  language=excluded.language, description=excluded.description,
			  subjects=excluded.subjects, location=excluded.location,
			  license=excluded.license, created=excluded.created,
			  status=excluded.status, updated_at=now()`,
			mpID, emptyNil(md.Creators), emptyNil(md.Contributors), md.Language,
			md.Description, emptyNil(md.Subjects), md.Location, md.License,
			md.Created, md.Status); err != nil {
			return fmt.Errorf("set metadata: %w", err)
		}
		var seriesID *string
		if md.SeriesID != "" {
			seriesID = &md.SeriesID
		}
		if _, err := tx.Exec(ctx, `update mediapackage set series_id=$2 where id=$1`,
			mpID, seriesID); err != nil {
			return fmt.Errorf("set metadata: %w", err)
		}
		return search.ProjectEvent(ctx, tx, mpID)
	})
}

// PutSeries upserts a series (full replace) and refreshes its projection —
// and its episodes' rows, whose denormalised series_title may have changed.
func PutSeries(ctx context.Context, pool *pgxpool.Pool, id string, md SeriesMetadata) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			insert into series (id, title, contributors, organizers, language,
			                    description, subjects, created)
			values ($1,nullif($2,''),$3,$4,nullif($5,''),nullif($6,''),$7,$8)
			on conflict (id) do update set
			  title=excluded.title, contributors=excluded.contributors,
			  organizers=excluded.organizers, language=excluded.language,
			  description=excluded.description, subjects=excluded.subjects,
			  created=excluded.created`,
			id, md.Title, emptyNil(md.Contributors), emptyNil(md.Organizers),
			md.Language, md.Description, emptyNil(md.Subjects), md.Created); err != nil {
			return fmt.Errorf("put series: %w", err)
		}
		return search.ProjectSeries(ctx, tx, id)
	})
}

// Publish records a publication and PINS the ACL: pub read roles are the
// event's read-allow set AT THIS INSTANT (a later archive-ACL edit
// must not leak into the published surface until republish). Idempotent per
// (mediapackage, channel): a re-publish refreshes the pin, matching the
// legacy system's republish semantics.
func Publish(ctx context.Context, pool *pgxpool.Pool, mpID, channel string) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := PublishTx(ctx, tx, mpID, channel); err != nil {
			return err
		}
		return search.ProjectEvent(ctx, tx, mpID)
	})
}

// PublishTx is the ONE pinned publication write — every publish path
// (native Publish above, the workflow publish-configure op) goes through
// this statement, so the pin can never be absent on one path and present on
// another (serve-auth F-D: ops.Publish used to insert an unpinned row).
// Returns the publication id for reference-set maintenance. The caller owns
// the projection refresh.
//
// The pin is D-028-evaluated at write time: read-allowed roles MINUS
// read-denied ones — a role that is both allowed and denied read is never
// pinned as readable. acl_state is stamped with
// the archive policy's D-032 state at the same instant (serve-auth F-B: the
// column used to keep its 'ABSENT' default forever on native publishes,
// making POPULATED pins report ABSENT), mirroring the projection's
// derivation in search/project.go. The schema.sql comment saying native
// Publish leaves the default predates this fix and is frozen there — the
// baseline is an applied ledger step, immutable by hash (T2).
func PublishTx(ctx context.Context, tx pgx.Tx, mpID, channel string) (string, error) {
	var id string
	if err := tx.QueryRow(ctx, `
		insert into publication (id, mediapackage_id, channel, acl_read, acl_state)
		values ($1, $2::uuid, $3,
		        coalesce((select array_agg(distinct a.role) from acl_entry a
		                  where a.scope='event' and a.scope_id=$4
		                    and a.action='read' and a.allow
		                    and not exists (select 1 from acl_entry d
		                          where d.scope=a.scope and d.scope_id=a.scope_id
		                            and d.role=a.role and d.action='read' and not d.allow)),
		                 '{}'),
		        case when not exists (select 1 from acl_policy p
		                              where p.scope='event' and p.scope_id=$4) then 'ABSENT'
		             when not exists (select 1 from acl_entry e
		                              where e.scope='event' and e.scope_id=$4) then 'EMPTY'
		             else 'POPULATED' end)
		on conflict (mediapackage_id, channel) do update set
		  acl_read = excluded.acl_read, acl_state = excluded.acl_state,
		  created_at = now()
		returning id`,
		uuid.NewString(), mpID, channel, mpID).Scan(&id); err != nil {
		return "", fmt.Errorf("publish: %w", err)
	}
	return id, nil
}
