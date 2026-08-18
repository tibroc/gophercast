// T4 write-surface support: the read-current/merge-write pair the PARTIAL
// metadata edit needs (the admin UI sends only changed fields — the measured
// request shape), and the tombstone half of the asymmetric delete.
//
// The archive hard-delete/GC half of delete is deliberately ABSENT: it is
// held pending the increment-6 GC-grace verification. Nothing
// here touches mp_snapshot, mp_element or CAS — a tombstoned mediapackage's
// archive stays byte-for-byte intact (ADR-008 source-unmutated preserved).
package mediapackage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/search"
)

// GetEventDC reads the current episode DC state — the archive fields on the
// mediapackage row plus the typed metadata row — as the merge base for a
// partial edit. A missing mp_metadata row yields zero-valued Metadata (a
// loader/migration-fed event may never have had one).
func GetEventDC(ctx context.Context, pool *pgxpool.Pool, mpID string) (title string, start *time.Time, md Metadata, err error) {
	var seriesID *string
	if err = pool.QueryRow(ctx, `
		select coalesce(title,''), start_time, series_id
		from mediapackage where id::text = $1 and deleted_at is null`, mpID).
		Scan(&title, &start, &seriesID); err != nil {
		return "", nil, Metadata{}, fmt.Errorf("get event dc %s: %w", mpID, err)
	}
	if seriesID != nil {
		md.SeriesID = *seriesID
	}
	var language, description, location, license, status *string
	err = pool.QueryRow(ctx, `
		select creators, contributors, language, description, subjects,
		       location, license, created, status
		from mp_metadata where mediapackage_id = $1`, mpID).
		Scan(&md.Creators, &md.Contributors, &language, &description, &md.Subjects,
			&location, &license, &md.Created, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return title, start, md, nil
	}
	if err != nil {
		return "", nil, Metadata{}, fmt.Errorf("get event dc %s: %w", mpID, err)
	}
	for dst, src := range map[*string]*string{
		&md.Language: language, &md.Description: description,
		&md.Location: location, &md.License: license, &md.Status: status,
	} {
		if src != nil {
			*dst = *src
		}
	}
	return title, start, md, nil
}

// SetEventDC writes the full episode DC state — archive fields (title,
// start_time, series_id) and the typed metadata — in ONE transaction with
// the projection refresh (S2 §4.5). The full-replace counterpart of
// GetEventDC: partial-merge semantics live in the HTTP handler, which reads,
// merges, and writes the whole state (the DC catalog is one document —
// SetMetadata's rationale, extended to the archive fields).
func SetEventDC(ctx context.Context, pool *pgxpool.Pool, mpID, title string, start *time.Time, md Metadata) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		var seriesID *string
		if md.SeriesID != "" {
			seriesID = &md.SeriesID
		}
		if _, err := tx.Exec(ctx, `
			update mediapackage set title = nullif($2,''), start_time = $3, series_id = $4
			where id::text = $1 and deleted_at is null`,
			mpID, title, start, seriesID); err != nil {
			return fmt.Errorf("set event dc: %w", err)
		}
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
			return fmt.Errorf("set event dc: %w", err)
		}
		return search.ProjectEvent(ctx, tx, mpID)
	})
}

// GetSeriesDC reads a live series' current metadata as the merge base for a
// partial edit. found=false for an unknown or tombstoned series.
func GetSeriesDC(ctx context.Context, pool *pgxpool.Pool, id string) (md SeriesMetadata, found bool, err error) {
	var title, language, description *string
	err = pool.QueryRow(ctx, `
		select title, contributors, organizers, language, description, subjects, created
		from series where id = $1 and deleted_at is null`, id).
		Scan(&title, &md.Contributors, &md.Organizers, &language, &description,
			&md.Subjects, &md.Created)
	if errors.Is(err, pgx.ErrNoRows) {
		return SeriesMetadata{}, false, nil
	}
	if err != nil {
		return SeriesMetadata{}, false, fmt.Errorf("get series %s: %w", id, err)
	}
	for dst, src := range map[*string]*string{
		&md.Title: title, &md.Language: language, &md.Description: description,
	} {
		if src != nil {
			*dst = *src
		}
	}
	return md, true, nil
}

// TombstoneEvent is the asymmetric event delete (approved 2026-08-18):
//
//   - INDEX half: set the dated retraction signal (deleted_at, mediapackage
//     row RETAINED — the tombstone a conformant consumer observes) and
//     retract by removing the publication rows (ordinary DML on the
//     serve-read set; publication_element cascades). The projection row is
//     removed in the same transaction, so every list surface drops the
//     entity atomically with the retraction.
//   - ARCHIVE half: DROP THE REFERENCES — snapshot rows, element rows and
//     their tags — matching the legacy system's stored-state observable (0
//     snapshot rows after delete). The BYTES are deliberately NOT touched:
//     reclaim belongs to the ADR-008 mark-sweep collector (internal/gc),
//     whose grace window protects content a migration or in-flight workflow
//     still references. Nothing on the delete path removes bytes inline.
//
// found=false when the event does not exist or is already tombstoned.
func TombstoneEvent(ctx context.Context, pool *pgxpool.Pool, mpID string) (found bool, err error) {
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			update mediapackage set deleted_at = now()
			where id::text = $1 and deleted_at is null`, mpID)
		if err != nil {
			return fmt.Errorf("tombstone event: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return nil // found stays false
		}
		found = true
		if _, err := tx.Exec(ctx, `delete from publication where mediapackage_id = $1::uuid`, mpID); err != nil {
			return fmt.Errorf("tombstone event: retract publications: %w", err)
		}
		// archive reference drop (FK order: publications above released
		// publication_element's hold on the element rows)
		if _, err := tx.Exec(ctx, `
			delete from mp_element_tag using mp_element
			where mp_element_tag.element_id = mp_element.id
			  and mp_element.mediapackage_id = $1::uuid`, mpID); err != nil {
			return fmt.Errorf("tombstone event: drop element tags: %w", err)
		}
		if _, err := tx.Exec(ctx, `delete from mp_element where mediapackage_id = $1::uuid`, mpID); err != nil {
			return fmt.Errorf("tombstone event: drop element references: %w", err)
		}
		if _, err := tx.Exec(ctx, `delete from mp_snapshot where mediapackage_id = $1::uuid`, mpID); err != nil {
			return fmt.Errorf("tombstone event: drop snapshot references: %w", err)
		}
		return search.ProjectEvent(ctx, tx, mpID)
	})
	return found, err
}

// TombstoneSeries sets the series' dated retraction signal (row retained)
// and drops it from the projection. Member events are untouched — a series
// delete tombstones the series only, matching the legacy system's measured
// behaviour.
func TombstoneSeries(ctx context.Context, pool *pgxpool.Pool, id string) (found bool, err error) {
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			update series set deleted_at = now()
			where id = $1 and deleted_at is null`, id)
		if err != nil {
			return fmt.Errorf("tombstone series: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		found = true
		return search.ProjectSeries(ctx, tx, id)
	})
	return found, err
}
