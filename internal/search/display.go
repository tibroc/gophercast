package search

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// display.go — read-only projection readers for the admin-UI detail surface
// (increment 5). These do NOT participate in visibility or ACL evaluation:
// callers get the visible, ordered id set (+ total) from Events/Series first,
// then fetch display fields for exactly those ids here. Keeping the reader
// separate is deliberate — the proven query/ACL logic in query.go is not
// touched, and the increments 1–4 e2e suite stays the regression guard.

// EventDisplay is the denormalised event row the admin-ng event list and
// detail views render. Field set follows what the admin UI's Event type and
// events table actually read (eventsTableConfig + eventSlice).
type EventDisplay struct {
	ID           string
	Title        string
	SeriesID     string
	SeriesTitle  string
	Status       string
	Presenters   []string
	Contributors []string
	Location     string
	Language     string
	Description  string
	Subjects     []string
	License      string
	StartDate    *time.Time
	Created      *time.Time
	DurationMs   *int64
	Published    bool
}

// EventsDisplay fetches display rows for a set of mediapackage ids, keyed by
// id. Visibility is the caller's responsibility (pass ids from Events()).
func EventsDisplay(ctx context.Context, pool *pgxpool.Pool, ids []string) (map[string]EventDisplay, error) {
	out := make(map[string]EventDisplay, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := pool.Query(ctx, `
		select mediapackage_id, coalesce(title,''), coalesce(series_id,''),
		       coalesce(series_title,''), coalesce(status,''), presenters,
		       contributors, coalesce(location,''), coalesce(language,''),
		       coalesce(description,''), subjects, coalesce(license,''),
		       start_date, created, duration_ms, published
		from search_event where mediapackage_id = any($1)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e EventDisplay
		if err := rows.Scan(&e.ID, &e.Title, &e.SeriesID, &e.SeriesTitle,
			&e.Status, &e.Presenters, &e.Contributors, &e.Location, &e.Language,
			&e.Description, &e.Subjects, &e.License, &e.StartDate, &e.Created,
			&e.DurationMs, &e.Published); err != nil {
			return nil, err
		}
		out[e.ID] = e
	}
	return out, rows.Err()
}

// EventDisplayByID fetches one event's display row (pgx.ErrNoRows if absent —
// the caller has already established visibility).
func EventDisplayByID(ctx context.Context, pool *pgxpool.Pool, id string) (EventDisplay, error) {
	m, err := EventsDisplay(ctx, pool, []string{id})
	if err != nil {
		return EventDisplay{}, err
	}
	e, ok := m[id]
	if !ok {
		return EventDisplay{}, pgx.ErrNoRows
	}
	return e, nil
}

// SeriesDisplay is the denormalised series row the admin-ng series list and
// detail views render.
type SeriesDisplay struct {
	ID           string
	Title        string
	Contributors []string
	Organizers   []string
	Language     string
	Description  string
	Subjects     []string
	Created      *time.Time
}

// SeriesDisplayByID fetches one series' display row.
func SeriesDisplayByID(ctx context.Context, pool *pgxpool.Pool, id string) (SeriesDisplay, error) {
	var s SeriesDisplay
	err := pool.QueryRow(ctx, `
		select series_id, coalesce(title,''), contributors, organizers,
		       coalesce(language,''), coalesce(description,''), subjects, created
		from search_series where series_id = $1`, id).
		Scan(&s.ID, &s.Title, &s.Contributors, &s.Organizers, &s.Language,
			&s.Description, &s.Subjects, &s.Created)
	return s, err
}
