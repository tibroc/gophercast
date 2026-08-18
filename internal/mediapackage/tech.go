package mediapackage

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Tech is the bounded technical-metadata set the inspect operation writes
// per element (ADR-007: bounded JSONB — this struct IS the bound).
type Tech struct {
	DurationMS int64   `json:"duration_ms"`
	Width      int     `json:"width,omitempty"`
	Height     int     `json:"height,omitempty"`
	Framecount int64   `json:"framecount,omitempty"`
	Framerate  float64 `json:"framerate,omitempty"`
	Channels   int     `json:"channels,omitempty"`
	SampleRate int     `json:"samplerate,omitempty"`
}

// SetElementTech records probed technical metadata inside the caller's
// transaction (the inspect operation's CompleteTask mutation).
func SetElementTech(ctx context.Context, tx pgx.Tx, elementID string, tech Tech) error {
	raw, err := json.Marshal(tech)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `update mp_element set tech = $2 where id = $1`, elementID, raw)
	return err
}

// SetDurationIfNull sets the mediapackage duration if the loader had none —
// the inspect operation's enrichment of the package-level duration
// (legacy Opencast writes it into dc:extent; ocng keeps it relational).
func SetDurationIfNull(ctx context.Context, tx pgx.Tx, mediapackageID string, durationMS int64) error {
	_, err := tx.Exec(ctx, `
		update mediapackage set duration_ms = $2
		where id = $1 and duration_ms is null`, mediapackageID, durationMS)
	return err
}

// ElementTech reads an element's probed technical metadata. pgx.ErrNoRows
// if the element does not exist; an error mentioning null if inspect never
// ran on it.
func ElementTech(ctx context.Context, pool *pgxpool.Pool, elementID string) (Tech, error) {
	var raw []byte
	if err := pool.QueryRow(ctx, `select tech from mp_element where id = $1`, elementID).Scan(&raw); err != nil {
		return Tech{}, err
	}
	var t Tech
	return t, json.Unmarshal(raw, &t)
}
