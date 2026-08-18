package definitions

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/engine"
)

// Registry is the DB-backed Source: the workflow_definition table is the
// execution source of truth (ADR-009 — a core replica without a bind mount,
// or whose mount lags, still executes what the database holds). Lookups are
// read-through with a short TTL cache so the ingest/admin-create hot path is
// not a query per request; the TTL bounds how long an edit takes to become
// visible on a replica that did not load it itself.
type Registry struct {
	Pool *pgxpool.Pool
	// TTL is the cache lifetime for both positive and negative lookups.
	// Zero means DefaultTTL.
	TTL time.Duration

	mu    sync.Mutex
	cache map[string]regEntry
}

const DefaultTTL = 2 * time.Second

type regEntry struct {
	def  engine.Definition
	hash string
	ok   bool
	at   time.Time
}

func (r *Registry) Definition(ctx context.Context, id string) (engine.Definition, bool, error) {
	ttl := r.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	r.mu.Lock()
	e, hit := r.cache[id]
	r.mu.Unlock()
	if hit && time.Since(e.at) < ttl {
		return e.def, e.ok, nil
	}

	var raw []byte
	var hash string
	err := r.Pool.QueryRow(ctx,
		`select yaml, hash from workflow_definition where id = $1`, id).Scan(&raw, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		r.put(id, regEntry{ok: false, at: time.Now()})
		return engine.Definition{}, false, nil
	}
	if err != nil {
		return engine.Definition{}, false, err
	}
	parsedID, def, err := Parse(raw)
	if err != nil {
		// the loader validated before upserting; a bad row means someone
		// wrote the table by hand — surface, don't guess
		return engine.Definition{}, false, fmt.Errorf("definitions: stored definition %q does not parse: %w", id, err)
	}
	if parsedID != id {
		return engine.Definition{}, false, fmt.Errorf("definitions: stored definition under key %q declares id %q", id, parsedID)
	}
	r.put(id, regEntry{def: def, hash: hash, ok: true, at: time.Now()})
	return def, true, nil
}

func (r *Registry) put(id string, e regEntry) {
	r.mu.Lock()
	if r.cache == nil {
		r.cache = map[string]regEntry{}
	}
	r.cache[id] = e
	r.mu.Unlock()
}
