package definitions

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Loader watches one bind-mounted directory of YAML definition files and
// upserts changed ones into workflow_definition (ADR-009: bind mount
// authors, database executes). Both replicas run a Loader — upserts are
// conditioned on the content hash, so racing replicas loading identical
// bytes write identical rows and a no-change poll issues no write at all.
type Loader struct {
	Pool *pgxpool.Pool
	Dir  string
	Log  *slog.Logger

	// per-file state: last successfully applied hash, and the last hash we
	// reported an error for (so a persistently broken file logs once per
	// distinct content, not once per tick)
	applied map[string]string
	errored map[string]string
}

// LoadOnce loads the directory once, fail-loud: any unreadable file, parse
// failure, or duplicate id is an error. This is the BOOT posture — boot is
// where loud is cheap (T5 boot-time load).
func (l *Loader) LoadOnce(ctx context.Context) error {
	return l.load(ctx, true)
}

// Watch polls the directory until ctx ends. This is the RUNTIME posture: a
// file that stops parsing keeps its last-good row and logs ERROR — an
// operator typo must not take the core down.
func (l *Loader) Watch(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := l.load(ctx, false); err != nil {
				// directory-level failure (mount gone, DB error): ERROR and
				// keep serving from the database
				l.Log.Error("definitions: poll failed", "dir", l.Dir, "err", err)
			}
		}
	}
}

// load is one pass over the directory. strict=true returns the first
// error (boot); strict=false logs per-file errors and applies what parses.
func (l *Loader) load(ctx context.Context, strict bool) error {
	if l.applied == nil {
		l.applied = map[string]string{}
		l.errored = map[string]string{}
	}
	entries, err := os.ReadDir(l.Dir)
	if err != nil {
		return fmt.Errorf("definitions: reading %s: %w", l.Dir, err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			files = append(files, name)
		}
	}
	sort.Strings(files)

	// parse pass first, over the whole directory, so duplicate ids across
	// files are detected before anything is written
	type parsed struct {
		file string
		id   string
		raw  []byte
		hash string
	}
	var toApply []parsed
	byID := map[string]string{} // id -> file, this pass
	for _, name := range files {
		path := filepath.Join(l.Dir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			if strict {
				return fmt.Errorf("definitions: %s: %w", path, err)
			}
			l.fileError(name, "", fmt.Errorf("reading: %w", err))
			continue
		}
		hash := Hash(raw)
		id, _, err := Parse(raw)
		if err != nil {
			if strict {
				return fmt.Errorf("definitions: %s: %w", path, err)
			}
			l.fileError(name, hash, err)
			continue
		}
		if other, dup := byID[id]; dup {
			err := fmt.Errorf("definitions: id %q defined in both %s and %s", id, other, name)
			if strict {
				return err
			}
			l.fileError(name, hash, err)
			continue
		}
		byID[id] = name
		delete(l.errored, name) // parses again: clear the once-per-content latch
		if l.applied[name] == hash {
			continue // unchanged since we last applied it
		}
		toApply = append(toApply, parsed{file: name, id: id, raw: raw, hash: hash})
	}

	for _, p := range toApply {
		tag, err := l.Pool.Exec(ctx, `
			insert into workflow_definition (id, yaml, hash, updated_at)
			values ($1, $2, $3, now())
			on conflict (id) do update
			   set yaml = excluded.yaml, hash = excluded.hash, updated_at = now()
			 where workflow_definition.hash is distinct from excluded.hash`,
			p.id, p.raw, p.hash)
		if err != nil {
			if strict {
				return fmt.Errorf("definitions: storing %q: %w", p.id, err)
			}
			l.Log.Error("definitions: storing failed", "id", p.id, "file", p.file, "err", err)
			continue
		}
		l.applied[p.file] = p.hash
		// tag distinguishes "we wrote it" from "another replica already had"
		// — both replicas logging the hash they loaded is the ADR-009 drift
		// signal, so log either way
		l.Log.Info("definition loaded", "id", p.id, "file", p.file,
			"hash", p.hash, "wrote", tag.RowsAffected() == 1)
	}
	return nil
}

// fileError logs one ERROR per distinct broken content of a file, keeping
// the last-good row serving (the runtime posture).
func (l *Loader) fileError(name, hash string, err error) {
	if l.errored[name] == hash && hash != "" {
		return
	}
	l.errored[name] = hash
	l.Log.Error("definitions: file rejected — last-good definition keeps serving",
		"file", name, "err", err)
}
