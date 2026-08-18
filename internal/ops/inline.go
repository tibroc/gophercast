// Package ops holds the inline-class operation implementations (ADR-011).
// Each is an engine.InlineFunc: kilobyte-scale work in core, with the row
// mutation committed inside the task's completion transaction (I3).
package ops

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/cas"
	"ocng/internal/engine"
	"ocng/internal/mediapackage"
	"ocng/internal/search"
)

// SnapshotManifest is the serialized archive-version payload — ocng's
// canonical form of what the legacy system's snapshot writes as
// manifest-archived.xml. Content-deduped in CAS: identical states hash to
// the same object (ADR-008); version rows append per call (decision B).
type SnapshotManifest struct {
	MediapackageID string            `json:"mediapackage_id"`
	Title          string            `json:"title,omitempty"`
	DurationMS     int64             `json:"duration_ms,omitempty"`
	Elements       []SnapshotElement `json:"elements"`
}

type SnapshotElement struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	Flavor    string   `json:"flavor"`
	Mimetype  string   `json:"mimetype,omitempty"`
	SHA256    string   `json:"sha256"`
	SizeBytes int64    `json:"size_bytes"`
	Tags      []string `json:"tags,omitempty"`
}

// Canonical serializes the manifest in canonical order — identical states
// serialize to identical bytes → the same CAS object (the content-dedup half
// of decision B). The single serialization both the snapshot operation and
// migration (increment 6) write, so the two paths cannot drift.
func (m *SnapshotManifest) Canonical() ([]byte, error) {
	sort.Slice(m.Elements, func(i, j int) bool {
		a, b := m.Elements[i], m.Elements[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Flavor != b.Flavor {
			return a.Flavor < b.Flavor
		}
		return a.ID < b.ID
	})
	return json.Marshal(m)
}

// Snapshot returns the inline snapshot operation — decision B (2026-08-14):
// one version row APPENDED per call, preserving the legacy system's observable
// every-call-is-a-version semantics; the manifest payload is
// content-addressed in CAS, so snapshots of identical state share bytes.
// No idempotency key: the version row commits inside the task's completion
// transaction (I3), and I4 makes it exactly-once per task.
func Snapshot(store *cas.Store) engine.InlineFunc {
	return func(ctx context.Context, pool *pgxpool.Pool, task engine.Task) (any, func(context.Context, pgx.Tx) error, error) {
		mpID, err := engine.MediapackageID(ctx, pool, task.ID)
		if err != nil {
			return nil, nil, err
		}
		patterns := splitList(task.Config["source-flavors"])
		if len(patterns) == 0 {
			patterns = []string{"*/*"} // legacy default: everything
		}

		var title *string
		var durationMS *int64
		if err := pool.QueryRow(ctx, `select title, duration_ms from mediapackage where id=$1`, mpID).
			Scan(&title, &durationMS); err != nil {
			return nil, nil, err
		}
		elements, err := mediapackage.Elements(ctx, pool, mpID)
		if err != nil {
			return nil, nil, err
		}
		tags, err := mediapackage.ElementTags(ctx, pool, mpID)
		if err != nil {
			return nil, nil, err
		}

		m := SnapshotManifest{MediapackageID: mpID}
		if title != nil {
			m.Title = *title
		}
		if durationMS != nil {
			m.DurationMS = *durationMS
		}
		for _, el := range elements {
			if !matchesAny(patterns, el.Flavor) {
				continue
			}
			elTags := append([]string(nil), tags[el.ID]...)
			sort.Strings(elTags)
			m.Elements = append(m.Elements, SnapshotElement{
				ID: el.ID, Kind: el.Kind, Flavor: el.Flavor, Mimetype: el.Mimetype,
				SHA256: el.SHA256, SizeBytes: el.SizeBytes, Tags: elTags,
			})
		}
		if len(m.Elements) == 0 {
			return nil, nil, fmt.Errorf("task %d: snapshot selected no elements (source-flavors %v)", task.ID, patterns)
		}
		raw, err := m.Canonical()
		if err != nil {
			return nil, nil, err
		}
		tmp, err := os.CreateTemp("", "ocng-snapshot-*.json")
		if err != nil {
			return nil, nil, err
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.Write(raw); err != nil {
			tmp.Close()
			return nil, nil, err
		}
		tmp.Close()
		sha, err := store.PutFile(ctx, tmp.Name())
		if err != nil {
			return nil, nil, err
		}

		result := map[string]any{"manifest_sha256": sha, "elements": len(m.Elements)}
		mutate := func(ctx context.Context, tx pgx.Tx) error {
			// serialize concurrent snapshots of one mediapackage on its
			// row lock, so max(version)+1 cannot collide
			if _, err := tx.Exec(ctx, `select 1 from mediapackage where id=$1 for update`, mpID); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `
				insert into mp_snapshot (mediapackage_id, version, manifest_sha256)
				select $1, coalesce(max(version),0)+1, $2
				from mp_snapshot where mediapackage_id = $1`, mpID, sha)
			return err
		}
		return result, mutate, nil
	}
}

// Publish returns the inline reference-based publish operation, registered
// as the legacy system's `publish-configure` (its op id and config-key names
// are wire contract: channel-id required, download-source-flavors
// selects; there is no bare "publish" among the 98). ADR-008: publication
// is rows referencing elements, never byte copies — CONTRACTS §3.2's
// inline classification of the publish family depends on exactly this.
// Re-publishing a channel replaces its reference set.
func Publish() engine.InlineFunc {
	return func(ctx context.Context, pool *pgxpool.Pool, task engine.Task) (any, func(context.Context, pgx.Tx) error, error) {
		mpID, err := engine.MediapackageID(ctx, pool, task.ID)
		if err != nil {
			return nil, nil, err
		}
		channel := task.Config["channel-id"]
		if channel == "" {
			return nil, nil, fmt.Errorf("task %d: channel-id is required", task.ID)
		}
		if task.Config["download-source-tags"] != "" || task.Config["streaming-source-flavors"] != "" {
			return nil, nil, fmt.Errorf("task %d: only download-source-flavors selection is implemented in increment 2", task.ID)
		}
		patterns := splitList(task.Config["download-source-flavors"])
		if len(patterns) == 0 {
			return nil, nil, fmt.Errorf("task %d: download-source-flavors is required", task.ID)
		}
		elements, err := mediapackage.Elements(ctx, pool, mpID)
		if err != nil {
			return nil, nil, err
		}
		var ids []string
		for _, el := range elements {
			if matchesAny(patterns, el.Flavor) {
				ids = append(ids, el.ID)
			}
		}
		if len(ids) == 0 {
			return nil, nil, fmt.Errorf("task %d: publish selected no elements (download-source-flavors %v)", task.ID, patterns)
		}
		result := map[string]any{"channel": channel, "elements": len(ids)}
		mutate := func(ctx context.Context, tx pgx.Tx) error {
			// The pinned insert (mediapackage.PublishTx) — serve-auth F-D:
			// this op used to write an unpinned publication row, so a
			// workflow-published event carried acl_read={} and D-044 would
			// have refused it to everyone. One write path for the pin.
			id, err := mediapackage.PublishTx(ctx, tx, mpID, channel)
			if err != nil {
				return err
			}
			// replace semantics: the channel's reference set is the new one
			if _, err := tx.Exec(ctx, `delete from publication_element where publication_id=$1`, id); err != nil {
				return err
			}
			for _, el := range ids {
				if _, err := tx.Exec(ctx, `
					insert into publication_element (publication_id, element_id)
					values ($1, $2)`, id, el); err != nil {
					return err
				}
			}
			// publication rows feed the projection (published, pub_read) —
			// refresh it in the completion transaction (I3), same wiring as
			// every other projected-state writer (assembly finding A3's class)
			return search.ProjectEvent(ctx, tx, mpID)
		}
		return result, mutate, nil
	}
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func matchesAny(patterns []string, flavor string) bool {
	for _, p := range patterns {
		if mediapackage.FlavorMatches(p, flavor) {
			return true
		}
	}
	return false
}

// LoadSnapshot fetches one archive version's manifest back out of CAS.
func LoadSnapshot(ctx context.Context, pool *pgxpool.Pool, store *cas.Store, mediapackageID string, version int) (SnapshotManifest, error) {
	var sha string
	if err := pool.QueryRow(ctx, `
		select manifest_sha256 from mp_snapshot
		where mediapackage_id = $1 and version = $2`, mediapackageID, version).Scan(&sha); err != nil {
		return SnapshotManifest{}, fmt.Errorf("snapshot v%d of %s: %w", version, mediapackageID, err)
	}
	r, err := store.Get(ctx, sha)
	if err != nil {
		return SnapshotManifest{}, err
	}
	defer r.Close()
	var m SnapshotManifest
	if err := json.NewDecoder(r).Decode(&m); err != nil {
		return SnapshotManifest{}, fmt.Errorf("snapshot payload %s: %w", sha, err)
	}
	return m, nil
}
