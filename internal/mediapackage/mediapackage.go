// Package mediapackage holds the ADR-007 internal representation (typed
// relational rows, elements referencing CAS objects) and the increment-1
// loader, which reads an ARCHIVED MANIFEST — the /assets/episode/{id}
// document class — fetches the referenced bytes into CAS, and writes
// element rows. It is a fixture feeder, not
// ingest (BUILD-ORDER increment 1).
//
// Parsing note: elements are matched by LOCAL NAME, deliberately. S1 found
// the same document arrives as default-ns, ns2:, oc: and mp: in the wild;
// all four bind the single mediapackage namespace, so local-name matching
// accepts every shape without a namespace table. Nothing here re-emits XML,
// so the S1 emission traps (D-015 float formatting, QName content) do not
// apply in this increment.
package mediapackage

import (
	"context"
	"crypto/md5"
	_ "embed"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/cas"
	"ocng/internal/schemastep"
	"ocng/internal/search"
)

//go:embed schema.sql
var schema string

type Element struct {
	ID             string
	MediapackageID string
	Kind           string // track | catalog | attachment
	Flavor         string
	Mimetype       string
	SHA256         string
	SizeBytes      int64
	SourceURL      string
	CreatedAt      time.Time // row write time; the bytes are immutable after (ADR-008), so this is the element's effective Last-Modified — populated by GetElement (serve's If-Modified-Since, D-041)
}

// Migrate applies the mediapackage migration plan (serialised with all
// other ocng migrations on one advisory key — schemastep.AdvisoryKey, the
// same key engine.MigrateLocked uses).
//
// T2 (Option A, 2026-08-17): the baseline is ledger step 0 — applied once,
// then skipped without any DDL lock (the F2 fix: this schema's four
// ADD COLUMN IF NOT EXISTS against mp_element/publication used to take
// ACCESS EXCLUSIVE on the serve-read set at EVERY replica boot). It is a
// GUARDED step because those statements are metadata-AEL on serve-read-set
// tables (§5.3): on the one boot that applies it against a live table, the
// lock_timeout+retry envelope bounds any stall behind a long reader.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := schemastep.Run(ctx, pool, "mediapackage", MigrationSteps())
	return err
}

// MigrationSteps: step 0 is the baseline; steps 1–2 are the first real
// multi-step non-transactional migration (T2 done-condition 3). The sha256
// index is ADR-008 GC groundwork — mark-sweep needs element rows by hash —
// built CONCURRENTLY because mp_element is the serve-read set's largest
// table. The backfill is a deliberate no-op walk (it touches every row in
// bounded batches and changes nothing): it exercises the batched-dml
// machinery end to end where a real backfill will later run.
func MigrationSteps() []schemastep.Step {
	cursor := "" // resume re-derives work by restarting the walk (idempotent no-op)
	return []schemastep.Step{
		schemastep.GuardedDDL(0, "baseline", schema),
		schemastep.ConcurrentIndex(1, "sha256-index (ADR-008 GC groundwork)", "mp_element_sha256_idx",
			`create index concurrently mp_element_sha256_idx on mp_element (sha256)`),
		schemastep.BatchedDML(2, "sha256-backfill-noop", func(ctx context.Context, conn *pgxpool.Conn) (bool, error) {
			var next string
			var n int
			err := conn.QueryRow(ctx, `
				with batch as (
				    select id from mp_element where id::text > $1 order by id::text limit 500
				), upd as (
				    update mp_element e set size_bytes = e.size_bytes
				    from batch b where e.id = b.id
				    returning e.id
				)
				select coalesce(max(id::text), ''), count(*) from upd`, cursor).Scan(&next, &n)
			if err != nil {
				return false, err
			}
			if n == 0 {
				return true, nil
			}
			cursor = next
			return false, nil
		}),
		// T4: the delete tombstone — the dated retraction
		// signal a conformant consumer reads (legacy Opencast keeps the
		// oc_search/oc_series row with deletion_date). Nullable adds on
		// mediapackage and series, both OFF the serve-read set → metadata-AEL
		// off-set, the UNCONSTRAINED case; the second forward exercise of the
		// T2 discipline (T3's task-resource-spec was the first). Verified
		// against the live classifier by TestTombstoneMigrationForwardProof,
		// not assumed. Retraction itself touches the serve-read set only via
		// ordinary DML (publication row DELETE), which is not a migration.
		schemastep.TxDDL(3, "t4-tombstone", `
			alter table mediapackage add column if not exists deleted_at timestamptz;
			alter table series       add column if not exists deleted_at timestamptz`),
	}
}

// ---- manifest shape (read-only; local-name matching, see package note) ----

type xmlChecksum struct {
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}

type xmlElement struct {
	ID       string      `xml:"id,attr"`
	Type     string      `xml:"type,attr"` // the flavor
	Mimetype string      `xml:"mimetype"`
	URL      string      `xml:"url"`
	Size     int64       `xml:"size"`
	Checksum xmlChecksum `xml:"checksum"`
	Tags     []string    `xml:"tags>tag"`
}

type xmlManifest struct {
	XMLName     xml.Name     `xml:"mediapackage"`
	ID          string       `xml:"id,attr"`
	Start       string       `xml:"start,attr"`
	Duration    int64        `xml:"duration,attr"`
	Title       string       `xml:"title"`
	Tracks      []xmlElement `xml:"media>track"`
	Catalogs    []xmlElement `xml:"metadata>catalog"`
	Attachments []xmlElement `xml:"attachments>attachment"`
}

// ---- the manifest model: what both front-ends (loader, ingest) produce ----

// ManifestElement is one element of a Manifest, pre-materialisation: a
// reference to bytes (URL, resolved by the caller's resolver) plus the
// metadata that becomes the element row.
type ManifestElement struct {
	ID       string // element id (fixture-carried for the loader, server-minted for ingest)
	Kind     string // track | catalog | attachment
	Flavor   string
	Mimetype string
	URL      string
	MD5      string // optional; verified against the resolved bytes when set
	Tags     []string
}

// Manifest is the materialisation input: the parsed form of an archived
// manifest (loader) or of the accumulated bearer document (ingest).
type Manifest struct {
	ID         string
	Title      string
	Start      *time.Time
	DurationMS int64
	Elements   []ManifestElement
}

// Load parses an archived manifest, resolves each element URL to bytes via
// resolve, verifies them against the manifest's own md5 checksum where one
// is present (a wrong resolver mapping must fail loudly, not load garbage),
// stores them in CAS, and records the mediapackage and its elements.
// Idempotent: re-loading the same manifest is a no-op (same ids, same
// hashes). Returns the mediapackage id from the manifest.
//
// Load is one of two front-ends of Materialise — the other is the ingest
// surface. Convergence between the two paths is structural because they
// share this single write path (increment 3's done-condition).
func Load(ctx context.Context, pool *pgxpool.Pool, store *cas.Store, manifestPath string, resolve func(url string) (io.ReadCloser, error)) (string, error) {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", fmt.Errorf("loader: %w", err)
	}
	manifest, err := ParseManifest(raw)
	if err != nil {
		return "", fmt.Errorf("loader: parsing %s: %w", manifestPath, err)
	}
	if _, err := Materialise(ctx, pool, store, manifest, resolve); err != nil {
		return "", fmt.Errorf("loader: %w", err)
	}
	return manifest.ID, nil
}

// ParseManifest parses mediapackage XML — an archived manifest or an
// in-flight bearer document — into the Manifest model. Local-name matching
// (see the package note): default-ns, ns2:, oc: and mp: shapes all parse.
func ParseManifest(raw []byte) (Manifest, error) {
	var m xmlManifest
	if err := xml.Unmarshal(raw, &m); err != nil {
		return Manifest{}, err
	}
	if m.ID == "" {
		return Manifest{}, fmt.Errorf("manifest has no mediapackage id")
	}

	var start *time.Time
	if m.Start != "" {
		ts, err := time.Parse(time.RFC3339, m.Start)
		if err != nil {
			// An unparseable start date is refused rather than
			// silently dropped (CONTRACTS §2.2): a fixture feeder
			// has no business guessing.
			return Manifest{}, fmt.Errorf("manifest start %q: %w", m.Start, err)
		}
		start = &ts
	}

	manifest := Manifest{ID: m.ID, Title: m.Title, Start: start, DurationMS: m.Duration}
	type kinded struct {
		kind string
		els  []xmlElement
	}
	for _, group := range []kinded{
		{"track", m.Tracks}, {"catalog", m.Catalogs}, {"attachment", m.Attachments},
	} {
		for _, el := range group.els {
			me := ManifestElement{
				ID: el.ID, Kind: group.kind, Flavor: el.Type,
				Mimetype: el.Mimetype, URL: el.URL, Tags: el.Tags,
			}
			if el.Checksum.Type == "md5" {
				me.MD5 = el.Checksum.Value
			}
			manifest.Elements = append(manifest.Elements, me)
		}
	}
	return manifest, nil
}

// Materialise is THE write path: it records the mediapackage row and, per
// element, resolves the bytes, verifies the optional md5, stores them in
// CAS and writes the element row. Both the loader and the ingest surface
// call it — there is deliberately no second implementation. Idempotent per
// (mediapackage id, element id). Returns the mediapackage id.
func Materialise(ctx context.Context, pool *pgxpool.Pool, store *cas.Store, m Manifest, resolve func(url string) (io.ReadCloser, error)) (string, error) {
	if m.ID == "" {
		return "", fmt.Errorf("materialise: manifest has no mediapackage id")
	}
	// The mediapackage row and its search projection commit in ONE
	// transaction (engine I3 posture: a projection reflects exactly the
	// committed state, no window). Assembly finding A3: this write path
	// never projected, so ingested events were invisible to every list
	// surface until a Rebuild. Elements are not projected columns, so the
	// per-element writes below stay outside this transaction.
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			insert into mediapackage (id, title, start_time, duration_ms)
			values ($1, nullif($2,''), $3, nullif($4,0))
			on conflict (id) do nothing`,
			m.ID, m.Title, m.Start, m.DurationMS); err != nil {
			return err
		}
		return search.ProjectEvent(ctx, tx, m.ID)
	}); err != nil {
		return "", fmt.Errorf("materialise: %w", err)
	}
	for _, el := range m.Elements {
		if err := materialiseElement(ctx, pool, store, m.ID, el, resolve); err != nil {
			return "", fmt.Errorf("materialise: element %s (%s): %w", el.ID, el.Flavor, err)
		}
	}
	return m.ID, nil
}

func materialiseElement(ctx context.Context, pool *pgxpool.Pool, store *cas.Store, mpID string, el ManifestElement, resolve func(url string) (io.ReadCloser, error)) error {
	r, err := resolve(el.URL)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp("", "ocng-load-*"+filepath.Ext(el.URL))
	if err != nil {
		r.Close()
		return err
	}
	defer os.Remove(tmp.Name())
	h := md5.New()
	size, err := io.Copy(io.MultiWriter(tmp, h), r)
	r.Close()
	tmp.Close()
	if err != nil {
		return err
	}
	if el.MD5 != "" {
		if got := hex.EncodeToString(h.Sum(nil)); got != el.MD5 {
			return fmt.Errorf("resolved bytes md5 %s != manifest checksum %s (wrong resolver mapping?)", got, el.MD5)
		}
	}

	sum, err := store.PutFile(ctx, tmp.Name())
	if err != nil {
		return err
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := insertElement(ctx, tx, Element{
		ID: el.ID, MediapackageID: mpID, Kind: el.Kind, Flavor: el.Flavor,
		Mimetype: el.Mimetype, SHA256: sum, SizeBytes: size, SourceURL: el.URL,
	}, el.Tags, true); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// InsertElement records a new element inside the caller's transaction —
// this is the mutation the worker passes to engine.CompleteTask so element
// row and task completion commit together.
func InsertElement(ctx context.Context, tx pgx.Tx, el Element, tags []string) error {
	return insertElement(ctx, tx, el, tags, false)
}

func insertElement(ctx context.Context, tx pgx.Tx, el Element, tags []string, idempotent bool) error {
	conflict := ""
	if idempotent {
		conflict = "on conflict (id) do nothing"
	}
	if _, err := tx.Exec(ctx, `
		insert into mp_element (id, mediapackage_id, kind, flavor, mimetype, sha256, size_bytes, source_url)
		values ($1,$2,$3,$4,nullif($5,''),$6,$7,nullif($8,'')) `+conflict,
		el.ID, el.MediapackageID, el.Kind, el.Flavor, el.Mimetype, el.SHA256, el.SizeBytes, el.SourceURL); err != nil {
		return err
	}
	for _, tag := range tags {
		if _, err := tx.Exec(ctx, `
			insert into mp_element_tag (element_id, tag) values ($1,$2)
			on conflict do nothing`, el.ID, tag); err != nil {
			return err
		}
	}
	return nil
}

// Elements lists a mediapackage's element rows.
func Elements(ctx context.Context, pool *pgxpool.Pool, mediapackageID string) ([]Element, error) {
	rows, err := pool.Query(ctx, `
		select id, mediapackage_id, kind, flavor, coalesce(mimetype,''),
		       sha256, size_bytes, coalesce(source_url,'')
		from mp_element where mediapackage_id = $1 order by created_at, id`,
		mediapackageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Element
	for rows.Next() {
		var el Element
		if err := rows.Scan(&el.ID, &el.MediapackageID, &el.Kind, &el.Flavor,
			&el.Mimetype, &el.SHA256, &el.SizeBytes, &el.SourceURL); err != nil {
			return nil, err
		}
		out = append(out, el)
	}
	return out, rows.Err()
}

// ElementTags returns every element's tags for one mediapackage,
// keyed by element id.
func ElementTags(ctx context.Context, pool *pgxpool.Pool, mediapackageID string) (map[string][]string, error) {
	rows, err := pool.Query(ctx, `
		select t.element_id, t.tag from mp_element_tag t
		join mp_element e on e.id = t.element_id
		where e.mediapackage_id = $1 order by t.tag`, mediapackageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var id, tag string
		if err := rows.Scan(&id, &tag); err != nil {
			return nil, err
		}
		out[id] = append(out[id], tag)
	}
	return out, rows.Err()
}

// GetElement fetches one element row by id.
func GetElement(ctx context.Context, pool *pgxpool.Pool, id string) (Element, error) {
	var el Element
	err := pool.QueryRow(ctx, `
		select id, mediapackage_id, kind, flavor, coalesce(mimetype,''),
		       sha256, size_bytes, coalesce(source_url,''), created_at
		from mp_element where id = $1`, id).
		Scan(&el.ID, &el.MediapackageID, &el.Kind, &el.Flavor,
			&el.Mimetype, &el.SHA256, &el.SizeBytes, &el.SourceURL, &el.CreatedAt)
	return el, err
}

// FlavorMatches reports whether flavor (e.g. "presentation/source") matches
// a pattern that may use '*' per part ("*/source"). This mirrors legacy
// Opencast's MediaPackageElementFlavor.matches wildcard semantics for the
// subset increment 1 needs.
func FlavorMatches(pattern, flavor string) bool {
	pp := strings.SplitN(pattern, "/", 2)
	fp := strings.SplitN(flavor, "/", 2)
	if len(pp) != 2 || len(fp) != 2 {
		return pattern == flavor
	}
	return (pp[0] == "*" || pp[0] == fp[0]) && (pp[1] == "*" || pp[1] == fp[1])
}
