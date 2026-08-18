// Run: read source (authoritative representations only) → write target
// (CAS + the increments 1–5 model, additively, through the existing write
// paths) → the caller verifies (the two-diff path + the after-hash).
// Per-tenant (ADR-010): one Run migrates ONE organisation; its org value is
// dropped from every target row and reported as dropped (D-010).
package migrate

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/acl"
	"ocng/internal/cas"
	"ocng/internal/mediapackage"
	"ocng/internal/ops"
	"ocng/internal/search"
)

type Result struct {
	RunID    int64
	Events   int
	Series   int
	Versions int
	Objects  int
	Holds    int
}

// Run migrates one organisation from src into the target pool + CAS store.
// Idempotent: CAS puts are content-addressed, rows are keyed by natural ids;
// a re-run converges. It writes ONLY the target — the SourceReader is the
// package's entire read surface and has no write methods.
func Run(ctx context.Context, pool *pgxpool.Pool, store *cas.Store, src SourceReader, org string) (*Result, error) {
	rep, err := newReporter(ctx, pool, org, src.Label())
	if err != nil {
		return nil, err
	}
	res := &Result{RunID: rep.runID}
	if err := run(ctx, pool, store, src, org, rep, res); err != nil {
		_ = rep.finish(ctx, res, "failed: "+err.Error())
		return nil, err
	}
	res.Holds = rep.holds
	outcome := "complete"
	if rep.holds > 0 {
		outcome = "complete-with-holds"
	}
	if err := rep.finish(ctx, res, outcome); err != nil {
		return nil, err
	}
	return res, nil
}

func run(ctx context.Context, pool *pgxpool.Pool, store *cas.Store, src SourceReader, org string, rep *reporter, res *Result) error {
	mergeMode, err := src.MergeMode()
	if err != nil {
		return fmt.Errorf("merge.mode: %w", err)
	}

	snaps, err := src.Snapshots()
	if err != nil {
		return err
	}
	seriesRows, err := src.Series()
	if err != nil {
		return err
	}
	published, err := src.Published()
	if err != nil {
		return err
	}
	eav, err := src.EpisodeEAV()
	if err != nil {
		return err
	}
	managed, err := src.ManagedACLs()
	if err != nil {
		return err
	}

	// ---- the per-tenant filter: this run's org migrates, its value drops
	// (reported); other orgs are skipped (reported), untouched, unmigrated.
	skipped := map[string]int{}
	var mySnaps []SnapshotRow
	for _, s := range snaps {
		if s.Org == org {
			mySnaps = append(mySnaps, s)
		} else {
			skipped[s.Org]++
		}
	}
	nSeries, nPub, nTmpl := 0, 0, 0
	for _, s := range seriesRows {
		if s.Org == org {
			nSeries++
		} else {
			skipped[s.Org]++
		}
	}
	for _, p := range published {
		if p.Org == org {
			nPub++
		} else {
			skipped[p.Org]++
		}
	}
	for _, m := range managed {
		if m.Org == org {
			nTmpl++
		} else {
			skipped[m.Org]++
		}
	}
	if err := rep.line(ctx, "organization-dropped", org, fmt.Sprintf(
		"organization=%s dropped from %d snapshot rows, %d series, %d published, %d managed-acl templates (ADR-010: the target has no organisation field)",
		org, len(mySnaps), nSeries, nPub, nTmpl)); err != nil {
		return err
	}
	for other, n := range skipped {
		if err := rep.line(ctx, "organization-skipped", other, fmt.Sprintf(
			"%d rows of organization=%s left unmigrated — a separate per-tenant run migrates them into their own instance (ADR-010)", n, other)); err != nil {
			return err
		}
	}

	// ---- series first (events reference them; series_title projects from them)
	for _, s := range seriesRows {
		if s.Org != org {
			continue
		}
		if s.DeletionDate != "" {
			if err := rep.hold(ctx, s.ID, "series soft-deleted (DELETION_DATE set) — semantics unexercised on the reference corpus, human decision required"); err != nil {
				return err
			}
			continue
		}
		if err := migrateSeries(ctx, pool, s, rep); err != nil {
			return fmt.Errorf("series %s: %w", s.ID, err)
		}
		res.Series++
	}

	// ---- events: group snapshots per mediapackage
	byMP := map[string][]SnapshotRow{}
	for _, s := range mySnaps {
		byMP[s.MediapackageID] = append(byMP[s.MediapackageID], s)
	}
	ids := make([]string, 0, len(byMP))
	for id := range byMP {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	pubByID := map[string]PublishedRow{}
	for _, p := range published {
		if p.Org == org {
			pubByID[p.ID] = p
		}
	}
	for _, id := range ids {
		versions := byMP[id]
		sort.Slice(versions, func(i, j int) bool { return versions[i].Version < versions[j].Version })
		if err := migrateEvent(ctx, pool, store, src, versions, eav[id], mergeMode, rep, res); err != nil {
			return fmt.Errorf("event %s: %w", id, err)
		}
		if p, ok := pubByID[id]; ok {
			if err := migratePublication(ctx, pool, store, src, p, rep, res); err != nil {
				return fmt.Errorf("event %s publication: %w", id, err)
			}
		}
		res.Events++
	}

	// ---- managed-ACL templates: report-only (ratified; no target consumer)
	for _, m := range managed {
		if m.Org != org {
			continue
		}
		if err := rep.line(ctx, "managed-acl-template", m.Name,
			"template recorded, not migrated — no target feature consumes managed-ACL templates (ADR-005 rule 1)"); err != nil {
			return err
		}
	}
	return nil
}

// ---- series ------------------------------------------------------------------

func migrateSeries(ctx context.Context, pool *pgxpool.Pool, s SeriesRow, rep *reporter) error {
	dc, err := parseDC(s.DublinCore)
	if err != nil {
		return err
	}
	created, err := dcTime(dc, "created")
	if err != nil {
		return err
	}
	if err := mediapackage.PutSeries(ctx, pool, s.ID, mediapackage.SeriesMetadata{
		Title:        dcFirst(dc, "title"),
		Organizers:   dc["creator"],
		Contributors: dc["contributor"],
		Language:     dcFirst(dc, "language"),
		Description:  dcFirst(dc, "description"),
		Subjects:     dc["subject"],
		Created:      created,
	}); err != nil {
		return err
	}
	// Series ACL: OC_SERIES.ACCESS_CONTROL is the one representation not
	// derived from attachments. NULL = ABSENT: no policy row,
	// never synthesized (D-032).
	if s.ACLNull {
		return rep.line(ctx, "acl-absent", s.ID, "series has no ACL anywhere — migrated as ABSENT (D-032), reported by name")
	}
	entries, err := parsePlainACL(s.ACLXML)
	if err != nil {
		return err
	}
	return search.SetACL(ctx, pool, acl.ScopeSeries, s.ID, entries)
}

// ---- one event, all versions ---------------------------------------------------

func migrateEvent(ctx context.Context, pool *pgxpool.Pool, store *cas.Store, src SourceReader,
	versions []SnapshotRow, eavEntries []acl.Entry, mergeMode string, rep *reporter, res *Result) error {

	mpID := versions[0].MediapackageID
	latest := versions[len(versions)-1]
	latestDoc, err := parseDocument(latest.XML)
	if err != nil {
		return err
	}

	// -- latest operable state first, through THE write path (Materialise):
	//    every later projection (ACL, metadata, publication) re-derives from
	//    this row, so it must exist before anything projects.
	manifest, err := docToManifest(latestDoc)
	if err != nil {
		return err
	}
	nSecurity := 0
	for _, el := range latestDoc.Elements {
		if el.IsSecurityXACML() {
			nSecurity++
		}
	}
	if nSecurity > 0 {
		if err := rep.line(ctx, "acl-attachment-classified", mpID, fmt.Sprintf(
			"%d security-XACML attachment(s) classified as ACL representation: meaning migrated to acl_entry, bytes preserved in CAS + verbatim source manifest — never an operable element row", nSecurity)); err != nil {
			return err
		}
	}
	if _, err := mediapackage.Materialise(ctx, pool, store, manifest, src.Resolve); err != nil {
		return err
	}
	if err := setEventMetadata(ctx, pool, src, latestDoc); err != nil {
		return err
	}

	// -- the authoritative archive ACL, latest snapshot
	resolved, err := resolveArchiveACL(latestDoc, src.Resolve, mergeMode)
	if err != nil {
		return rep.hold(ctx, mpID, "archive ACL unresolvable the authoritative way: "+err.Error())
	}
	switch resolved.State {
	case "PRESENT":
		if !entrySetEqual(resolved.Entries, eavEntries) {
			if err := rep.hold(ctx, mpID, fmt.Sprintf(
				"XACML-vs-EAV mismatch: resolved [%s] vs enforcement copy [%s] — the two representations claim different policies",
				entriesString(resolved.Entries), entriesString(eavEntries))); err != nil {
				return err
			}
		} else {
			if err := search.SetACL(ctx, pool, acl.ScopeEvent, mpID, resolved.Entries); err != nil {
				return err
			}
		}
	case "ABSENT":
		if len(eavEntries) > 0 {
			if err := rep.hold(ctx, mpID, fmt.Sprintf(
				"no XACML attachment but %d EAV enforcement rows exist — representations disagree on whether a policy exists", len(eavEntries))); err != nil {
				return err
			}
		} else if err := rep.line(ctx, "acl-absent", mpID,
			"event has no ACL anywhere — migrated as ABSENT (D-032), reported by name, never synthesized"); err != nil {
			return err
		}
	}

	// -- every version: bytes into CAS, URL into the repoint map, the
	//    canonical manifest AND the verbatim source XML per version
	nInSnapshotPubs := 0
	for _, v := range versions {
		if v.Availability != "" && v.Availability != "ONLINE" {
			if err := rep.hold(ctx, mpID, fmt.Sprintf("version %d availability %q — OFFLINE semantics unexercised on the reference corpus", v.Version, v.Availability)); err != nil {
				return err
			}
			continue
		}
		doc := latestDoc
		if v.Version != latest.Version {
			if doc, err = parseDocument(v.XML); err != nil {
				return fmt.Errorf("v%d: %w", v.Version, err)
			}
		}
		nInSnapshotPubs += len(doc.Publications)

		all := append([]docElement{}, doc.Elements...)
		for _, p := range doc.Publications {
			all = append(all, p.Elements...)
		}
		for _, el := range all {
			if el.URL == "" {
				continue
			}
			sha, err := putElementBytes(ctx, store, src, el)
			if err != nil {
				return fmt.Errorf("v%d element %s (%s): %w", v.Version, el.ID, el.Flavor, err)
			}
			res.Objects++
			if err := recordURL(ctx, pool, rep, urlMapRow{
				URL: el.URL, MP: mpID, Version: v.Version, ElementID: el.ID,
				Kind: el.Kind, Flavor: el.Flavor, SHA256: sha,
			}); err != nil {
				return err
			}
		}

		// canonical manifest = the operable element set of this version
		cm := ops.SnapshotManifest{MediapackageID: mpID, Title: doc.Title, DurationMS: doc.DurationMS}
		for _, el := range doc.Elements {
			if el.IsSecurityXACML() {
				continue
			}
			var sha string
			if err := pool.QueryRow(ctx,
				`select sha256 from migration_url_map where old_url=$1`, el.URL).Scan(&sha); err != nil {
				return fmt.Errorf("v%d: element %s has no recorded hash: %w", v.Version, el.URL, err)
			}
			tags := append([]string(nil), el.Tags...)
			sort.Strings(tags)
			cm.Elements = append(cm.Elements, ops.SnapshotElement{
				ID: el.ID, Kind: el.Kind, Flavor: el.Flavor, Mimetype: el.Mimetype,
				SHA256: sha, SizeBytes: el.Size, Tags: tags,
			})
		}
		canonical, err := cm.Canonical()
		if err != nil {
			return err
		}
		manifestSha, err := putBytes(ctx, store, canonical)
		if err != nil {
			return err
		}
		srcSha, err := putBytes(ctx, store, v.XML) // D-010: the source document, verbatim
		if err != nil {
			return err
		}
		res.Objects += 2
		if _, err := pool.Exec(ctx, `
			insert into mp_snapshot (mediapackage_id, version, manifest_sha256, source_manifest_sha256)
			values ($1,$2,$3,$4)
			on conflict (mediapackage_id, version) do update set
			  manifest_sha256=excluded.manifest_sha256,
			  source_manifest_sha256=excluded.source_manifest_sha256`,
			mpID, v.Version, manifestSha, srcSha); err != nil {
			return err
		}
		res.Versions++
	}
	if nInSnapshotPubs > 0 {
		if err := rep.line(ctx, "in-snapshot-publication-preserved", mpID, fmt.Sprintf(
			"%d in-snapshot publication container(s) across versions — not representable in the flat manifest, preserved verbatim via source_manifest_sha256 (D-010); their element bytes are in CAS and migration_url_map", nInSnapshotPubs)); err != nil {
			return err
		}
	}
	return nil
}

func docToManifest(doc document) (mediapackage.Manifest, error) {
	m := mediapackage.Manifest{ID: doc.ID, Title: doc.Title, DurationMS: doc.DurationMS}
	if doc.Start != "" {
		ts, err := time.Parse(time.RFC3339, doc.Start)
		if err != nil {
			return m, fmt.Errorf("start %q: %w", doc.Start, err)
		}
		m.Start = &ts
	}
	for _, el := range doc.Elements {
		if el.IsSecurityXACML() {
			continue
		}
		m.Elements = append(m.Elements, mediapackage.ManifestElement{
			ID: el.ID, Kind: el.Kind, Flavor: el.Flavor, Mimetype: el.Mimetype,
			URL: el.URL, MD5: el.MD5, Tags: el.Tags,
		})
	}
	return m, nil
}

func setEventMetadata(ctx context.Context, pool *pgxpool.Pool, src SourceReader, doc document) error {
	var dcRaw []byte
	for _, el := range doc.Elements {
		if el.Kind == "catalog" && el.Flavor == "dublincore/episode" {
			r, err := src.Resolve(el.URL)
			if err != nil {
				return err
			}
			b, err := io.ReadAll(r)
			r.Close()
			if err != nil {
				return err
			}
			dcRaw = b
			break
		}
	}
	md := mediapackage.Metadata{SeriesID: doc.SeriesID}
	if dcRaw != nil {
		dc, err := parseDC(dcRaw)
		if err != nil {
			return err
		}
		created, err := dcTime(dc, "created")
		if err != nil {
			return err
		}
		md.Creators = dc["creator"]
		md.Contributors = dc["contributor"]
		md.Language = dcFirst(dc, "language")
		md.Description = dcFirst(dc, "description")
		md.Subjects = dc["subject"]
		md.Location = dcFirst(dc, "spatial")
		md.License = dcFirst(dc, "license")
		md.Created = created
	}
	return mediapackage.SetMetadata(ctx, pool, doc.ID, md)
}

// ---- the published record (OC_SEARCH): its own data class --------------------

func migratePublication(ctx context.Context, pool *pgxpool.Pool, store *cas.Store, src SourceReader,
	p PublishedRow, rep *reporter, res *Result) error {

	if p.DeletionDate != "" {
		return rep.hold(ctx, p.ID, "publication retracted (DELETION_DATE set) — soft-delete semantics unexercised on the reference corpus")
	}

	// The published ACL, from OC_SEARCH.ACCESS_CONTROL — never derived from
	// the archive ACL, never reconciled.
	state := "ABSENT"
	pin := []string{}
	if p.ACLNull {
		if err := rep.line(ctx, "published-acl-null-semantics", p.ID,
			"NULL published ACL: the legacy system treated this as unrestricted on engage single-get; the target's ABSENT state denies (D-028, decided BREAK) — the state survives, the interpretation changes"); err != nil {
			return err
		}
	} else {
		entries, err := parsePlainACL(p.ACLXML)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if !e.Allow {
				// Armed guard: the pin (a read-role array) cannot
				// represent a deny — a stored-model finding, never a
				// workaround.
				return rep.hold(ctx, p.ID, fmt.Sprintf(
					"published ACL contains a DENY (%s|%s) — unrepresentable in the publication pin; STORED-MODEL FINDING, raise as a finding", e.Role, e.Action))
			}
		}
		if len(entries) == 0 {
			state = "EMPTY"
		} else {
			state = "POPULATED"
			seen := map[string]bool{}
			for _, e := range entries {
				if e.Action == "read" && e.Allow && !seen[e.Role] {
					seen[e.Role] = true
					pin = append(pin, e.Role)
				}
			}
			sort.Strings(pin)
		}
	}

	// The published record, verbatim, into CAS (D-010 — it carries the
	// distribution URLs and the published element set as the legacy system
	// served them).
	recSha, err := putBytes(ctx, store, p.XML)
	if err != nil {
		return err
	}
	res.Objects++
	if err := rep.line(ctx, "publication-record-preserved", p.ID,
		"published mediapackage document preserved verbatim in CAS: sha256="+recSha); err != nil {
		return err
	}

	doc, err := parseDocument(p.XML)
	if err != nil {
		return err
	}
	// Published elements are REAL distinct bytes (distribution encodings,
	// not copies of archive elements) — they become element rows through the
	// same single write path, then publication references (ADR-008:
	// reference-based, never byte copies).
	pubManifest := mediapackage.Manifest{ID: p.ID}
	for _, el := range doc.Elements {
		if el.IsSecurityXACML() {
			continue
		}
		pubManifest.Elements = append(pubManifest.Elements, mediapackage.ManifestElement{
			ID: el.ID, Kind: el.Kind, Flavor: el.Flavor, Mimetype: el.Mimetype,
			URL: el.URL, MD5: el.MD5, Tags: el.Tags,
		})
	}
	if _, err := mediapackage.Materialise(ctx, pool, store, pubManifest, src.Resolve); err != nil {
		return err
	}
	// Every published element URL (security attachment included) lands in
	// the repoint map — "links stay the same" is served from these rows.
	for _, el := range doc.Elements {
		if el.URL == "" {
			continue
		}
		sha, err := putElementBytes(ctx, store, src, el)
		if err != nil {
			return fmt.Errorf("published element %s: %w", el.ID, err)
		}
		res.Objects++
		if err := recordURL(ctx, pool, rep, urlMapRow{
			URL: el.URL, MP: p.ID, ElementID: el.ID,
			Kind: el.Kind, Flavor: el.Flavor, SHA256: sha,
		}); err != nil {
			return err
		}
	}

	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			insert into publication (id, mediapackage_id, channel, acl_read, acl_state)
			values ($1,$2::uuid,$3,$4,$5)
			on conflict (mediapackage_id, channel) do update set
			  acl_read=excluded.acl_read, acl_state=excluded.acl_state`,
			uuid.NewString(), p.ID, "engage-player", pin, state); err != nil {
			return err
		}
		var pubID string
		if err := tx.QueryRow(ctx, `
			select id from publication where mediapackage_id=$1::uuid and channel=$2`,
			p.ID, "engage-player").Scan(&pubID); err != nil {
			return err
		}
		for _, el := range doc.Elements {
			if el.IsSecurityXACML() {
				continue
			}
			if _, err := tx.Exec(ctx, `
				insert into publication_element (publication_id, element_id)
				values ($1,$2) on conflict do nothing`, pubID, el.ID); err != nil {
				return err
			}
		}
		return search.ProjectEvent(ctx, tx, p.ID)
	})
}

// ---- byte plumbing -------------------------------------------------------------

// putElementBytes resolves one element's bytes, verifies the document's own
// md5 where present (a wrong resolver mapping must fail loudly), and stores
// them content-addressed.
func putElementBytes(ctx context.Context, store *cas.Store, src SourceReader, el docElement) (string, error) {
	r, err := src.Resolve(el.URL)
	if err != nil {
		return "", err
	}
	defer r.Close()
	tmp, err := os.CreateTemp("", "ocng-migrate-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	h := md5.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), r); err != nil {
		tmp.Close()
		return "", err
	}
	tmp.Close()
	if el.MD5 != "" {
		if got := hex.EncodeToString(h.Sum(nil)); got != el.MD5 {
			return "", fmt.Errorf("resolved bytes md5 %s != document checksum %s (wrong resolver mapping?)", got, el.MD5)
		}
	}
	return store.PutFile(ctx, tmp.Name())
}

func putBytes(ctx context.Context, store *cas.Store, b []byte) (string, error) {
	tmp, err := os.CreateTemp("", "ocng-migrate-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return "", err
	}
	tmp.Close()
	return store.PutFile(ctx, tmp.Name())
}

type urlMapRow struct {
	URL, MP, ElementID, Kind, Flavor, SHA256 string
	Version                                  int
}

// recordURL upserts the repoint row. The same URL recurring across versions
// (a stable /static distribution copy) must carry the same content — a
// hash flip for one URL would mean the "same link" served different bytes,
// which is a HOLD, not a silent overwrite.
func recordURL(ctx context.Context, pool *pgxpool.Pool, rep *reporter, r urlMapRow) error {
	tag, err := pool.Exec(ctx, `
		insert into migration_url_map (old_url, mediapackage_id, version, element_id, kind, flavor, sha256, run_id)
		values ($1,$2,$3,$4,$5,$6,$7,$8)
		on conflict (old_url) do nothing`,
		r.URL, r.MP, r.Version, r.ElementID, r.Kind, r.Flavor, r.SHA256, rep.runID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var existing string
		if err := pool.QueryRow(ctx,
			`select sha256 from migration_url_map where old_url=$1`, r.URL).Scan(&existing); err != nil {
			return err
		}
		if existing != r.SHA256 {
			return rep.hold(ctx, r.MP, fmt.Sprintf(
				"URL %s carries different bytes in different versions (%s vs %s) — one link cannot map to two contents", r.URL, existing, r.SHA256))
		}
	}
	return nil
}
