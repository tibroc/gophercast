// Package migrate is increment 6: read a source Opencast archive through its
// AUTHORITATIVE representations only, write the ocng target (CAS + the
// increments 1–5 data model, additively), verify by the two-diff path — and
// never, under any input, write the source (ADR-008 zero exceptions;
// rollback is repoint, not restore).
//
// The HTTP ACL read paths (GET .../acl, the withacl list endpoints) are not
// authoritative representations of stored policy, so they are excluded BY
// CONSTRUCTION: this package imports no HTTP client and takes no source-system
// URL. It reads database-column representations and archive bytes.
package migrate

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"ocng/internal/acl"
)

// SnapshotRow is one OC_ASSETS_SNAPSHOT row: the authoritative per-version
// mediapackage (every runtime consumer parses this column; on the increment-6
// reference corpus it is byte-identical to manifest.xml on all 64 versions,
// so the column IS the record).
type SnapshotRow struct {
	MediapackageID string
	Version        int
	Org            string
	Availability   string
	XML            []byte
}

// SeriesRow is one OC_SERIES row. ACLNull distinguishes the ABSENT state
// (NULL column) from a stored-but-empty ACL (D-032).
type SeriesRow struct {
	ID           string
	Org          string
	DeletionDate string
	ACLNull      bool
	ACLXML       []byte
	DublinCore   []byte
}

// PublishedRow is one OC_SEARCH row: the published mediapackage and the
// published ACL — its OWN data class, never derived from or reconciled with
// the archive ACL.
type PublishedRow struct {
	ID           string
	Org          string
	SeriesID     string
	DeletionDate string
	ACLNull      bool
	ACLXML       []byte
	XML          []byte
}

// ManagedACL is one managed-ACL template row — report-only in this increment
// (no target feature consumes templates; ADR-005 rule 1).
type ManagedACL struct {
	Org  string
	Name string
}

// SourceReader is the migration's entire view of a source installation. A
// fixture backend exists now (the reference-corpus export); a live-DB backend for real
// adopters (H2 / MariaDB, read-only credentials) is deferred adopter work.
type SourceReader interface {
	Label() string
	Snapshots() ([]SnapshotRow, error)
	Series() ([]SeriesRow, error)
	Published() ([]PublishedRow, error)
	// EpisodeEAV returns the asset-manager security properties (the
	// enforcement copy) per mediapackage — the cross-check against the
	// XACML resolution (a mismatch is a per-record HOLD).
	EpisodeEAV() (map[string][]acl.Entry, error)
	ManagedACLs() ([]ManagedACL, error)
	// MergeMode returns the XACMLAuthorizationService merge.mode in effect —
	// part of the ACL's meaning.
	MergeMode() (string, error)
	// Resolve maps a source element URL (urn:matterhorn:… or …/static/…) to
	// its bytes. Read-only by construction.
	Resolve(url string) (io.ReadCloser, error)
}

// FixtureSource reads the reference-corpus export layout: db/exports/*.csv
// for the columns, snapshots/<mp>/<v>/mediapackage.xml for the per-version
// XML (byte-identical to the column — cross-checked here again), and
// source/{archive,downloads} for element bytes.
type FixtureSource struct {
	Dir string
	Org string // the organisation whose archive paths this source resolves
}

func (f *FixtureSource) Label() string { return "fixture:" + f.Dir }

func (f *FixtureSource) readCSV(rel string) ([]map[string]string, error) {
	fh, err := os.Open(filepath.Join(f.Dir, rel))
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	r := csv.NewReader(fh)
	recs, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	if len(recs) == 0 {
		return nil, fmt.Errorf("%s: empty", rel)
	}
	var out []map[string]string
	for _, rec := range recs[1:] {
		row := map[string]string{}
		for i, h := range recs[0] {
			row[h] = rec[i]
		}
		out = append(out, row)
	}
	return out, nil
}

func (f *FixtureSource) Snapshots() ([]SnapshotRow, error) {
	rows, err := f.readCSV("db/exports/snapshots.csv")
	if err != nil {
		return nil, err
	}
	var out []SnapshotRow
	for _, r := range rows {
		var v int
		if _, err := fmt.Sscanf(r["VERSION"], "%d", &v); err != nil {
			return nil, fmt.Errorf("snapshot %s: version %q: %w", r["MEDIAPACKAGE_ID"], r["VERSION"], err)
		}
		s := SnapshotRow{
			MediapackageID: r["MEDIAPACKAGE_ID"], Version: v,
			Org: r["ORGANIZATION_ID"], Availability: r["AVAILABILITY"],
			XML: []byte(r["MEDIAPACKAGE_XML"]),
		}
		// The fixture's per-version file was extracted from this same column;
		// a divergence means fixture corruption — abort, never guess.
		file := filepath.Join(f.Dir, "snapshots", s.MediapackageID, fmt.Sprint(v), "mediapackage.xml")
		if banked, err := os.ReadFile(file); err == nil && !bytes.Equal(banked, s.XML) {
			return nil, fmt.Errorf("snapshot %s v%d: per-version file diverges from the exported column", s.MediapackageID, v)
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].MediapackageID != out[j].MediapackageID {
			return out[i].MediapackageID < out[j].MediapackageID
		}
		return out[i].Version < out[j].Version
	})
	return out, nil
}

func (f *FixtureSource) Series() ([]SeriesRow, error) {
	rows, err := f.readCSV("db/exports/series.csv")
	if err != nil {
		return nil, err
	}
	var out []SeriesRow
	for _, r := range rows {
		out = append(out, SeriesRow{
			ID: r["ID"], Org: r["ORGANIZATION"], DeletionDate: r["DELETION_DATE"],
			ACLNull: r["ACL_IS_NULL"] == "YES", ACLXML: []byte(r["ACCESS_CONTROL"]),
			DublinCore: []byte(r["DUBLIN_CORE"]),
		})
	}
	return out, nil
}

func (f *FixtureSource) Published() ([]PublishedRow, error) {
	rows, err := f.readCSV("db/exports/search.csv")
	if err != nil {
		return nil, err
	}
	var out []PublishedRow
	for _, r := range rows {
		out = append(out, PublishedRow{
			ID: r["ID"], Org: r["ORGANIZATION"], SeriesID: r["SERIES_ID"],
			DeletionDate: r["DELETION_DATE"],
			ACLNull:      r["ACL_IS_NULL"] == "YES", ACLXML: []byte(r["ACCESS_CONTROL"]),
			XML: []byte(r["MEDIAPACKAGE_XML"]),
		})
	}
	return out, nil
}

func (f *FixtureSource) EpisodeEAV() (map[string][]acl.Entry, error) {
	rows, err := f.readCSV("db/exports/properties.csv")
	if err != nil {
		return nil, err
	}
	out := map[string][]acl.Entry{}
	for _, r := range rows {
		if r["NAMESPACE"] != "org.opencastproject.assetmanager.security" {
			continue
		}
		// PROPERTY_NAME is "ROLE | action"; VAL_BOOL is the allow flag.
		// This projection is keyed on (role, action), so an
		// allow+deny pair CANNOT coexist here — which is exactly why it is
		// the cross-check and never the source.
		parts := strings.SplitN(r["PROPERTY_NAME"], " | ", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("eav property %q: not 'ROLE | action'", r["PROPERTY_NAME"])
		}
		out[r["MEDIAPACKAGE_ID"]] = append(out[r["MEDIAPACKAGE_ID"]], acl.Entry{
			Role: parts[0], Action: parts[1], Allow: strings.EqualFold(r["VAL_BOOL"], "TRUE"),
		})
	}
	return out, nil
}

func (f *FixtureSource) ManagedACLs() ([]ManagedACL, error) {
	rows, err := f.readCSV("db/exports/managed-acls.csv")
	if err != nil {
		return nil, err
	}
	var out []ManagedACL
	for _, r := range rows {
		out = append(out, ManagedACL{Org: r["ORGANIZATION_ID"], Name: r["NAME"]})
	}
	return out, nil
}

func (f *FixtureSource) MergeMode() (string, error) {
	raw, err := os.ReadFile(filepath.Join(f.Dir, "config/XACMLAuthorizationService.cfg"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "merge.mode") {
			kv := strings.SplitN(line, "=", 2)
			if len(kv) == 2 {
				return strings.TrimSpace(kv[1]), nil
			}
		}
	}
	// all keys commented = shipped default = episode overrides series
	return "override", nil
}

// Resolve maps the two source URL shapes to fixture bytes, a rule verified
// over every element of the reference corpus (zero unresolved):
//
//	urn:matterhorn:<mp>:<v>:<element>:<filename> → source/archive/<org>/<mp>/<v>/<element><ext>
//	http(s)://<host>/static/<path>               → source/downloads/<path>
func (f *FixtureSource) Resolve(url string) (io.ReadCloser, error) {
	if strings.HasPrefix(url, "urn:matterhorn:") {
		parts := strings.Split(strings.TrimPrefix(url, "urn:matterhorn:"), ":")
		if len(parts) != 4 {
			return nil, fmt.Errorf("unresolvable urn %q", url)
		}
		mp, v, el, filename := parts[0], parts[1], parts[2], parts[3]
		p := filepath.Join(f.Dir, "source", "archive", f.Org, mp, v, el+path.Ext(filename))
		return os.Open(p)
	}
	if i := strings.Index(url, "/static/"); i >= 0 && (strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")) {
		p := filepath.Join(f.Dir, "source", "downloads", filepath.FromSlash(url[i+len("/static/"):]))
		return os.Open(p)
	}
	return nil, fmt.Errorf("unresolvable element url %q (neither urn:matterhorn nor /static shape)", url)
}
