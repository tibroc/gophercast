package ingest

import (
	"encoding/xml"
	"regexp"
	"strings"
	"time"
)

// Episode-DublinCore derivation: at /ingest/ingest the mediapackage's title
// and start are derived from the DC catalog, matching legacy Opencast's
// MEASURED archive behaviour (the archived start is dcterms:temporal's
// start, not deposit time; title and creators likewise come from the DC).
//
// Local-name parsing, same posture as the mediapackage parser: prefix
// shapes vary in the wild, the namespace is what matters — and this reader
// never re-emits, so no D-015 concerns.

type dcCatalog struct {
	Title    string `xml:"title"`
	Temporal string `xml:"temporal"`
	Created  string `xml:"created"`
}

var dcTemporalStartRe = regexp.MustCompile(`start=([^;\s]+)\s*;`)

// dcDerive returns the title and start instant legacy Opencast derives from
// an episode DC catalog: dcterms:temporal's start= token when present,
// else dcterms:created, else nil (deposit time stands).
func dcDerive(raw []byte) (title string, start *time.Time, err error) {
	var dc dcCatalog
	if err := xml.Unmarshal(raw, &dc); err != nil {
		return "", nil, err
	}
	title = strings.TrimSpace(dc.Title)
	if m := dcTemporalStartRe.FindStringSubmatch(dc.Temporal); m != nil {
		if ts, perr := time.Parse(time.RFC3339, m[1]); perr == nil {
			return title, &ts, nil
		}
	}
	if c := strings.TrimSpace(dc.Created); c != "" {
		// dcterms:created is W3CDTF and may be minute-precision ("2026-08-14T06:44Z")
		for _, layout := range []string{time.RFC3339, "2006-01-02T15:04Z07:00"} {
			if ts, perr := time.Parse(layout, c); perr == nil {
				return title, &ts, nil
			}
		}
	}
	return title, nil, nil
}
