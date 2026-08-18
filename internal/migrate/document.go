// Full mediapackage-document parsing for migration: unlike the loader's
// ParseManifest (top-level operable elements only), migration must see
// EVERYTHING the legacy system's snapshot XML carries — nested in-snapshot
// publications and security-XACML attachments included — because every byte
// must land in CAS and every URL in the repoint map, even where the operable
// model deliberately does not represent the element (D-010: preserved
// verbatim via source_manifest_sha256).
package migrate

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"
)

// docElement is one element anywhere in a mediapackage document.
type docElement struct {
	ID       string
	Kind     string // track | catalog | attachment
	Flavor   string
	Mimetype string
	URL      string
	MD5      string
	Size     int64
	Tags     []string
	// Channel is empty for top-level elements; for elements nested inside an
	// in-snapshot <publication> it is that publication's channel.
	Channel string
}

// IsSecurityXACML reports whether this element is the legacy system's ACL
// representation (security/xacml+episode|series). These migrate as the ACL
// class — bytes preserved in CAS, meaning in acl_entry — never as operable
// element rows: carrying them live would duplicate policy across
// representations. Their ids ("security-policy-episode") are also the
// one measured non-uuid element-id shape in the corpus.
func (e docElement) IsSecurityXACML() bool {
	return strings.HasPrefix(e.Flavor, "security/xacml")
}

type docPublication struct {
	ID       string
	Channel  string
	URL      string // the publication's own page link (/play/…) — preserved verbatim only
	Elements []docElement
}

type document struct {
	ID           string
	Title        string
	SeriesID     string
	Start        string
	DurationMS   int64
	Elements     []docElement // top-level operable candidates
	Publications []docPublication
}

type xmlDocElement struct {
	ID       string `xml:"id,attr"`
	Type     string `xml:"type,attr"`
	Mimetype string `xml:"mimetype"`
	URL      string `xml:"url"`
	Size     int64  `xml:"size"`
	Checksum struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"checksum"`
	Tags []string `xml:"tags>tag"`
}

type xmlDocPublication struct {
	ID          string          `xml:"id,attr"`
	Channel     string          `xml:"channel,attr"`
	URL         string          `xml:"url"`
	Tracks      []xmlDocElement `xml:"media>track"`
	Catalogs    []xmlDocElement `xml:"metadata>catalog"`
	Attachments []xmlDocElement `xml:"attachments>attachment"`
}

type xmlDocument struct {
	XMLName      xml.Name            `xml:"mediapackage"`
	ID           string              `xml:"id,attr"`
	Start        string              `xml:"start,attr"`
	Duration     int64               `xml:"duration,attr"`
	Title        string              `xml:"title"`
	Series       string              `xml:"series"`
	Tracks       []xmlDocElement     `xml:"media>track"`
	Catalogs     []xmlDocElement     `xml:"metadata>catalog"`
	Attachments  []xmlDocElement     `xml:"attachments>attachment"`
	Publications []xmlDocPublication `xml:"publications>publication"`
}

func convertDocElements(kind string, els []xmlDocElement, channel string) []docElement {
	var out []docElement
	for _, el := range els {
		d := docElement{
			ID: el.ID, Kind: kind, Flavor: el.Type, Mimetype: strings.TrimSpace(el.Mimetype),
			URL: strings.TrimSpace(el.URL), Size: el.Size, Tags: el.Tags, Channel: channel,
		}
		if el.Checksum.Type == "md5" {
			d.MD5 = strings.TrimSpace(el.Checksum.Value)
		}
		out = append(out, d)
	}
	return out
}

func parseDocument(raw []byte) (document, error) {
	var x xmlDocument
	if err := xml.Unmarshal(raw, &x); err != nil {
		return document{}, fmt.Errorf("mediapackage document: %w", err)
	}
	if x.ID == "" {
		return document{}, fmt.Errorf("mediapackage document has no id")
	}
	d := document{
		ID: x.ID, Title: x.Title, SeriesID: strings.TrimSpace(x.Series),
		Start: x.Start, DurationMS: x.Duration,
	}
	d.Elements = append(d.Elements, convertDocElements("track", x.Tracks, "")...)
	d.Elements = append(d.Elements, convertDocElements("catalog", x.Catalogs, "")...)
	d.Elements = append(d.Elements, convertDocElements("attachment", x.Attachments, "")...)
	for _, p := range x.Publications {
		pub := docPublication{ID: p.ID, Channel: p.Channel, URL: strings.TrimSpace(p.URL)}
		pub.Elements = append(pub.Elements, convertDocElements("track", p.Tracks, p.Channel)...)
		pub.Elements = append(pub.Elements, convertDocElements("catalog", p.Catalogs, p.Channel)...)
		pub.Elements = append(pub.Elements, convertDocElements("attachment", p.Attachments, p.Channel)...)
		d.Publications = append(d.Publications, pub)
	}
	return d, nil
}

// ---- Dublin Core parsing ---------------------------------------------------

type dcDoc struct {
	Fields []dcField `xml:",any"`
}

type dcField struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

// parseDC returns every Dublin Core field by local name (a field can repeat:
// creator, contributor, subject).
func parseDC(raw []byte) (map[string][]string, error) {
	var d dcDoc
	if err := xml.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("dublin core: %w", err)
	}
	out := map[string][]string{}
	for _, f := range d.Fields {
		v := strings.TrimSpace(f.Value)
		if v != "" {
			out[f.XMLName.Local] = append(out[f.XMLName.Local], v)
		}
	}
	return out, nil
}

func dcFirst(m map[string][]string, key string) string {
	if v := m[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// w3cdtfLayouts is the W3C-DTF precision ladder Dublin Core actually uses —
// the legacy system writes minute precision for series created
// ("2026-08-13T10:36Z", present in the increment-6 fixture), which RFC3339
// rejects for its missing seconds.
var w3cdtfLayouts = []string{
	time.RFC3339,
	"2006-01-02T15:04Z07:00",
	"2006-01-02",
	"2006-01",
	"2006",
}

func dcTime(m map[string][]string, key string) (*time.Time, error) {
	s := dcFirst(m, key)
	if s == "" {
		return nil, nil
	}
	for _, layout := range w3cdtfLayouts {
		if ts, err := time.Parse(layout, s); err == nil {
			return &ts, nil
		}
	}
	return nil, fmt.Errorf("dc %s %q: not a W3C-DTF timestamp", key, s)
}
