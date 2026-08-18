package ingest

import (
	"bytes"
	"encoding/xml"
	"time"

	"ocng/internal/mediapackage"
)

// The bearer-document emitter: ocng's first PRODUCTION of the mediapackage
// wire format (consumption came in increment 1). The target is the
// unprefixed default-namespace shape, SEMANTICALLY equal to the reference
// mediapackage documents — see TestEmitBearerSemanticParity.
//
// Hand-built serialisation on purpose: the mediapackage format is defined
// operationally by JAXB plus one legacy hand-built serialiser (CONTRACTS
// §2, "there is no XSD"), and Go's encoding/xml cannot control attribute
// ordering. D-015 (float formatting) does not bite — this document class
// carries no float fields — and the guard is the parity tests.
//
// Attribute order: ONE canonical order (xmlns, id, start), always. The
// legacy server emits xmlns FIRST from some code paths and LAST from others
// (two marshaller paths). ocng deliberately emits one canonical order
// instead (decision 2026-08-14): XML attribute order is semantically
// insignificant, no conformant parser may depend on it, and the consumer
// sweep found nothing that hashes or byte-compares a mediapackage document
// (ocng's snapshot hashes canonical JSON; ETags and dedup hash element
// bytes; clients hold the bearer opaquely, D-021). The general rule, per
// the wire-fidelity rule: reproduce what a conformant consumer can observe; normalize
// below the standard's semantic level.

const mpXMLHeader = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`
const mpNamespace = "http://mediapackage.opencastproject.org"

// startAttrFormat is the start-attribute shape: RFC 3339, whole seconds,
// UTC 'Z' (e.g. start="2026-08-14T08:04:49Z").
const startAttrFormat = "2006-01-02T15:04:05Z"

func esc(s string) string {
	var b bytes.Buffer
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

// emitBearer serialises the in-flight mediapackage to the bearer wire
// shape. Only fields this document class carries pre-workflow are
// emitted: id, start, optional title, tracks (mimetype/tags/url/live),
// catalogs and attachments (mimetype/tags/url).
func emitBearer(m mediapackage.Manifest) []byte {
	var b bytes.Buffer
	b.WriteString(mpXMLHeader)
	b.WriteString("<mediapackage")
	b.WriteString(` xmlns="` + mpNamespace + `"`)
	if m.ID != "" {
		b.WriteString(` id="` + esc(m.ID) + `"`)
	}
	if m.Start != nil {
		b.WriteString(` start="` + m.Start.UTC().Format(startAttrFormat) + `"`)
	}
	b.WriteString(">")
	if m.Title != "" {
		b.WriteString("<title>" + esc(m.Title) + "</title>")
	}

	emitGroup(&b, "media", "track", m.Elements, true)
	emitGroup(&b, "metadata", "catalog", m.Elements, false)
	emitGroup(&b, "attachments", "attachment", m.Elements, false)
	b.WriteString("<publications/>")
	b.WriteString("</mediapackage>")
	return b.Bytes()
}

func emitGroup(b *bytes.Buffer, wrapper, kind string, els []mediapackage.ManifestElement, live bool) {
	var members []mediapackage.ManifestElement
	for _, el := range els {
		if el.Kind == kind {
			members = append(members, el)
		}
	}
	if len(members) == 0 {
		b.WriteString("<" + wrapper + "/>")
		return
	}
	b.WriteString("<" + wrapper + ">")
	for _, el := range members {
		b.WriteString("<" + kind + ` id="` + esc(el.ID) + `" type="` + esc(el.Flavor) + `">`)
		if el.Mimetype != "" {
			b.WriteString("<mimetype>" + esc(el.Mimetype) + "</mimetype>")
		}
		if len(el.Tags) == 0 {
			b.WriteString("<tags/>")
		} else {
			b.WriteString("<tags>")
			for _, tag := range el.Tags {
				b.WriteString("<tag>" + esc(tag) + "</tag>")
			}
			b.WriteString("</tags>")
		}
		b.WriteString("<url>" + esc(el.URL) + "</url>")
		if live {
			b.WriteString("<live>false</live>")
		}
		b.WriteString("</" + kind + ">")
	}
	b.WriteString("</" + wrapper + ">")
}

// parseBearer reads a bearer document back — the same local-name parser the
// loader uses (mediapackage.ParseManifest), because a client may round-trip
// prefixed shapes just as well as ours (D-021: the client never parses, but
// WE must accept whatever any producer emitted).
func parseBearer(raw []byte) (mediapackage.Manifest, error) {
	return mediapackage.ParseManifest(raw)
}

// nowSecond is the deposit-time start attribute for createMediaPackage:
// whole seconds UTC, matching the established emitted precision.
func nowSecond() *time.Time {
	t := time.Now().UTC().Truncate(time.Second)
	return &t
}
