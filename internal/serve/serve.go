// Package serve is the delivery layer: element bytes by reference, plus the
// reference-based publication listing (ADR-008).
//
// GET /elements/{id} implements the delivery contract every player byte
// flows through: quoted strong ETag with If-None-Match→304,
// single-range→206, unsatisfiable→416, ?download=1→attachment.
//
// Conditional-request behaviour (D-041): ocng emits a conformant QUOTED
// content-hash ETag and round-trips it, and HONOURS If-Modified-Since
// (→304) against the element's created_at — which is its true
// Last-Modified, the bytes being immutable (ADR-008).
//
// A multi-range request (Range: bytes=a-b,c-d) returns 200 with the full
// body — RFC 7233 permits ignoring the Range header.
package serve

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/authn"
	"ocng/internal/cas"
	"ocng/internal/mediapackage"
)

// Option configures the handler; the zero configuration is the dev-seam
// authenticator (what the 1–6 suites construct), same idiom as searchapi.
type Option func(*handler)

// WithAuth wires the process-wide authenticator (D-044: every delivery
// request is authorized against the published pin).
func WithAuth(a *authn.Authenticator) Option {
	return func(h *handler) { h.authn = a }
}

type handler struct {
	pool  *pgxpool.Pool
	store *cas.Store
	authn *authn.Authenticator
}

// Publication is the JSON shape of GET /publications/{mediapackageID}:
// a reference-based publication — a channel plus the element ids it
// references (ADR-008: rows, never byte copies).
type Publication struct {
	Channel    string   `json:"channel"`
	ElementIDs []string `json:"element_ids"`
}

// Handler serves the delivery surface.
func Handler(pool *pgxpool.Pool, store *cas.Store, opts ...Option) http.Handler {
	h := &handler{pool: pool, store: store, authn: authn.DevSeam(nil)}
	for _, o := range opts {
		o(h)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /elements/{id}", h.serveElement)
	mux.HandleFunc("GET /publications/{mediapackageID}", h.servePublications)
	return mux
}

// pinsForElement reads every containing publication's pin — the reverse
// join the serve-read set was ratified to include (READSET.md). Both tables
// are IN the set; the archive-ACL tables are structurally unreadable from
// the ocng_serve pool and must never appear here (delivery reads the pin,
// never the archive ACL).
func pinsForElement(pool *pgxpool.Pool, r *http.Request, elementID string) ([]PublicationPin, error) {
	rows, err := pool.Query(r.Context(), `
		select p.mediapackage_id::text, p.channel, p.acl_read, p.acl_state
		from publication_element pe
		join publication p on p.id = pe.publication_id
		where pe.element_id = $1`, elementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pins []PublicationPin
	for rows.Next() {
		var pin PublicationPin
		if err := rows.Scan(&pin.MediapackageID, &pin.Channel, &pin.ACLRead, &pin.ACLState); err != nil {
			return nil, err
		}
		pins = append(pins, pin)
	}
	return pins, rows.Err()
}

func (h *handler) serveElement(w http.ResponseWriter, r *http.Request) {
	pool, store := h.pool, h.store
	id := r.PathValue("id")
	el, err := mediapackage.GetElement(r.Context(), pool, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "no such element", http.StatusNotFound)
			return
		}
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}

	// D-044 delivery authorization: the element exists — is this
	// principal allowed its bytes? Refusal is 403, not 404 (ratified: an
	// element UUID's existence is not treated as a secret).
	pins, err := pinsForElement(pool, r, id)
	if err != nil {
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	principal, _ := h.authn.Principal(r)
	if !Authorized(pins, principal) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	ct := el.Mimetype
	if ct == "" {
		ct = "application/octet-stream"
	}
	// one quoted strong form, emitted AND matched — the same bytes are
	// accepted back in If-None-Match
	etag := `"` + el.SHA256 + `"`
	hdr := w.Header()
	hdr.Set("ETag", etag)
	hdr.Set("Accept-Ranges", "bytes")
	hdr.Set("Content-Type", ct)
	hdr.Set("X-Content-SHA256", el.SHA256)
	if r.URL.Query().Get("download") == "1" {
		name := path.Base(el.SourceURL)
		if name == "" || name == "." || name == "/" {
			name = el.ID
		}
		hdr.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	}

	// Content-addressed elements are immutable after the row is written
	// (ADR-008), so created_at IS the effective Last-Modified. Emit it, and
	// honour both conditional validators (D-041). RFC 7232 §6: If-None-Match takes
	// precedence over If-Modified-Since.
	lastMod := el.CreatedAt.UTC().Truncate(time.Second)
	if !lastMod.IsZero() {
		hdr.Set("Last-Modified", lastMod.Format(http.TimeFormat))
	}
	if match := r.Header.Get("If-None-Match"); match != "" {
		if ifNoneMatchHits(match, etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	} else if ims := r.Header.Get("If-Modified-Since"); ims != "" && !lastMod.IsZero() {
		if t, err := http.ParseTime(ims); err == nil && !lastMod.After(t) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	size := el.SizeBytes
	start, end, status := int64(0), size-1, http.StatusOK
	if rng := r.Header.Get("Range"); rng != "" {
		s, e, verdict := parseRange(rng, size)
		switch verdict {
		case rangeUnsatisfiable:
			hdr.Set("Content-Range", fmt.Sprintf("bytes */%d", size))
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		case rangeSingle:
			start, end, status = s, e, http.StatusPartialContent
			hdr.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
		case rangeIgnore:
			// multi-range or malformed: serve the full body (RFC 7233
			// allows ignoring the Range header)
		}
	}

	var obj io.ReadCloser
	if status == http.StatusPartialContent {
		obj, err = store.GetRange(r.Context(), el.SHA256, start, end)
	} else {
		obj, err = store.Get(r.Context(), el.SHA256)
	}
	if err != nil {
		// an element row whose object is missing is a broken reference,
		// not a 404: say so loudly
		http.Error(w, "element exists but its object is missing from CAS", http.StatusBadGateway)
		return
	}
	defer obj.Close()
	hdr.Set("Content-Length", strconv.FormatInt(end-start+1, 10))
	w.WriteHeader(status)
	if _, err := io.Copy(w, obj); err != nil && !strings.Contains(err.Error(), "broken pipe") {
		return // headers already sent; nothing to do
	}
}

// ifNoneMatchHits implements RFC 7232 §3.2 for strong entity tags: '*'
// matches anything; otherwise compare against each listed tag (weak
// prefixes tolerated on the request side).
func ifNoneMatchHits(header, etag string) bool {
	if strings.TrimSpace(header) == "*" {
		return true
	}
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(part, "W/")
		if part == etag {
			return true
		}
	}
	return false
}

type rangeVerdict int

const (
	rangeIgnore rangeVerdict = iota
	rangeSingle
	rangeUnsatisfiable
)

// parseRange handles a SINGLE byte range: "bytes=a-b", "bytes=a-",
// "bytes=-n". Multi-range and malformed specs → ignore (200 full).
// A first-byte position beyond the end → unsatisfiable (416).
func parseRange(spec string, size int64) (start, end int64, verdict rangeVerdict) {
	spec = strings.TrimSpace(spec)
	if !strings.HasPrefix(spec, "bytes=") {
		return 0, 0, rangeIgnore
	}
	spec = strings.TrimPrefix(spec, "bytes=")
	if strings.Contains(spec, ",") {
		return 0, 0, rangeIgnore // multi-range: deliberate 200-full
	}
	first, last, ok := strings.Cut(spec, "-")
	if !ok {
		return 0, 0, rangeIgnore
	}
	first, last = strings.TrimSpace(first), strings.TrimSpace(last)
	switch {
	case first == "" && last != "": // suffix: last n bytes
		n, err := strconv.ParseInt(last, 10, 64)
		if err != nil || n <= 0 {
			return 0, 0, rangeIgnore
		}
		if n > size {
			n = size
		}
		return size - n, size - 1, rangeSingle
	case first != "":
		s, err := strconv.ParseInt(first, 10, 64)
		if err != nil {
			return 0, 0, rangeIgnore
		}
		if s >= size {
			return 0, 0, rangeUnsatisfiable
		}
		e := size - 1
		if last != "" {
			e, err = strconv.ParseInt(last, 10, 64)
			if err != nil || e < s {
				return 0, 0, rangeIgnore
			}
			if e > size-1 {
				e = size - 1
			}
		}
		return s, e, rangeSingle
	}
	return 0, 0, rangeIgnore
}

func (h *handler) servePublications(w http.ResponseWriter, r *http.Request) {
	pool := h.pool
	mpID := r.PathValue("mediapackageID")
	rows, err := pool.Query(r.Context(), `
		select p.channel, p.acl_read, p.acl_state, pe.element_id
		from publication p
		join publication_element pe on pe.publication_id = p.id
		where p.mediapackage_id = $1
		order by p.channel, pe.element_id`, mpID)
	if err != nil {
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	// D-044: the listing filters by the SAME rule as delivery — a
	// publication whose pin refuses the principal is not listed, or the
	// listing would enumerate the element UUIDs of restricted content. An
	// unreadable mediapackage yields [], indistinguishable from "no
	// publications" (the listing leaks no existence signal).
	principal, _ := h.authn.Principal(r)
	var pubs []Publication
	for rows.Next() {
		var pin PublicationPin
		var elID string
		pin.MediapackageID = mpID
		if err := rows.Scan(&pin.Channel, &pin.ACLRead, &pin.ACLState, &elID); err != nil {
			http.Error(w, "scan failed", http.StatusInternalServerError)
			return
		}
		if !Authorized([]PublicationPin{pin}, principal) {
			continue
		}
		if len(pubs) == 0 || pubs[len(pubs)-1].Channel != pin.Channel {
			pubs = append(pubs, Publication{Channel: pin.Channel})
		}
		pubs[len(pubs)-1].ElementIDs = append(pubs[len(pubs)-1].ElementIDs, elID)
	}
	if rows.Err() != nil {
		http.Error(w, "iteration failed", http.StatusInternalServerError)
		return
	}
	if pubs == nil {
		pubs = []Publication{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pubs)
}
