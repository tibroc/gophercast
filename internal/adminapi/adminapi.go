// Package adminapi is increment 5's widened /admin-ng READ surface: the
// boot-and-browse set the unmodified admin-interface bundle consumes to render
// the event list and metadata (BUILD-ORDER increment 5 done-condition).
//
// It is a thin COMPOSITION layer, not new domain logic:
//   - visibility, ordering and totals come from search.Events / search.Series
//     (increment 4's proven query+ACL layer, untouched);
//   - display fields come from the read-only search.*Display projection readers;
//   - ACL display comes from acl.Get — the ONE authoritative representation.
//     The access views render every stored entry (denies included) and the
//     explicit three-valued state (D-032); a stored deny is always visible
//     on read-back, and an ACL-less series renders cleanly.
//
// Auth: principals come from the ONE extraction layer (internal/authn — T1
// step 1; the constructor defaults to the dev seam so in-process test
// construction is unchanged, the assembled binary wires the configured
// authenticator). Identity headers (X-RUN-AS-*, X-Opencast-Matterhorn-*) are
// NEVER honoured here: core rejects them itself, not trusting the edge
// (ADR-012).
package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/acl"
	"ocng/internal/authn"
	"ocng/internal/cas"
	"ocng/internal/definitions"
	"ocng/internal/engine"
	"ocng/internal/search"
)

// Option configures the handler; the zero configuration is the dev-seam
// authenticator (pre-T1 behaviour, what the 1–6 suites construct).
type Option func(*handler)

// WithAuth wires the process-wide authenticator (T1 step 1).
func WithAuth(a *authn.Authenticator) Option {
	return func(h *handler) { h.authn = a }
}

// WithWrite wires the T4 write surface's dependencies: CAS for uploaded
// track bytes, the engine + the workflow-definition Source for the create
// workflow (the publish step runs through the one pinned path, D-044).
// Since T5 the assembled binary passes the DB-backed definitions.Registry
// (ADR-009's execution source of truth); tests pass definitions.Static.
// Without it the write routes still authorize and parse, but event create
// reports the missing wiring instead of half-working.
func WithWrite(store *cas.Store, eng *engine.Engine, defs definitions.Source) Option {
	return func(h *handler) { h.store, h.engine, h.defs = store, eng, defs }
}

// Handler mounts the widened /admin-ng read surface plus /info/me.json.
func Handler(pool *pgxpool.Pool, opts ...Option) http.Handler {
	h := newHandler(pool, opts)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /info/me.json", h.me)
	mux.HandleFunc("GET /admin-ng/event/events.json", h.auth(h.events))
	mux.HandleFunc("GET /admin-ng/event/{id}/metadata.json", h.auth(h.eventMetadata))
	mux.HandleFunc("GET /admin-ng/event/{id}/access.json", h.auth(h.eventAccess))
	mux.HandleFunc("GET /admin-ng/event/{id}/publications.json", h.auth(h.eventPublications))
	mux.HandleFunc("GET /admin-ng/series/series.json", h.auth(h.series))
	mux.HandleFunc("GET /admin-ng/series/{id}/metadata.json", h.auth(h.seriesMetadata))
	mux.HandleFunc("GET /admin-ng/series/{id}/access.json", h.auth(h.seriesAccess))
	// T4: the write surface (write.go) — exactly the eight endpoints the
	// admin-interface bundle issues, every one behind the same auth seam as
	// the reads (never anonymous, never X-* identity headers).
	mux.HandleFunc("POST /admin-ng/event/new", h.auth(h.eventNew))
	mux.HandleFunc("POST /admin-ng/series/new", h.auth(h.seriesNew))
	mux.HandleFunc("PUT /admin-ng/event/{id}/metadata", h.auth(h.eventMetadataEdit))
	mux.HandleFunc("PUT /admin-ng/series/{id}/metadata", h.auth(h.seriesMetadataEdit))
	mux.HandleFunc("POST /admin-ng/event/{id}/access", h.auth(h.eventAccessWrite))
	mux.HandleFunc("POST /admin-ng/series/{id}/access", h.auth(h.seriesAccessWrite))
	mux.HandleFunc("DELETE /admin-ng/event/{id}", h.auth(h.eventDelete))
	mux.HandleFunc("DELETE /admin-ng/series/{id}", h.auth(h.seriesDelete))
	return mux
}

type handler struct {
	pool  *pgxpool.Pool
	authn *authn.Authenticator
	// T4 write-surface wiring (WithWrite); nil in read-only construction
	store  *cas.Store
	engine *engine.Engine
	defs   definitions.Source
}

func newHandler(pool *pgxpool.Pool, opts []Option) *handler {
	h := &handler{pool: pool, authn: authn.DevSeam(nil)}
	for _, o := range opts {
		o(h)
	}
	return h
}

func (h *handler) auth(next func(http.ResponseWriter, *http.Request, search.Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := h.authn.Principal(r)
		if !ok {
			http.Error(w, "forbidden", http.StatusForbidden) // anonymous → 403 on admin-ng (measured)
			return
		}
		next(w, r, p)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func intParam(r *http.Request, name string, def int) int {
	if v := r.URL.Query().Get(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func isoOrEmpty(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// ---- query parsing (shared with searchapi's /api surface) ------------------

// ParseAdminFilters parses the admin-ng/External-API `filter=a:x,b:y` form:
// comma-separated pairs, name before the FIRST colon (values may contain
// colons — date ranges do), duplicate names overwrite (RestUtils.java
// measured semantics). The ONE parser for both mounts of the merged list
// handlers and searchapi's /api surface (increment 5.6, finding A1).
func ParseAdminFilters(r *http.Request) (map[string]string, string) {
	filters := map[string]string{}
	text := ""
	for _, pair := range strings.Split(r.URL.Query().Get("filter"), ",") {
		if pair == "" {
			continue
		}
		name, val, ok := strings.Cut(pair, ":")
		if !ok {
			continue
		}
		if name == "textFilter" {
			text = val
			continue
		}
		filters[name] = val
	}
	return filters, text
}

// ParseSort parses `sort=field:ASC` (admin-ng / External API).
func ParseSort(r *http.Request) []search.SortKey {
	var keys []search.SortKey
	for _, part := range strings.Split(r.URL.Query().Get("sort"), ",") {
		if part == "" {
			continue
		}
		field, dir, _ := strings.Cut(part, ":")
		keys = append(keys, search.SortKey{Field: field, Desc: strings.EqualFold(dir, "DESC")})
	}
	return keys
}

// ---- event list -----------------------------------------------------------

// EventsList and SeriesList expose the merged list handlers so searchapi can
// mount the SAME implementation on its mux: one handler serving the rich
// row shape AND honouring filter/sort/pagination plus the total=0-past-offset
// wart — never two divergent handlers.
func EventsList(pool *pgxpool.Pool, opts ...Option) http.HandlerFunc {
	h := newHandler(pool, opts)
	return h.auth(h.events)
}

func SeriesList(pool *pgxpool.Pool, opts ...Option) http.HandlerFunc {
	h := newHandler(pool, opts)
	return h.auth(h.series)
}

func (h *handler) events(w http.ResponseWriter, r *http.Request, p search.Principal) {
	limit, offset := intParam(r, "limit", 100), intParam(r, "offset", 0)
	filters, text := ParseAdminFilters(r)
	sortKeys := ParseSort(r)
	if len(sortKeys) == 0 {
		// no explicit sort → the default event-list order the admin UI
		// relies on
		sortKeys = []search.SortKey{{Field: "start_date", Desc: true}}
	}
	res, err := search.Events(r.Context(), h.pool, p, search.Query{
		Surface: search.AdminEvents, Filters: filters, Text: text,
		Sort: sortKeys, Limit: limit, Offset: offset,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ids := make([]string, len(res.Items))
	for i, it := range res.Items {
		ids[i] = it.ID
	}
	disp, err := search.EventsDisplay(r.Context(), h.pool, ids)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows := make([]map[string]any, 0, len(ids))
	for _, id := range ids { // preserve search's order
		rows = append(rows, eventRow(disp[id]))
	}
	total := res.Total
	if len(res.Items) == 0 && offset > 0 {
		// Compatibility wart, reproduced deliberately (admin-ng events
		// only): an offset past the visible set reports total=0, while
		// in-range offsets report the exact total — the admin UI expects
		// this shape.
		total = 0
	}
	writeJSON(w, map[string]any{
		"total": total, "count": len(rows), "limit": limit, "offset": offset,
		"results": rows,
	})
}

// eventRow builds the admin-ng event-list row from the fields the admin UI's
// Event type + eventsTableConfig actually read.
func eventRow(e search.EventDisplay) map[string]any {
	start := isoOrEmpty(e.StartDate)
	end := start
	if e.StartDate != nil && e.DurationMs != nil {
		end = e.StartDate.UTC().Add(time.Duration(*e.DurationMs) * time.Millisecond).Format("2006-01-02T15:04:05Z")
	}
	status := e.Status
	if status == "" {
		status = "EVENTS.EVENTS.STATUS.PROCESSED"
	}
	row := map[string]any{
		"id":                       e.ID,
		"title":                    e.Title,
		"source":                   "ARCHIVE",
		"presenters":               strs(e.Presenters),
		"location":                 e.Location,
		"start_date":               start,
		"end_date":                 end,
		"technical_start":          start,
		"technical_end":            end,
		"technical_presenters":     []string{},
		"language":                 e.Language,
		"language_translation_key": languageKey(e.Language),
		"event_status":             status,
		"displayable_status":       status,
		"workflow_state":           "SUCCEEDED",
		"has_comments":             false,
		"has_open_comments":        false,
		"needs_cutting":            false,
		"has_preview":              e.Published,
		"published":                e.Published,
		"publications":             publications(e.ID, e.Published),
	}
	if e.SeriesID != "" {
		row["series"] = map[string]any{"id": e.SeriesID, "title": e.SeriesTitle}
	}
	return row
}

func publications(mpID string, published bool) []map[string]any {
	if !published {
		return []map[string]any{}
	}
	return []map[string]any{{
		"id":   "engage-player",
		"name": "EVENTS.EVENTS.DETAILS.PUBLICATIONS.ENGAGE",
		"url":  "http://localhost:8080/play/" + mpID,
	}}
}

// ---- event metadata (DC catalog) ------------------------------------------

func (h *handler) eventMetadata(w http.ResponseWriter, r *http.Request, p search.Principal) {
	id := r.PathValue("id")
	if !h.visibleEvent(r.Context(), p, id) {
		http.NotFound(w, r)
		return
	}
	e, err := search.EventDisplayByID(r.Context(), h.pool, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	fields := []map[string]any{
		field("title", "TITLE", e.Title, "text", true),
		field("subject", "SUBJECT", strings.Join(e.Subjects, ", "), "text", false),
		field("description", "DESCRIPTION", e.Description, "text_long", false),
		field("language", "LANGUAGE", e.Language, "text", false),
		field("rightsHolder", "RIGHTS", "", "text", false),
		field("license", "LICENSE", e.License, "text", false),
		field("isPartOf", "SERIES", e.SeriesID, "text", false),
		field("creator", "PRESENTERS", "", "mixed_text", false, e.Presenters),
		field("contributor", "CONTRIBUTORS", "", "mixed_text", false, e.Contributors),
		field("startDate", "START_DATE", isoOrEmpty(e.StartDate), "date", false),
	}
	writeJSON(w, []map[string]any{{
		"flavor": "dublincore/episode",
		"title":  "EVENTS.EVENTS.DETAILS.CATALOG.EPISODE",
		"fields": fields,
	}})
}

// field builds one admin-ng metadata field record. A trailing []string arg
// carries a mixed_text (array) value.
func field(id, labelKey, value, typ string, required bool, arr ...[]string) map[string]any {
	f := map[string]any{
		"id":       id,
		"label":    "EVENTS.EVENTS.DETAILS.METADATA." + labelKey,
		"type":     typ,
		"readOnly": false,
		"required": required,
	}
	if len(arr) > 0 {
		f["value"] = strs(arr[0])
	} else {
		f["value"] = value
	}
	return f
}

// ---- event access (ACL) ----------------------------------------------------

func (h *handler) eventAccess(w http.ResponseWriter, r *http.Request, p search.Principal) {
	id := r.PathValue("id")
	if !h.visibleEvent(r.Context(), p, id) {
		http.NotFound(w, r)
		return
	}
	access, err := h.accessBlock(r.Context(), acl.ScopeEvent, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"episode_access": access,
		"system_acls":    systemAcls(),
	})
}

func (h *handler) seriesAccess(w http.ResponseWriter, r *http.Request, p search.Principal) {
	id := r.PathValue("id")
	access, err := h.accessBlock(r.Context(), acl.ScopeSeries, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"series_access": access,
		"system_acls":   systemAcls(),
	})
}

// accessBlock renders the stored ACL from acl.Get — the authoritative source.
// It renders every stored entry (denies included) and the three-valued state
// cleanly; an ABSENT policy renders as ABSENT, never as an error.
func (h *handler) accessBlock(ctx context.Context, scope acl.Scope, id string) (map[string]any, error) {
	entries, state, err := acl.Get(ctx, h.pool, scope, id)
	if err != nil {
		return nil, err
	}
	// aggregate by role → {read,write}, and a flat acl list; a deny (Allow
	// false) is rendered as read/write=false so a stored deny is VISIBLE,
	// never elided from the view.
	type rw struct{ read, write, readSet, writeSet bool }
	byRole := map[string]*rw{}
	order := []string{}
	for _, e := range entries {
		r, ok := byRole[e.Role]
		if !ok {
			r = &rw{}
			byRole[e.Role] = r
			order = append(order, e.Role)
		}
		// deny-sticky: when an allow and a deny COEXIST for one
		// (role,action) — both are stored — the aggregate must show the
		// deny-vetoes outcome, never let the allow mask the stored deny
		switch e.Action {
		case "read":
			if r.readSet {
				r.read = r.read && e.Allow
			} else {
				r.read, r.readSet = e.Allow, true
			}
		case "write":
			if r.writeSet {
				r.write = r.write && e.Allow
			} else {
				r.write, r.writeSet = e.Allow, true
			}
		}
	}
	privileges := map[string]any{}
	aclList := []map[string]any{}
	for _, role := range order {
		r := byRole[role]
		priv := map[string]any{}
		if r.readSet {
			priv["read"] = r.read
		}
		if r.writeSet {
			priv["write"] = r.write
		}
		privileges[role] = priv
		aclList = append(aclList, map[string]any{
			"role": role, "read": r.read, "write": r.write, "actions": []string{},
		})
	}
	return map[string]any{
		"acl_state":  string(state), // D-032: ABSENT / EMPTY / POPULATED, explicit (an ocng addition to the response)
		"privileges": privileges,
		"acl":        aclList,
	}, nil
}

// systemAcls: ocng names its managed ACL templates rather than numbering
// them. The UI's ACL dropdown reads name; no numeric id is emitted (an
// additive divergence, D-040 tolerated).
func systemAcls() []map[string]any {
	return []map[string]any{
		{"name": "public"}, {"name": "private"}, {"name": "authenticated"},
	}
}

// ---- event publications ----------------------------------------------------

func (h *handler) eventPublications(w http.ResponseWriter, r *http.Request, p search.Principal) {
	id := r.PathValue("id")
	if !h.visibleEvent(r.Context(), p, id) {
		http.NotFound(w, r)
		return
	}
	e, err := search.EventDisplayByID(r.Context(), h.pool, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	start := isoOrEmpty(e.StartDate)
	end := start
	if e.StartDate != nil && e.DurationMs != nil {
		end = e.StartDate.UTC().Add(time.Duration(*e.DurationMs) * time.Millisecond).Format("2006-01-02T15:04:05Z")
	}
	writeJSON(w, map[string]any{
		"publications": publications(id, e.Published),
		"start-date":   start,
		"end-date":     end,
	})
}

// ---- series ----------------------------------------------------------------

func (h *handler) series(w http.ResponseWriter, r *http.Request, p search.Principal) {
	limit, offset := intParam(r, "limit", 100), intParam(r, "offset", 0)
	// textFilter is the only series filter the contract exercises so far
	// (search.Query doc); exact-match filters and sort are not part of the
	// series list contract.
	_, text := ParseAdminFilters(r)
	res, err := search.Series(r.Context(), h.pool, p, search.Query{
		Surface: search.AdminSeries, Text: text, Limit: limit, Offset: offset,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rows := make([]map[string]any, 0, len(res.Items))
	for _, it := range res.Items {
		s, err := search.SeriesDisplayByID(r.Context(), h.pool, it.ID)
		if err != nil {
			continue
		}
		rows = append(rows, map[string]any{
			"id":            s.ID,
			"title":         s.Title,
			"organizers":    strs(s.Organizers),
			"contributors":  strs(s.Contributors),
			"createdBy":     "",
			"creation_date": isoOrEmpty(s.Created),
		})
	}
	writeJSON(w, map[string]any{
		"total": res.Total, "count": len(rows), "limit": limit, "offset": offset,
		"results": rows,
	})
}

func (h *handler) seriesMetadata(w http.ResponseWriter, r *http.Request, p search.Principal) {
	id := r.PathValue("id")
	s, err := search.SeriesDisplayByID(r.Context(), h.pool, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	fields := []map[string]any{
		field("title", "TITLE", s.Title, "text", true),
		field("description", "DESCRIPTION", s.Description, "text_long", false),
		field("language", "LANGUAGE", s.Language, "text", false),
		field("subject", "SUBJECT", strings.Join(s.Subjects, ", "), "text", false),
		field("creator", "ORGANIZERS", "", "mixed_text", false, s.Organizers),
		field("contributor", "CONTRIBUTORS", "", "mixed_text", false, s.Contributors),
	}
	writeJSON(w, []map[string]any{{
		"flavor": "dublincore/series",
		"title":  "EVENTS.SERIES.DETAILS.CATALOG.SERIES",
		"fields": fields,
	}})
}

// ---- info/me.json ----------------------------------------------------------

func (h *handler) me(w http.ResponseWriter, r *http.Request) {
	// T1 step 6: the display identity is the authn-resolved one. Under the
	// dev seam Info.Username is empty and the roles-derived stand-in below
	// keeps the increment-5 tier-1 contract byte-identical.
	p, info, _ := h.authn.Resolve(r)
	name := info.Username
	if name == "" {
		name = username(p)
	}
	writeJSON(w, map[string]any{
		"org": map[string]any{
			"id":            "mh_default_org",
			"name":          "Opencast Project",
			"adminRole":     "ROLE_ADMIN",
			"anonymousRole": "ROLE_ANONYMOUS",
			"properties":    map[string]any{},
		},
		"roles":    p.Roles,
		"userRole": "ROLE_USER_" + strings.ToUpper(name),
		"user": map[string]any{
			"provider": "opencast",
			"username": name,
			"name":     name,
			"email":    "",
		},
	})
}

func username(p search.Principal) string {
	if p.IsAdmin() {
		return "admin"
	}
	return "user"
}

// ---- helpers ---------------------------------------------------------------

// visibleEvent reports whether the principal may see the event, using the
// proven AdminEvents ACL path (get-by-id). Admin sees all (no-ACL bypass).
func (h *handler) visibleEvent(ctx context.Context, p search.Principal, id string) bool {
	res, err := search.Events(ctx, h.pool, p, search.Query{
		Surface: search.AdminEvents, ByID: id, Limit: 1,
	})
	return err == nil && len(res.Items) == 1
}

func strs(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

var languageKeys = map[string]string{
	"eng": "LANGUAGES.ENGLISH", "ger": "LANGUAGES.GERMAN", "deu": "LANGUAGES.GERMAN",
	"fra": "LANGUAGES.FRENCH", "spa": "LANGUAGES.SPANISH",
}

func languageKey(lang string) string {
	if k, ok := languageKeys[lang]; ok {
		return k
	}
	return ""
}
