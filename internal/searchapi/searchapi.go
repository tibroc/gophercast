// Package searchapi is the REST layer: the three query surfaces (admin-ng,
// External API, engage /search) over the search query layer. The two
// admin-ng list routes are served by the MERGED handlers in adminapi — rich
// UI rows AND filter/sort/pagination — mounted here as the same functions;
// the /api and /search surfaces keep their thin shapes.
//
// Principals come from the ONE extraction layer (internal/authn — T1 step 1;
// the constructor defaults to the dev seam so in-process test construction is
// unchanged, the assembled binary wires the configured authenticator).
// Anonymous: 403 on admin-ng and /api (as existing clients expect),
// ROLE_ANONYMOUS on /search.
package searchapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/adminapi"
	"ocng/internal/authn"
	"ocng/internal/search"
)

// Option configures the handler; the zero configuration is the dev-seam
// authenticator (pre-T1 behaviour, what the 1–6 suites construct).
type Option func(*handler)

// WithAuth wires the process-wide authenticator (T1 step 1).
func WithAuth(a *authn.Authenticator) Option {
	return func(h *handler) { h.authn = a }
}

func NewHandler(pool *pgxpool.Pool, opts ...Option) http.Handler {
	mux := http.NewServeMux()
	h := &handler{pool: pool, authn: authn.DevSeam(nil)}
	for _, o := range opts {
		o(h)
	}
	// The admin-ng list routes are the MERGED handlers (increment 5.6,
	// assembly finding A1): one implementation — adminapi's — serving the
	// rich row shape the UI renders AND honouring filter/sort/pagination
	// plus the total=0-past-offset wart. Mounted here too so this package's
	// mux stays a complete increment-4 surface; there is deliberately no
	// second implementation of these paths anywhere. They share THIS
	// handler's authenticator — one extraction layer per process.
	mux.HandleFunc("GET /admin-ng/event/events.json", adminapi.EventsList(pool, adminapi.WithAuth(h.authn)))
	mux.HandleFunc("GET /admin-ng/series/series.json", adminapi.SeriesList(pool, adminapi.WithAuth(h.authn)))
	mux.HandleFunc("GET /admin-ng/resources/events/filters.json", h.auth(h.eventFilters))
	mux.HandleFunc("GET /api/events", h.auth(h.apiEvents))
	// Player increment: get-by-id is the enriched External-API event body
	// (eventmanifest.go) and — alone among the /api routes (D-047) — admits
	// anonymous principals, pin-evaluated. The list above keeps the
	// measured 403.
	mux.HandleFunc("GET /api/events/{id}", h.apiEventByIDFull)
	// The External API ACL write. ocng honours the request shape and funnels
	// it through the ONE ACL model (adminapi/write.go): a deny is stored,
	// reported and veto-evaluated, always visible on read-back.
	mux.HandleFunc("PUT /api/events/{id}/acl", adminapi.APIEventACL(pool, adminapi.WithAuth(h.authn)))
	mux.HandleFunc("GET /api/series", h.auth(h.apiSeries))
	mux.HandleFunc("GET /search/episode.json", h.engageEpisode) // anonymous allowed
	mux.HandleFunc("GET /search/series.json", h.engageSeries)   // anonymous allowed
	return mux
}

type handler struct {
	pool  *pgxpool.Pool
	authn *authn.Authenticator
}

// auth gates the authenticated surfaces: anonymous → 403 on admin-ng and
// /api (the shape existing clients expect).
func (h *handler) auth(next func(http.ResponseWriter, *http.Request, search.Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := h.authn.Principal(r)
		if !ok {
			http.Error(w, "forbidden", http.StatusForbidden)
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

func (h *handler) runEvents(w http.ResponseWriter, r *http.Request, p search.Principal, surface search.Surface) (search.Result, bool) {
	// filter/sort parsing lives in adminapi since the 5.6 merge (finding
	// A1) — one parser for the admin-ng and /api surfaces, never two.
	filters, text := adminapi.ParseAdminFilters(r)
	res, err := search.Events(r.Context(), h.pool, p, search.Query{
		Surface: surface, Filters: filters, Text: text, Sort: adminapi.ParseSort(r),
		Limit: intParam(r, "limit", 100), Offset: intParam(r, "offset", 0),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return search.Result{}, false
	}
	return res, true
}

type apiItem struct {
	Identifier string `json:"identifier"`
	Title      string `json:"title"`
}

func apiItems(res search.Result) []apiItem {
	items := make([]apiItem, 0, len(res.Items))
	for _, it := range res.Items {
		items = append(items, apiItem{it.ID, it.Title})
	}
	return items
}

func (h *handler) apiEvents(w http.ResponseWriter, r *http.Request, p search.Principal) {
	res, ok := h.runEvents(w, r, p, search.APIEvents)
	if !ok {
		return
	}
	writeJSON(w, apiItems(res))
}

func (h *handler) apiSeries(w http.ResponseWriter, r *http.Request, p search.Principal) {
	res, err := search.Series(r.Context(), h.pool, p, search.Query{
		Surface: search.APISeries,
		Limit:   intParam(r, "limit", 100), Offset: intParam(r, "offset", 0),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, apiItems(res))
}

type engageItem struct {
	ID string `json:"id"`
}

func (h *handler) engageEpisode(w http.ResponseWriter, r *http.Request) {
	p, _ := h.authn.Principal(r)
	q := search.Query{
		Surface: search.EngageEpisode,
		Text:    r.URL.Query().Get("q"),
		ByID:    r.URL.Query().Get("id"),
		Limit:   intParam(r, "limit", 20),
		Offset:  intParam(r, "offset", 0),
	}
	if sid := r.URL.Query().Get("sid"); sid != "" {
		q.Filters = map[string]string{"series": sid}
	}
	// engage sort format: "field asc|desc" (space-separated)
	if s := r.URL.Query().Get("sort"); s != "" {
		field, dir, _ := strings.Cut(s, " ")
		q.Sort = []search.SortKey{{Field: field, Desc: strings.EqualFold(dir, "desc")}}
	}
	res, err := search.Events(r.Context(), h.pool, p, q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	items := make([]engageItem, 0, len(res.Items))
	for _, it := range res.Items {
		items = append(items, engageItem{it.ID})
	}
	writeJSON(w, map[string]any{
		"total": res.Total, "limit": q.Limit, "offset": q.Offset, "result": items,
	})
}

func (h *handler) engageSeries(w http.ResponseWriter, r *http.Request) {
	p, _ := h.authn.Principal(r)
	res, err := engageSeriesQuery(r.Context(), h.pool, p,
		r.URL.Query().Get("q"), intParam(r, "limit", 20), intParam(r, "offset", 0))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	items := make([]engageItem, 0, len(res.Items))
	for _, it := range res.Items {
		items = append(items, engageItem{it.ID})
	}
	writeJSON(w, map[string]any{
		"total": res.Total, "limit": intParam(r, "limit", 20), "offset": intParam(r, "offset", 0),
		"result": items,
	})
	// Deliberate divergence: ocng does not echo the raw index source here.
	// The internal projection fields (searchable_acl / acl / org / modified)
	// are not part of the response contract (contract doc §4.5), no consumer
	// reads them, and ocng does not emit them.
}

// engageSeriesQuery reproduces the established series-q semantics: `q` is a
// WILDCARD SUBSTRING over analyzed (lowercased) tokens —
// token-scoped, so a q containing whitespace can match nothing
// (se-series-q: 0 hits, measured), while a single-token substring matches
// (se-series-q2: measured). This is engage-series-specific; every other
// fulltext surface uses the D-020 tsquery semantics.
func engageSeriesQuery(ctx context.Context, pool *pgxpool.Pool, p search.Principal, q string, limit, offset int) (search.Result, error) {
	if strings.ContainsAny(strings.TrimSpace(q), " \t") {
		return search.Result{Items: nil, Total: 0}, nil
	}
	base := search.Query{Surface: search.EngageSeries, Limit: limit, Offset: offset}
	if strings.TrimSpace(q) == "" {
		return search.Series(ctx, pool, p, base)
	}
	// substring predicate, ACL/published clauses shared with the query layer
	return search.SeriesSubstring(ctx, pool, p, strings.TrimSpace(q), limit, offset)
}

func (h *handler) eventFilters(w http.ResponseWriter, r *http.Request, p search.Principal) {
	// D-019: org-scoped (trivially — one tenant per instance, ADR-010),
	// NOT ACL-scoped — the decided semantics. The key set is the contract
	// (the fixture asserts it); values are dropdown options.
	opts, err := search.FilterOptions(r.Context(), h.pool)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, opts)
}
