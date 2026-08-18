// Query layer (increment 4). S2 strategy A: array-overlap ACL predicates
// over GIN. The obligations carried from S2 §4.3 and the sweep:
//
//   - ROLE PRUNING BEFORE THE PLANNER: a principal's role list is
//     intersected with the live ACL vocabulary before it appears in any
//     query — hundreds of never-matching role keys fed to a GIN BitmapAnd
//     is exactly the measured plan-bistability trigger (6 ms–3.7 s).
//   - ROLE_EPISODE_<id>_READ/WRITE are never stored (schema.sql note); a
//     principal HOLDING one (the JWT `oc` claim mints them —
//     DynamicLoginHandler.java:337, the one live grant path found by the
//     increment-4 sweep) gets it rewritten into a direct id grant here.
//   - Admin bypass: ROLE_ADMIN (and the global-admin role) get NO ACL
//     clause at all, which is why the worst-case latency principal is a
//     many-role non-admin.
//   - D-020: fulltext is AND-of-terms via tsquery with prefix match on the
//     final token; when the exact query finds nothing, a pg_trgm similarity
//     fallback provides typo tolerance. Rank order is not part of any
//     assertion; explicit sorts are deterministic.
package search

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Surface int

const (
	AdminEvents   Surface = iota // read AND write on the archive ACL
	APIEvents                    // read on the archive ACL
	AdminSeries                  // read AND write on the series ACL
	APISeries                    // read on the series ACL
	EngageEpisode                // published + read on the PIN (pub_read)
	EngageSeries                 // union of published episodes' pins
)

type Principal struct {
	Roles []string
}

// adminRoles carry the no-ACL-clause bypass (all admin queries; the
// org-admin role of the single ADR-010 tenant).
var adminRoles = map[string]bool{"ROLE_ADMIN": true, "ROLE_GLOBAL_ADMIN": true}

func (p Principal) IsAdmin() bool {
	for _, r := range p.Roles {
		if adminRoles[r] {
			return true
		}
	}
	return false
}

var episodeRoleRe = regexp.MustCompile(`^ROLE_EPISODE_(.+)_(READ|WRITE)$`)

// split separates a principal's roles into plain roles and direct episode
// grants (the query-side form of the synthetic episode roles).
func (p Principal) split() (plain []string, episodeRead, episodeWrite []string) {
	for _, r := range p.Roles {
		if m := episodeRoleRe.FindStringSubmatch(r); m != nil {
			if m[2] == "READ" {
				episodeRead = append(episodeRead, m[1])
			} else {
				episodeWrite = append(episodeWrite, m[1])
			}
			continue
		}
		plain = append(plain, r)
	}
	return
}

// Prune intersects roles with the ACL vocabulary (S2 §4.3: droppable by
// construction; typical LMS-heavy principals collapse from hundreds to
// tens). The vocabulary query is a small indexed distinct-scan; correctness
// is guaranteed by construction (a role absent from every ACL entry can
// match no ACL array) and asserted by the fixture's multi≡A∪B case.
func Prune(ctx context.Context, pool *pgxpool.Pool, roles []string) ([]string, error) {
	if len(roles) == 0 {
		return roles, nil
	}
	rows, err := pool.Query(ctx, `
		select distinct role from acl_entry where role = any($1)`, roles)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type SortKey struct {
	Field string
	Desc  bool
}

type Query struct {
	Surface Surface
	// Filters: exact-match/range predicates by contract filter name
	// (events: series, status, location, language, presentersBibliographic /
	// presenters, startDate; series: textFilter only so far).
	Filters map[string]string
	Text    string // fulltext (textFilter / q)
	Sort    []SortKey
	Limit   int
	Offset  int
	ByID    string // get-by-id / engage id= / engage sid= handled via Filters["series"]
}

type Item struct {
	ID    string
	Title string
}

type Result struct {
	Items []Item
	Total int
}

// sort whitelists per surface: the contract's ORDER BY set for the shapes
// the contract exercises. ICU collation for the admin/API surfaces; engage
// sorts on the raw keyword (byte order), hence COLLATE "C".
var sortColumns = map[string]string{
	"title":      "title",
	"start_date": "start_date",
	"date":       "start_date",
	"created":    "created",
}

// Events executes an event query for a principal on one of the three event
// surfaces, with exact totals (the admin/API contract: every listing costs a
// page plus an exact ACL-filtered count).
func Events(ctx context.Context, pool *pgxpool.Pool, p Principal, q Query) (Result, error) {
	where, args := []string{"true"}, []any{}
	arg := func(v any) string { args = append(args, v); return fmt.Sprintf("$%d", len(args)) }

	// visibility
	if !p.IsAdmin() {
		plain, epRead, epWrite := p.split()
		pruned, err := Prune(ctx, pool, plain)
		if err != nil {
			return Result{}, err
		}
		switch q.Surface {
		case AdminEvents: // read AND write (both may be satisfied by direct grants)
			where = append(where,
				"(acl_read && "+arg(pruned)+" or mediapackage_id::text = any("+arg(emptyIfNil(epRead))+"))",
				"(acl_write && "+arg(pruned)+" or mediapackage_id::text = any("+arg(emptyIfNil(epWrite))+"))")
		case APIEvents:
			where = append(where,
				"(acl_read && "+arg(pruned)+" or mediapackage_id::text = any("+arg(emptyIfNil(epRead))+"))")
		case EngageEpisode:
			where = append(where,
				"(pub_read && "+arg(pruned)+" or mediapackage_id::text = any("+arg(emptyIfNil(epRead))+"))")
		default:
			return Result{}, fmt.Errorf("Events: not an event surface")
		}
	}
	if q.Surface == EngageEpisode {
		where = append(where, "published")
	}

	if q.ByID != "" {
		where = append(where, "mediapackage_id::text = "+arg(q.ByID))
	}
	for name, val := range q.Filters {
		switch name {
		case "series":
			where = append(where, "series_id = "+arg(val))
		case "status":
			where = append(where, "status = "+arg(val))
		case "location":
			where = append(where, "location = "+arg(val))
		case "language":
			where = append(where, "language = "+arg(val))
		case "presentersBibliographic", "presenters":
			where = append(where, arg(val)+" = any(presenters)")
		case "startDate": // from/to, ISO instants
			parts := strings.SplitN(val, "/", 2)
			if len(parts) != 2 {
				return Result{}, fmt.Errorf("startDate filter %q: want from/to", val)
			}
			from, err := time.Parse(time.RFC3339, parts[0])
			if err != nil {
				return Result{}, fmt.Errorf("startDate from: %w", err)
			}
			to, err := time.Parse(time.RFC3339, parts[1])
			if err != nil {
				return Result{}, fmt.Errorf("startDate to: %w", err)
			}
			where = append(where, "start_date between "+arg(from)+" and "+arg(to))
		default:
			return Result{}, fmt.Errorf("unknown filter %q", name)
		}
	}

	ftsWhere, ftsArgs, err := fulltextClause(ctx, pool, "search_event", q.Text, len(args))
	if err != nil {
		return Result{}, err
	}
	if ftsWhere != "" {
		where = append(where, ftsWhere)
		args = append(args, ftsArgs...)
	}

	collate := ` collate "en-x-icu"`
	if q.Surface == EngageEpisode {
		collate = ` collate "C"` // ES keyword sort is byte order, not collation
	}
	order := "start_date desc, mediapackage_id"
	if len(q.Sort) > 0 {
		var keys []string
		for _, s := range q.Sort {
			col, ok := sortColumns[s.Field]
			if !ok {
				return Result{}, fmt.Errorf("unsortable field %q", s.Field)
			}
			dir := "asc"
			if s.Desc {
				dir = "desc"
			}
			if col == "title" {
				col += collate
			}
			keys = append(keys, col+" "+dir)
		}
		order = strings.Join(keys, ", ") + ", mediapackage_id"
	}

	cond := strings.Join(where, " and ")
	var total int
	if err := pool.QueryRow(ctx, "select count(*) from search_event where "+cond, args...).Scan(&total); err != nil {
		return Result{}, fmt.Errorf("count: %w", err)
	}
	limit, offset := q.Limit, q.Offset
	if limit <= 0 {
		limit = 100
	}
	rows, err := pool.Query(ctx,
		"select mediapackage_id::text, coalesce(title,'') from search_event where "+cond+
			" order by "+order+fmt.Sprintf(" limit %d offset %d", limit, offset), args...)
	if err != nil {
		return Result{}, fmt.Errorf("page: %w", err)
	}
	defer rows.Close()
	res := Result{Total: total}
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.ID, &it.Title); err != nil {
			return Result{}, err
		}
		res.Items = append(res.Items, it)
	}
	return res, rows.Err()
}

// Series executes a series query on one of the three series surfaces.
func Series(ctx context.Context, pool *pgxpool.Pool, p Principal, q Query) (Result, error) {
	where, args := []string{"true"}, []any{}
	arg := func(v any) string { args = append(args, v); return fmt.Sprintf("$%d", len(args)) }

	if !p.IsAdmin() {
		plain, _, _ := p.split()
		pruned, err := Prune(ctx, pool, plain)
		if err != nil {
			return Result{}, err
		}
		switch q.Surface {
		case AdminSeries:
			where = append(where, "acl_read && "+arg(pruned), "acl_write && "+arg(pruned))
		case APISeries:
			where = append(where, "acl_read && "+arg(pruned))
		case EngageSeries:
			where = append(where, "pub_read && "+arg(pruned))
		default:
			return Result{}, fmt.Errorf("Series: not a series surface")
		}
	}
	if q.Surface == EngageSeries {
		where = append(where, "has_published")
	}

	ftsWhere, ftsArgs, err := fulltextClause(ctx, pool, "search_series", q.Text, len(args))
	if err != nil {
		return Result{}, err
	}
	if ftsWhere != "" {
		where = append(where, ftsWhere)
		args = append(args, ftsArgs...)
	}

	order := `title collate "en-x-icu", series_id`
	if q.Surface == EngageSeries {
		order = `title collate "C", series_id`
	}
	cond := strings.Join(where, " and ")
	var total int
	if err := pool.QueryRow(ctx, "select count(*) from search_series where "+cond, args...).Scan(&total); err != nil {
		return Result{}, fmt.Errorf("count: %w", err)
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	rows, err := pool.Query(ctx,
		"select series_id, coalesce(title,'') from search_series where "+cond+
			" order by "+order+fmt.Sprintf(" limit %d offset %d", limit, q.Offset), args...)
	if err != nil {
		return Result{}, err
	}
	defer rows.Close()
	res := Result{Total: total}
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.ID, &it.Title); err != nil {
			return Result{}, err
		}
		res.Items = append(res.Items, it)
	}
	return res, rows.Err()
}

// fulltextClause builds the D-020 text predicate: AND-of-terms tsquery with
// prefix match on the final token. If the exact tsquery matches NOTHING in
// the table, it falls back to pg_trgm word-similarity per term (typo
// tolerance as reachability, not set fidelity).
func fulltextClause(ctx context.Context, pool *pgxpool.Pool, table, text string, argOffset int) (string, []any, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "", nil, nil
	}
	terms := strings.Fields(text)
	var qparts []string
	for i, t := range terms {
		t = strings.ReplaceAll(t, "'", "''")
		t = strings.ReplaceAll(t, "\\", "")
		if i == len(terms)-1 {
			qparts = append(qparts, "'"+t+"':*") // prefix on the final token (D-020c)
		} else {
			qparts = append(qparts, "'"+t+"'")
		}
	}
	tsq := strings.Join(qparts, " & ")

	// does the exact query match anything at all? (fallback decision is
	// corpus-global, mirroring "no results → try fuzzy", not per-row)
	var found bool
	if err := pool.QueryRow(ctx,
		"select exists (select 1 from "+table+" where fts @@ to_tsquery('english', $1))",
		tsq).Scan(&found); err != nil {
		return "", nil, fmt.Errorf("fulltext probe: %w", err)
	}
	if found {
		return fmt.Sprintf("fts @@ to_tsquery('english', $%d)", argOffset+1), []any{tsq}, nil
	}
	// trgm fallback: every term must fuzzy-match the searchable text
	var conds []string
	var args []any
	n := argOffset
	for _, t := range terms {
		n++
		// 0.4: measured floor — word_similarity('quntum', the fixture's
		// quantum titles) = 0.5 exactly; ES fuzziness AUTO tolerates edit
		// distance 2 at this length, so the boundary needs margin below it
		conds = append(conds, fmt.Sprintf("word_similarity($%d, coalesce(title,'')) >= 0.4", n))
		args = append(args, t)
	}
	return "(" + strings.Join(conds, " and ") + ")", args, nil
}

func emptyIfNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// SeriesSubstring is the engage-series `q` shape ONLY: case-insensitive
// substring over the title (the established wire issues
// wildcard(fulltext, *q*) over analyzed tokens — token-scoped substring
// semantics, distinct from every other fulltext surface).
func SeriesSubstring(ctx context.Context, pool *pgxpool.Pool, p Principal, q string, limit, offset int) (Result, error) {
	where, args := []string{"has_published", "title ilike '%' || $1 || '%'"}, []any{q}
	if !p.IsAdmin() {
		plain, _, _ := p.split()
		pruned, err := Prune(ctx, pool, plain)
		if err != nil {
			return Result{}, err
		}
		args = append(args, pruned)
		where = append(where, fmt.Sprintf("pub_read && $%d", len(args)))
	}
	cond := strings.Join(where, " and ")
	var total int
	if err := pool.QueryRow(ctx, "select count(*) from search_series where "+cond, args...).Scan(&total); err != nil {
		return Result{}, err
	}
	if limit <= 0 {
		limit = 20
	}
	rows, err := pool.Query(ctx, "select series_id, coalesce(title,'') from search_series where "+
		cond+fmt.Sprintf(` order by title collate "C", series_id limit %d offset %d`, limit, offset), args...)
	if err != nil {
		return Result{}, err
	}
	defer rows.Close()
	res := Result{Total: total}
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.ID, &it.Title); err != nil {
			return Result{}, err
		}
		res.Items = append(res.Items, it)
	}
	return res, rows.Err()
}

// FilterOptions serves the admin-ng filter-dropdown enumeration. The KEY SET
// is contract (asserted by the fixture); D-019: org-scoped (trivial under
// ADR-010's one-tenant instances), deliberately NOT ACL-scoped. Values come
// from cheap DISTINCT scans over the projection; these are simple and
// cacheable if a measurement ever demands it.
func FilterOptions(ctx context.Context, pool *pgxpool.Pool) (map[string]any, error) {
	distinct := func(col string) ([]string, error) {
		rows, err := pool.Query(ctx,
			"select distinct "+col+" from search_event where "+col+" is not null order by 1")
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, rows.Err()
	}
	locations, err := distinct("location")
	if err != nil {
		return nil, err
	}
	languages, err := distinct("language")
	if err != nil {
		return nil, err
	}
	statuses, err := distinct("status")
	if err != nil {
		return nil, err
	}
	series := map[string]string{}
	rows, err := pool.Query(ctx, "select series_id, coalesce(title,'') from search_series order by 1")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, title string
		if err := rows.Scan(&id, &title); err != nil {
			return nil, err
		}
		series[id] = title
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// The 11 keys are the contract's filter key set.
	return map[string]any{
		"agent":        map[string]any{"options": map[string]string{}},
		"comments":     map[string]any{"options": map[string]string{"NONE": "NONE", "OPEN": "OPEN", "RESOLVED": "RESOLVED"}},
		"isPublished":  map[string]any{"options": map[string]string{"true": "YES", "false": "NO"}},
		"language":     map[string]any{"options": toOptions(languages)},
		"location":     map[string]any{"options": toOptions(locations)},
		"needsCutting": map[string]any{"options": map[string]string{"true": "YES", "false": "NO"}},
		"readAccess":   map[string]any{"options": map[string]string{}},
		"series":       map[string]any{"options": series},
		"startDate":    map[string]any{"type": "period"},
		"status":       map[string]any{"options": toOptions(statuses)},
		"writeAccess":  map[string]any{"options": map[string]string{}},
	}, nil
}

func toOptions(vals []string) map[string]string {
	out := map[string]string{}
	for _, v := range vals {
		out[v] = v
	}
	return out
}
