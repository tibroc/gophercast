// The admin write surface: the eight write endpoints the admin-interface
// bundle actually issues, matched against real-client captures.
//
// Semantics, endpoint by endpoint:
//   - create event: multipart (metadata JSON part + track_* file parts),
//     201 + the new mediapackage id; the processing workflow publishes
//     through the ONE pinned publish path (ops.Publish → PublishTx, D-044).
//   - create series: urlencoded `metadata`, 201 + the new series id.
//   - metadata edits: PARTIAL (changed fields only; the server merges).
//   - ACL edits: FULL-REPLACE, through the ONE model: a deny is STORED
//     faithfully, REPORTED truthfully and EVALUATED as veto. What is stored
//     is what reads back, and what reads back is what is enforced.
//   - series ACL carries `override`: false = series only, true = propagate
//     to member events (the blast-radius control).
//   - delete: the approved SOFT half — tombstone (dated retraction signal,
//     row retained) + publication retraction by ordinary DML. The archive
//     hard-delete/GC half is gated on the GC grace window: nothing here
//     mutates snapshots, elements or CAS.
//
// Authorization: through validated identity only, never anonymous,
// never X-* headers. Create requires the platform-admin grant (conservative:
// no org authoring role is defined yet — revisit when one is). Edit/delete
// evaluate WRITE against the target's stored ACL, deny-vetoes (D-028), with
// the platform-admin bypass and the direct episode-write grant honoured.
package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/acl"
	"ocng/internal/mediapackage"
	"ocng/internal/search"
)

// ---- ACL document parsing ---------------------------------------------------

type aceJSON struct {
	Action string `json:"action"`
	Allow  bool   `json:"allow"`
	Role   string `json:"role"`
}

// parseACEs accepts the two wire shapes of an ACL document — the wrapped
// {"acl":{"ace":[…]}} the admin UI sends and the bare array the External
// API PUT sends — and maps them onto acl.Entry VERBATIM, denies included:
// rejecting a deny at the wire would silently lose the operator's
// instruction.
func parseACEs(raw string) ([]acl.Entry, error) {
	trim := strings.TrimSpace(raw)
	if trim == "" {
		return nil, errors.New("empty acl document")
	}
	var aces []aceJSON
	if trim[0] == '[' {
		if err := json.Unmarshal([]byte(trim), &aces); err != nil {
			return nil, fmt.Errorf("acl document: %w", err)
		}
	} else {
		var doc struct {
			ACL struct {
				ACE []aceJSON `json:"ace"`
			} `json:"acl"`
		}
		if err := json.Unmarshal([]byte(trim), &doc); err != nil {
			return nil, fmt.Errorf("acl document: %w", err)
		}
		aces = doc.ACL.ACE
	}
	entries := make([]acl.Entry, 0, len(aces))
	for _, a := range aces {
		if a.Role == "" || a.Action == "" {
			return nil, fmt.Errorf("acl entry missing role or action: %+v", a)
		}
		entries = append(entries, acl.Entry{Role: a.Role, Action: a.Action, Allow: a.Allow})
	}
	return entries, nil
}

// ---- write authorization ----------------------------------------------------

// writeDenied reports whether any held role carries an explicit write deny —
// the veto that also defeats the direct episode grant (D-028: a write
// proceeds only on a positive grant not defeated by an applicable deny).
func writeDenied(entries []acl.Entry, roles []string) bool {
	held := make(map[string]bool, len(roles))
	for _, r := range roles {
		held[r] = true
	}
	for _, e := range entries {
		if e.Action == "write" && !e.Allow && held[e.Role] {
			return true
		}
	}
	return false
}

// canWriteEvent evaluates WRITE on the event's stored ACL: platform-admin
// bypass, deny vetoes, ABSENT/EMPTY deny (D-028/D-032). The direct
// ROLE_EPISODE_<id>_WRITE grant (the query-side synthetic episode role) is
// honoured, but an applicable deny still vetoes it.
func (h *handler) canWriteEvent(ctx context.Context, p search.Principal, id string) bool {
	if p.IsAdmin() {
		return true
	}
	entries, state, err := acl.Get(ctx, h.pool, acl.ScopeEvent, id)
	if err != nil {
		return false
	}
	if acl.Evaluate(entries, state, p.Roles, "write") {
		return true
	}
	for _, r := range p.Roles {
		if r == "ROLE_EPISODE_"+id+"_WRITE" {
			return !writeDenied(entries, p.Roles)
		}
	}
	return false
}

func (h *handler) canWriteSeries(ctx context.Context, p search.Principal, id string) bool {
	if p.IsAdmin() {
		return true
	}
	entries, state, err := acl.Get(ctx, h.pool, acl.ScopeSeries, id)
	if err != nil {
		return false
	}
	return acl.Evaluate(entries, state, p.Roles, "write")
}

// requireEventWrite resolves the {id} target and authorizes the write.
// Unauthorized == absent (404): the AdminEvents read surface already couples
// visibility to read AND write, so a 403 here would leak existence to a
// principal the list hides it from.
func (h *handler) requireEventWrite(w http.ResponseWriter, r *http.Request, p search.Principal) (string, bool) {
	id := r.PathValue("id")
	var exists bool
	if err := h.pool.QueryRow(r.Context(),
		`select exists (select 1 from mediapackage where id::text = $1 and deleted_at is null)`,
		id).Scan(&exists); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return "", false
	}
	if !exists || !h.canWriteEvent(r.Context(), p, id) {
		http.NotFound(w, r)
		return "", false
	}
	return id, true
}

func (h *handler) requireSeriesWrite(w http.ResponseWriter, r *http.Request, p search.Principal) (string, bool) {
	id := r.PathValue("id")
	var exists bool
	if err := h.pool.QueryRow(r.Context(),
		`select exists (select 1 from series where id = $1 and deleted_at is null)`,
		id).Scan(&exists); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return "", false
	}
	if !exists {
		http.NotFound(w, r)
		return "", false
	}
	if !h.canWriteSeries(r.Context(), p, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return "", false
	}
	return id, true
}

// canCreate: the create grant. Conservative platform-admin only — the
// the captured requests exercised create as the admin, and no org authoring role is
// decided yet; widening this is a decision, not a default.
func canCreate(p search.Principal) bool { return p.IsAdmin() }

// ---- ACL write endpoints ----------------------------------------------------

func (h *handler) eventAccessWrite(w http.ResponseWriter, r *http.Request, p search.Principal) {
	id, ok := h.requireEventWrite(w, r, p)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	entries, err := parseACEs(r.PostFormValue("acl"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// full-replace through the ONE path (search.SetACL → acl.SetTx +
	// projection, one transaction). The stored state is exactly `entries`,
	// denies included; read-back is a plain select of these rows;
	// evaluation is deny-vetoes.
	if err := search.SetACL(r.Context(), h.pool, acl.ScopeEvent, id, entries); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *handler) seriesAccessWrite(w http.ResponseWriter, r *http.Request, p search.Principal) {
	id, ok := h.requireSeriesWrite(w, r, p)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	entries, err := parseACEs(r.PostFormValue("acl"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	override := strings.EqualFold(r.PostFormValue("override"), "true")
	if err := search.SetSeriesACL(r.Context(), h.pool, id, entries, override); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// apiEventACL is the External API ACL write (PUT /api/events/{id}/acl,
// bare ace-array form, 204). It funnels through the same model as the
// admin-ng path above: stored faithfully, reported truthfully, deny vetoes.
func (h *handler) apiEventACL(w http.ResponseWriter, r *http.Request, p search.Principal) {
	id, ok := h.requireEventWrite(w, r, p)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	entries, err := parseACEs(r.PostFormValue("acl"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := search.SetACL(r.Context(), h.pool, acl.ScopeEvent, id, entries); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent) // 204: the shape existing clients expect
}

// APIEventACL exposes the External API ACL write for searchapi to mount on
// its /api mux — ONE implementation for both mounts (the 5.6/A1 posture:
// never two divergent handlers for one wire behaviour).
func APIEventACL(pool *pgxpool.Pool, opts ...Option) http.HandlerFunc {
	h := newHandler(pool, opts)
	return h.auth(h.apiEventACL)
}

// ---- the wizard metadata document -------------------------------------------

type wizardField struct {
	ID    string          `json:"id"`
	Value json.RawMessage `json:"value"`
}

type wizardCatalog struct {
	Flavor string        `json:"flavor"`
	Fields []wizardField `json:"fields"`
}

func fieldString(v json.RawMessage) string {
	var s string
	if json.Unmarshal(v, &s) == nil {
		return s
	}
	return ""
}

func fieldStrings(v json.RawMessage) []string {
	var out []string
	if json.Unmarshal(v, &out) == nil {
		return out
	}
	return nil
}

// splitSubjects maps the wizard's single subject text field onto the typed
// subjects list (comma-separated, as the read surface joins it back).
func splitSubjects(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// applyEventFields merges one wizard field set into the episode DC state.
// Fields NOT present are untouched — this one function is both create (full
// field set sent) and the PARTIAL edit (changed fields only, the measured
// semantics). publisher/rightsHolder are accepted and dropped: ocng carries
// neither (the read surface renders rightsHolder as "" — increment 5).
func applyEventFields(fields []wizardField, title *string, start **time.Time, md *mediapackage.Metadata) error {
	for _, f := range fields {
		switch f.ID {
		case "title":
			*title = fieldString(f.Value)
		case "startDate":
			v := fieldString(f.Value)
			if v == "" {
				continue
			}
			ts, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return fmt.Errorf("startDate %q: %w", v, err)
			}
			*start = &ts
		case "subject":
			md.Subjects = splitSubjects(fieldString(f.Value))
		case "description":
			md.Description = fieldString(f.Value)
		case "language":
			md.Language = fieldString(f.Value)
		case "license":
			md.License = fieldString(f.Value)
		case "isPartOf":
			md.SeriesID = fieldString(f.Value)
		case "creator":
			md.Creators = fieldStrings(f.Value)
		case "contributor":
			md.Contributors = fieldStrings(f.Value)
		case "location":
			md.Location = fieldString(f.Value)
		}
	}
	return nil
}

func applySeriesFields(fields []wizardField, md *mediapackage.SeriesMetadata) {
	for _, f := range fields {
		switch f.ID {
		case "title":
			md.Title = fieldString(f.Value)
		case "description":
			md.Description = fieldString(f.Value)
		case "language":
			md.Language = fieldString(f.Value)
		case "subject":
			md.Subjects = splitSubjects(fieldString(f.Value))
		case "creator":
			md.Organizers = fieldStrings(f.Value)
		case "contributor":
			md.Contributors = fieldStrings(f.Value)
		}
	}
}

// ---- create -----------------------------------------------------------------

// newEventDoc is the metadata part of POST /admin-ng/event/new — the admin
// UI's create-event wizard payload.
type newEventDoc struct {
	Metadata   []wizardCatalog `json:"metadata"`
	Processing struct {
		Workflow      string            `json:"workflow"`
		Configuration map[string]string `json:"configuration"`
	} `json:"processing"`
	Access struct {
		ACL struct {
			ACE []aceJSON `json:"ace"`
		} `json:"acl"`
	} `json:"access"`
	Source struct {
		Type string `json:"type"`
	} `json:"source"`
	Assets struct {
		Options []struct {
			ID            string `json:"id"`
			Type          string `json:"type"`
			FlavorType    string `json:"flavorType"`
			FlavorSubType string `json:"flavorSubType"`
		} `json:"options"`
	} `json:"assets"`
}

// stashCAS spools one uploaded part to disk and stores it content-addressed
// (the same spool-then-PutFile shape as ingest's stashUpload — the hash IS
// the key, so the bytes must be fully known first; disk, never memory).
func (h *handler) stashCAS(ctx context.Context, r io.Reader) (sha string, size int64, err error) {
	tmp, err := os.CreateTemp("", "ocng-adminwrite-*")
	if err != nil {
		return "", 0, err
	}
	defer os.Remove(tmp.Name())
	size, err = io.Copy(tmp, r)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", 0, fmt.Errorf("spooling upload: %w", err)
	}
	sha, err = h.store.PutFile(ctx, tmp.Name())
	if err != nil {
		return "", 0, err
	}
	return sha, size, nil
}

func (h *handler) eventNew(w http.ResponseWriter, r *http.Request, p search.Principal) {
	if !canCreate(p) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if h.store == nil || h.engine == nil || h.defs == nil {
		http.Error(w, "write surface not wired (no store/engine/definitions)", http.StatusInternalServerError)
		return
	}
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "multipart/form-data required", http.StatusBadRequest)
		return
	}

	// stream the parts in wire order: file parts go straight to CAS (they
	// arrive BEFORE the metadata part in the captured real-client request),
	// small form fields are buffered
	type upload struct {
		field, filename, mimetype, sha string
		size                           int64
	}
	var uploads []upload
	var metaRaw []byte
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if part.FileName() == "" {
			val, err := io.ReadAll(io.LimitReader(part, 10<<20))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if part.FormName() == "metadata" {
				metaRaw = val
			}
			continue
		}
		sha, size, err := h.stashCAS(r.Context(), part)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		mimetype := part.Header.Get("Content-Type")
		if mimetype == "" {
			mimetype = "application/octet-stream"
		}
		uploads = append(uploads, upload{
			field: part.FormName(), filename: part.FileName(),
			mimetype: mimetype, sha: sha, size: size,
		})
	}
	if len(metaRaw) == 0 {
		http.Error(w, "metadata part is required", http.StatusBadRequest)
		return
	}
	var doc newEventDoc
	if err := json.Unmarshal(metaRaw, &doc); err != nil {
		http.Error(w, "unparseable metadata: "+err.Error(), http.StatusBadRequest)
		return
	}
	def, ok, err := h.defs.Definition(r.Context(), doc.Processing.Workflow)
	if err != nil {
		http.Error(w, "definition lookup: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, fmt.Sprintf("workflow definition %q not registered", doc.Processing.Workflow), http.StatusBadRequest)
		return
	}

	// wizard fields → episode DC state
	var title string
	var start *time.Time
	var md mediapackage.Metadata
	for _, cat := range doc.Metadata {
		if cat.Flavor != "dublincore/episode" {
			continue
		}
		if err := applyEventFields(cat.Fields, &title, &start, &md); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	now := time.Now().UTC()
	md.Created = &now

	// asset options map the track_* field names onto flavors
	flavors := map[string]string{}
	for _, o := range doc.Assets.Options {
		flavors[o.ID] = o.FlavorType + "/" + o.FlavorSubType
	}

	mpID := uuid.NewString()
	m := mediapackage.Manifest{ID: mpID, Title: title, Start: start}
	byURL := map[string]string{} // staged pseudo-URL → CAS sha
	for _, u := range uploads {
		base := u.field
		if i := strings.LastIndexByte(base, '.'); i > 0 {
			base = base[:i] // track_presenter.0 → track_presenter
		}
		flavor, ok := flavors[base]
		if !ok {
			http.Error(w, fmt.Sprintf("upload field %q matches no asset option", u.field), http.StatusBadRequest)
			return
		}
		url := "cas:" + u.sha + "/" + u.filename
		byURL[url] = u.sha
		m.Elements = append(m.Elements, mediapackage.ManifestElement{
			ID: uuid.NewString(), Kind: "track", Flavor: flavor,
			Mimetype: u.mimetype, URL: url,
		})
	}
	resolve := func(url string) (io.ReadCloser, error) {
		sha, ok := byURL[url]
		if !ok {
			return nil, fmt.Errorf("element url %q is not an upload of this request", url)
		}
		return h.store.Get(r.Context(), sha)
	}

	// materialise through the ONE write path the loader and ingest share,
	// then the typed DC state, then the ACL through the corrected model
	if _, err := mediapackage.Materialise(r.Context(), h.pool, h.store, m, resolve); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := mediapackage.SetEventDC(r.Context(), h.pool, mpID, title, start, md); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	entries := make([]acl.Entry, 0, len(doc.Access.ACL.ACE))
	for _, a := range doc.Access.ACL.ACE {
		if a.Role == "" || a.Action == "" {
			http.Error(w, fmt.Sprintf("acl entry missing role or action: %+v", a), http.StatusBadRequest)
			return
		}
		entries = append(entries, acl.Entry{Role: a.Role, Action: a.Action, Allow: a.Allow})
	}
	if err := search.SetACL(r.Context(), h.pool, acl.ScopeEvent, mpID, entries); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := h.engine.CreateWorkflow(r.Context(), mpID, def); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	io.WriteString(w, mpID) // 201 body: the new id, as the admin UI expects
}

type newSeriesDoc struct {
	Metadata []wizardCatalog `json:"metadata"`
	Access   struct {
		ACL struct {
			ACE []aceJSON `json:"ace"`
		} `json:"acl"`
	} `json:"access"`
}

func (h *handler) seriesNew(w http.ResponseWriter, r *http.Request, p search.Principal) {
	if !canCreate(p) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	var doc newSeriesDoc
	if err := json.Unmarshal([]byte(r.PostFormValue("metadata")), &doc); err != nil {
		http.Error(w, "unparseable metadata: "+err.Error(), http.StatusBadRequest)
		return
	}
	var md mediapackage.SeriesMetadata
	for _, cat := range doc.Metadata {
		if cat.Flavor != "dublincore/series" {
			continue
		}
		applySeriesFields(cat.Fields, &md)
	}
	now := time.Now().UTC()
	md.Created = &now

	id := uuid.NewString()
	if err := mediapackage.PutSeries(r.Context(), h.pool, id, md); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(doc.Access.ACL.ACE) > 0 {
		entries := make([]acl.Entry, 0, len(doc.Access.ACL.ACE))
		for _, a := range doc.Access.ACL.ACE {
			entries = append(entries, acl.Entry{Role: a.Role, Action: a.Action, Allow: a.Allow})
		}
		if err := search.SetACL(r.Context(), h.pool, acl.ScopeSeries, id, entries); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusCreated)
	io.WriteString(w, id)
}

// ---- edit (PARTIAL merge — the measured semantics) ---------------------------

func (h *handler) eventMetadataEdit(w http.ResponseWriter, r *http.Request, p search.Principal) {
	id, ok := h.requireEventWrite(w, r, p)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	var catalogs []wizardCatalog
	if err := json.Unmarshal([]byte(r.PostFormValue("metadata")), &catalogs); err != nil {
		http.Error(w, "unparseable metadata: "+err.Error(), http.StatusBadRequest)
		return
	}
	// read current → merge only the fields sent → write whole state
	title, start, md, err := mediapackage.GetEventDC(r.Context(), h.pool, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, cat := range catalogs {
		if cat.Flavor != "dublincore/episode" {
			continue
		}
		if err := applyEventFields(cat.Fields, &title, &start, &md); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if err := mediapackage.SetEventDC(r.Context(), h.pool, id, title, start, md); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *handler) seriesMetadataEdit(w http.ResponseWriter, r *http.Request, p search.Principal) {
	id, ok := h.requireSeriesWrite(w, r, p)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	var catalogs []wizardCatalog
	if err := json.Unmarshal([]byte(r.PostFormValue("metadata")), &catalogs); err != nil {
		http.Error(w, "unparseable metadata: "+err.Error(), http.StatusBadRequest)
		return
	}
	md, found, err := mediapackage.GetSeriesDC(r.Context(), h.pool, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	for _, cat := range catalogs {
		if cat.Flavor != "dublincore/series" {
			continue
		}
		applySeriesFields(cat.Fields, &md)
	}
	if err := mediapackage.PutSeries(r.Context(), h.pool, id, md); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ---- delete (the approved soft half; archive hard-delete HELD) ---------------

func (h *handler) eventDelete(w http.ResponseWriter, r *http.Request, p search.Principal) {
	id, ok := h.requireEventWrite(w, r, p)
	if !ok {
		return
	}
	found, err := mediapackage.TombstoneEvent(r.Context(), h.pool, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *handler) seriesDelete(w http.ResponseWriter, r *http.Request, p search.Principal) {
	id, ok := h.requireSeriesWrite(w, r, p)
	if !ok {
		return
	}
	found, err := mediapackage.TombstoneSeries(r.Context(), h.pool, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
}
