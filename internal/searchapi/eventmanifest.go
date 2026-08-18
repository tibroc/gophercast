// Player increment (D-047): the enriched GET /api/events/{id} — the
// External-API event shape the paella-opencast DATAPASS integration reads
// (APIEventConversor.ts; autodiscovery keys on identifier+publications).
//
// Two authorities decide visibility, OR-ed (D-047):
//   - the archive ACL read (search.APIEvents — the gate every authenticated
//     /api consumer goes through, unchanged), OR
//   - the published pin (search.EngageEpisode) — the D-044 delivery
//     authority. The manifest is readable exactly when the bytes would
//     serve, anonymous ROLE_ANONYMOUS included. Get-by-id is deliberately
//     the ONE /api route that admits anonymous principals; every other
//     /api route keeps the blanket 403 for anonymous callers.
//
// The publications LISTING inside the body reuses the D-044 pin rule
// (serve.Authorized): a publication whose pin refuses the principal is not
// listed, so the manifest never names element UUIDs delivery would 403 —
// same rule as GET /publications/{id}.
//
// Deliberate shape decisions in this body: element URLs are origin-relative
// /elements/{id}/{filename} (same-origin serving is the point); checksum
// omitted; security-policy attachments absent (migration skips them);
// tech-derived track fields omitted when no probe data exists (migration
// imports no ffprobe output — fabricating has_audio would be a lie);
// archive_version / has_previews / creator / processing_state and the
// withmetadata form-array are not emitted (nothing player-visible reads
// them; rightsholder/source render "" — the increment-5 read-surface
// decision, adminapi/write.go).
package searchapi

import (
	"context"
	"mime"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/acl"
	"ocng/internal/search"
	"ocng/internal/serve"
)

type apiEventElement struct {
	ID        string   `json:"id"`
	Mediatype string   `json:"mediatype"`
	URL       string   `json:"url"`
	Flavor    string   `json:"flavor"`
	Size      int64    `json:"size"`
	Tags      []string `json:"tags"`

	// track-only technical fields, present only when the inspect op probed
	// the bytes (mp_element.tech); the conversor tolerates absence.
	HasAudio   *bool    `json:"has_audio,omitempty"`
	HasVideo   *bool    `json:"has_video,omitempty"`
	DurationMS *int64   `json:"duration,omitempty"`
	Width      *int     `json:"width,omitempty"`
	Height     *int     `json:"height,omitempty"`
	Framerate  *float64 `json:"framerate,omitempty"`
	Framecount *int64   `json:"framecount,omitempty"`
	IsMaster   *bool    `json:"is_master_playlist,omitempty"`
	IsLive     *bool    `json:"is_live,omitempty"`
}

type apiEventPublication struct {
	ID          string            `json:"id"`
	Channel     string            `json:"channel"`
	Mediatype   string            `json:"mediatype"`
	URL         string            `json:"url"`
	Media       []apiEventElement `json:"media"`
	Attachments []apiEventElement `json:"attachments"`
	Metadata    []apiEventElement `json:"metadata"`
}

type apiACLEntry struct {
	Allow  bool   `json:"allow"`
	Action string `json:"action"`
	Role   string `json:"role"`
}

// apiEventBody is the enriched get-by-id response. Key set and value
// semantics follow the External-API event schema; JSON key order is not
// contract (reproduce the observable, normalize below it).
type apiEventBody struct {
	Identifier        string                `json:"identifier"`
	Title             string                `json:"title"`
	Description       string                `json:"description"`
	Subjects          []string              `json:"subjects"`
	Language          string                `json:"language"`
	Rightsholder      string                `json:"rightsholder"`
	License           string                `json:"license"`
	IsPartOf          string                `json:"is_part_of"`
	Series            string                `json:"series"`
	Presenter         []string              `json:"presenter"`
	Contributor       []string              `json:"contributor"`
	Start             string                `json:"start"`
	Created           string                `json:"created"`
	DurationMS        int64                 `json:"duration"`
	Location          string                `json:"location"`
	Source            string                `json:"source"`
	Status            string                `json:"status"`
	PublicationStatus []string              `json:"publication_status"`
	ACL               []apiACLEntry         `json:"acl,omitempty"`
	Publications      []apiEventPublication `json:"publications,omitempty"`
}

// visibleForManifest is the D-047 OR: archive-readable (the authenticated
// /api gate) or pin-readable (the delivery authority).
func visibleForManifest(ctx context.Context, pool *pgxpool.Pool, p search.Principal, id string) (bool, error) {
	for _, surface := range []search.Surface{search.APIEvents, search.EngageEpisode} {
		res, err := search.Events(ctx, pool, p, search.Query{Surface: surface, ByID: id, Limit: 1})
		if err != nil {
			return false, err
		}
		if len(res.Items) == 1 {
			return true, nil
		}
	}
	return false, nil
}

func buildAPIEventBody(ctx context.Context, pool *pgxpool.Pool, p search.Principal, id string, withACL, withPublications bool) (apiEventBody, error) {
	disp, err := search.EventDisplayByID(ctx, pool, id)
	if err != nil {
		return apiEventBody{}, err
	}
	body := apiEventBody{
		Identifier:  disp.ID,
		Title:       disp.Title,
		Description: disp.Description,
		Subjects:    strsOrEmpty(disp.Subjects),
		Language:    disp.Language,
		License:     disp.License,
		IsPartOf:    disp.SeriesID,
		Series:      disp.SeriesTitle,
		Presenter:   strsOrEmpty(disp.Presenters),
		Contributor: strsOrEmpty(disp.Contributors),
		Location:    disp.Location,
		Status:      disp.Status,
	}
	if disp.StartDate != nil {
		body.Start = disp.StartDate.UTC().Format(time.RFC3339)
	}
	if disp.Created != nil {
		body.Created = disp.Created.UTC().Format(time.RFC3339)
	}
	if disp.DurationMs != nil {
		body.DurationMS = *disp.DurationMs
	}

	if withACL {
		entries, _, err := acl.Get(ctx, pool, acl.ScopeEvent, id)
		if err != nil {
			return apiEventBody{}, err
		}
		body.ACL = make([]apiACLEntry, 0, len(entries))
		for _, e := range entries {
			body.ACL = append(body.ACL, apiACLEntry{Allow: e.Allow, Action: e.Action, Role: e.Role})
		}
	}

	pubs, status, err := publicationsFor(ctx, pool, p, id)
	if err != nil {
		return apiEventBody{}, err
	}
	body.PublicationStatus = status
	if withPublications {
		body.Publications = pubs
	}
	return body, nil
}

// publicationsFor lists the event's publications with their elements,
// FILTERED by the D-044 pin rule — the same decision delivery makes, so the
// manifest and the byte surface can never disagree. publication_status
// carries only the channels the principal may see (a hidden publication is
// not announced either).
func publicationsFor(ctx context.Context, pool *pgxpool.Pool, p search.Principal, mpID string) ([]apiEventPublication, []string, error) {
	rows, err := pool.Query(ctx, `
		select p.id::text, p.channel, p.acl_read, p.acl_state,
		       e.id, e.kind, e.flavor, coalesce(e.mimetype,''), e.size_bytes,
		       coalesce(e.source_url,''), e.tech,
		       coalesce((select array_agg(t.tag order by t.tag)
		                 from mp_element_tag t where t.element_id = e.id), '{}')
		from publication p
		join publication_element pe on pe.publication_id = p.id
		join mp_element e on e.id = pe.element_id
		where p.mediapackage_id = $1
		order by p.channel, e.kind, e.flavor, e.id`, mpID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var pubs []apiEventPublication
	var status []string
	for rows.Next() {
		var pin serve.PublicationPin
		var pubID, elID, kind, flavor, mimetype, sourceURL string
		var size int64
		var tech *elementTech
		var tags []string
		pin.MediapackageID = mpID
		if err := rows.Scan(&pubID, &pin.Channel, &pin.ACLRead, &pin.ACLState,
			&elID, &kind, &flavor, &mimetype, &size, &sourceURL, &tech, &tags); err != nil {
			return nil, nil, err
		}
		if !serve.Authorized([]serve.PublicationPin{pin}, p) {
			continue
		}
		if len(pubs) == 0 || pubs[len(pubs)-1].ID != pubID {
			pubs = append(pubs, apiEventPublication{
				ID: pubID, Channel: pin.Channel,
				Mediatype: "text/html", URL: "/play/" + mpID,
				Media: []apiEventElement{}, Attachments: []apiEventElement{}, Metadata: []apiEventElement{},
			})
			status = append(status, pin.Channel)
		}
		el := apiEventElement{
			ID: elID, Mediatype: mimetype, Flavor: flavor, Size: size,
			Tags: strsOrEmpty(tags),
			URL:  elementURL(elID, sourceURL, mimetype),
		}
		cur := &pubs[len(pubs)-1]
		switch kind {
		case "track":
			if tech != nil {
				el.applyTech(*tech)
			}
			cur.Media = append(cur.Media, el)
		case "attachment":
			cur.Attachments = append(cur.Attachments, el)
		default: // catalog
			cur.Metadata = append(cur.Metadata, el)
		}
	}
	if status == nil {
		status = []string{}
	}
	return pubs, status, rows.Err()
}

// elementTech mirrors mediapackage.Tech's JSONB (kept locally to avoid
// widening that package's surface for a read).
type elementTech struct {
	DurationMS int64   `json:"duration_ms"`
	Width      int     `json:"width,omitempty"`
	Height     int     `json:"height,omitempty"`
	Framecount int64   `json:"framecount,omitempty"`
	Framerate  float64 `json:"framerate,omitempty"`
	Channels   int     `json:"channels,omitempty"`
	SampleRate int     `json:"samplerate,omitempty"`
}

func (el *apiEventElement) applyTech(t elementTech) {
	hasAudio := t.Channels > 0
	hasVideo := t.Width > 0
	f := false
	el.HasAudio, el.HasVideo = &hasAudio, &hasVideo
	el.DurationMS = &t.DurationMS
	el.IsMaster, el.IsLive = &f, &f
	if hasVideo {
		el.Width, el.Height = &t.Width, &t.Height
		el.Framerate, el.Framecount = &t.Framerate, &t.Framecount
	}
}

// elementURL builds the origin-relative delivery URL with a decorative
// trailing filename: Paella derives caption format from the URL's last
// dot-segment, so the segment must end in a real extension. Preference:
// the element's original basename; else an extension synthesized from the
// mimetype.
func elementURL(elID, sourceURL, mimetype string) string {
	name := path.Base(sourceURL)
	if name == "." || name == "/" {
		name = ""
	}
	if name == "" || path.Ext(name) == "" {
		name = elID + extForMime(mimetype)
	}
	return "/elements/" + elID + "/" + url.PathEscape(name)
}

// extForMime: the small closed set this system produces, with a stdlib
// fallback. text/vtt is the load-bearing one (Paella's caption format
// derivation); mime.ExtensionsByType maps it to .vtt too, but pinning the
// player-critical cases keeps them independent of the host's mime tables.
func extForMime(mimetype string) string {
	switch mimetype {
	case "text/vtt":
		return ".vtt"
	case "video/mp4":
		return ".mp4"
	case "image/jpeg":
		return ".jpg"
	case "text/xml", "application/xml":
		return ".xml"
	}
	if exts, err := mime.ExtensionsByType(mimetype); err == nil && len(exts) > 0 {
		return exts[0]
	}
	return ""
}

func strsOrEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// apiEventByIDFull is the player-increment get-by-id handler (mounted
// without the blanket auth gate — D-047 makes anonymous a first-class
// principal here; every OTHER /api route keeps the anonymous 403).
func (h *handler) apiEventByIDFull(w http.ResponseWriter, r *http.Request) {
	p, _ := h.authn.Principal(r) // anonymous → ROLE_ANONYMOUS principal
	id := r.PathValue("id")
	ok, err := visibleForManifest(r.Context(), h.pool, p, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !ok {
		// invisible get-by-id stays 404 (information-hiding semantics)
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	body, err := buildAPIEventBody(r.Context(), h.pool, p, id,
		q.Get("withacl") == "true", q.Get("withpublications") == "true")
	if err != nil {
		http.Error(w, "manifest build failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, body)
}
