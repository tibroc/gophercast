package ingest

import (
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"ocng/internal/engine"
	"ocng/internal/mediapackage"
)

// Endpoint semantics follow recorded wire captures of the legacy system —
// statuses, content types, field handling and the bearer round-trip are all
// measured, not read from docs.

func (h *handler) route(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimSuffix(r.URL.Path, "/")
	switch {
	case r.Method == http.MethodGet && p == "/ingest/createMediaPackage":
		h.createMediaPackage(w, r)
	case r.Method == http.MethodPost && p == "/ingest/addDCCatalog":
		h.addDCCatalog(w, r)
	case r.Method == http.MethodPost && p == "/ingest/addTrack":
		h.addTrack(w, r)
	case r.Method == http.MethodPost && p == "/ingest/ingest":
		h.ingest(w, r, "")
	case r.Method == http.MethodPost && strings.HasPrefix(p, "/ingest/ingest/"):
		h.ingest(w, r, strings.TrimPrefix(p, "/ingest/ingest/"))
	default:
		http.NotFound(w, r)
	}
}

// authorized delegates to the process-wide extraction layer (T1 step 1) —
// machine deposits are a service credential, resolved by authn (dev seam:
// the increment-3 Basic shim over Options.Users; production: OIDC
// client-credentials, a later T1 step). Any failure is 403, the legacy
// system's measured anonymous response on /ingest.
func (h *handler) authorized(r *http.Request) bool {
	return h.o.Auth.Service(r)
}

func writeXML(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// createMediaPackage mints the mediapackage: server-assigned id, deposit
// time as the start attribute (rewritten from the DC at ingest — the
// measured behaviour), everything else empty. No database row yet: the
// bearer document IS the state until /ingest/ingest.
func (h *handler) createMediaPackage(w http.ResponseWriter, r *http.Request) {
	m := mediapackage.Manifest{ID: uuid.NewString(), Start: nowSecond()}
	writeXML(w, emitBearer(m))
}

func (h *handler) stagedURL(r *http.Request, sha, filename string) string {
	return "http://" + r.Host + "/ingest/staged/" + sha + "/" + filename
}

var stagedShaRe = regexp.MustCompile(`/ingest/staged/([0-9a-f]{64})/`)

func (h *handler) addDCCatalog(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	mpXML, dc, flavor := r.PostFormValue("mediaPackage"), r.PostFormValue("dublinCore"), r.PostFormValue("flavor")
	if mpXML == "" || dc == "" || flavor == "" {
		http.Error(w, "mediaPackage, dublinCore and flavor are required", http.StatusBadRequest)
		return
	}
	m, err := parseBearer([]byte(mpXML))
	if err != nil {
		http.Error(w, "unparseable mediaPackage: "+err.Error(), http.StatusBadRequest)
		return
	}
	sha, _, err := stashUpload(r.Context(), h.o.Store, strings.NewReader(dc))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	m.Elements = append(m.Elements, mediapackage.ManifestElement{
		ID:       uuid.NewString(),
		Kind:     "catalog",
		Flavor:   flavor,
		Mimetype: "text/xml", // the legacy system's measured catalog mimetype
		URL:      h.stagedURL(r, sha, "dublincore.xml"),
	})
	writeXML(w, emitBearer(m))
}

// addTrack consumes the multipart stream strictly in wire order: form
// fields BEFORE the file part (load-bearing legacy Opencast behaviour,
// CONTRACTS §1.2 rows 116-118 — fields after the file are never seen, a
// missing required field is 400, trailing fields are ignored). The file
// bytes stream through a disk spool into CAS, never into memory.
func (h *handler) addTrack(w http.ResponseWriter, r *http.Request) {
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "multipart/form-data required", http.StatusBadRequest)
		return
	}
	fields := map[string]string{}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			// stream ended without a file part
			http.Error(w, "no file part (BODY) in request", http.StatusBadRequest)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if part.FileName() == "" {
			// an ordinary form field, buffered (small by construction)
			val, err := io.ReadAll(io.LimitReader(part, 10<<20))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			fields[part.FormName()] = string(val)
			continue
		}

		// The file part. Required fields must already have arrived —
		// anything after this part is deliberately never read.
		mpXML, flavor := fields["mediaPackage"], fields["flavor"]
		if mpXML == "" || flavor == "" {
			http.Error(w, "mediaPackage and flavor must precede the file part", http.StatusBadRequest)
			return
		}
		m, err := parseBearer([]byte(mpXML))
		if err != nil {
			http.Error(w, "unparseable mediaPackage: "+err.Error(), http.StatusBadRequest)
			return
		}
		sha, _, err := stashUpload(r.Context(), h.o.Store, part)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		mimetype := part.Header.Get("Content-Type")
		if mimetype == "" {
			mimetype = "application/octet-stream"
		}
		filename := path.Base(part.FileName())
		if filename == "" || filename == "." || filename == "/" {
			filename = "track"
		}
		m.Elements = append(m.Elements, mediapackage.ManifestElement{
			ID:       uuid.NewString(),
			Kind:     "track",
			Flavor:   flavor,
			Mimetype: mimetype,
			URL:      h.stagedURL(r, sha, filename),
		})
		writeXML(w, emitBearer(m))
		return
	}
}

// ingest closes the deposit: parse the bearer back, derive title/start from
// the episode DC (the measured archive-time rewrite), materialise through
// the loader's own write path, start the named workflow.
func (h *handler) ingest(w http.ResponseWriter, r *http.Request, wdID string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}

	// EXPLICIT REFUSAL (deliberate design decision, revisit at the
	// scheduler increment): legacy Opencast's workflowInstanceId handling
	// silently renames the mediapackage to bind it to a scheduled event.
	// ocng has no scheduler to bind to — fail loud, not silent, and
	// materialise nothing.
	if v := r.PostFormValue("workflowInstanceId"); v != "" {
		http.Error(w, "workflowInstanceId is not supported: ocng has no scheduler to bind a legacy mediapackage id to (revisit at the scheduler increment)", http.StatusBadRequest)
		return
	}

	mpXML := r.PostFormValue("mediaPackage")
	if mpXML == "" {
		http.Error(w, "mediaPackage is required", http.StatusBadRequest)
		return
	}
	if wdID == "" {
		wdID = r.PostFormValue("workflowDefinitionId")
	}
	var def engine.Definition
	var ok bool
	if h.o.Definitions != nil {
		var err error
		def, ok, err = h.o.Definitions.Definition(r.Context(), wdID)
		if err != nil {
			http.Error(w, "definition lookup: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if !ok {
		http.Error(w, fmt.Sprintf("workflow definition %q not registered", wdID), http.StatusNotFound)
		return
	}
	m, err := parseBearer([]byte(mpXML))
	if err != nil {
		http.Error(w, "unparseable mediaPackage: "+err.Error(), http.StatusBadRequest)
		return
	}

	// resolve staged bytes straight from CAS — the URL carries the hash
	resolve := func(url string) (io.ReadCloser, error) {
		sm := stagedShaRe.FindStringSubmatch(url)
		if sm == nil {
			return nil, fmt.Errorf("ingest: element url %q is not a staged upload of this instance", url)
		}
		return h.o.Store.Get(r.Context(), sm[1])
	}

	// title/start from the episode DC — the measured derivation
	for _, el := range m.Elements {
		if el.Kind != "catalog" || el.Flavor != "dublincore/episode" {
			continue
		}
		rc, err := resolve(el.URL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		raw, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		title, start, err := dcDerive(raw)
		if err != nil {
			http.Error(w, "unparseable episode DublinCore: "+err.Error(), http.StatusBadRequest)
			return
		}
		if title != "" {
			m.Title = title
		}
		if start != nil {
			m.Start = start
		}
		break
	}

	mpID, err := mediapackage.Materialise(r.Context(), h.o.Pool, h.o.Store, m, resolve)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	wfID, err := h.o.Engine.CreateWorkflow(r.Context(), mpID, def)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Minimal workflow-instance response: enough for a client to learn the
	// workflow id (the observed usage of the captured clients). Full
	// wf:workflow document parity is NOT attempted here — a recorded
	// deferral; the workflow REST surface is a later increment.
	body := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`+
		`<wf:workflow xmlns:wf="http://workflow.opencastproject.org" xmlns:mp="%s" id="%d" state="INSTANTIATED"><wf:template>%s</wf:template><wf:mediaPackageId>%s</wf:mediaPackageId></wf:workflow>`,
		mpNamespace, wfID, esc(wdID), esc(mpID))
	writeXML(w, []byte(body))
}
