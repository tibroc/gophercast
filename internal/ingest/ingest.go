// Package ingest is the increment-3 capture-agent-shaped ingest surface:
// the 5-endpoint subset of the legacy Opencast /ingest API that the convergence
// done-condition requires:
//
//	GET  /ingest/createMediaPackage
//	POST /ingest/addDCCatalog
//	POST /ingest/addTrack            (file variant, fields-before-file)
//	POST /ingest/ingest
//	POST /ingest/ingest/{wdID}
//
// The client holds the mediapackage XML as an opaque bearer string between
// calls (D-021); uploaded bytes stream into CAS immediately, so the bearer
// document IS the staging state — no staging table. /ingest/ingest parses
// the bearer back and materialises it through the same function the loader
// uses (mediapackage.Materialise), which is what makes convergence
// structural rather than coincidental.
package ingest

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/authn"
	"ocng/internal/cas"
	"ocng/internal/definitions"
	"ocng/internal/engine"
)

// Options wires the handler to the same storage + element-row path the
// loader writes. Definitions is the explicit contract for which workflow a
// deposit starts — since T5 a Source (the assembled binary wires the
// DB-backed definitions.Registry, ADR-009's execution source of truth;
// tests pass definitions.Static). Nil = no workflows accepted.
type Options struct {
	Pool        *pgxpool.Pool
	Store       *cas.Store
	Engine      *engine.Engine
	Definitions definitions.Source
	// Users is the dev auth shim (increment 3). When Auth is nil, NewHandler
	// wraps it in the dev-seam authenticator — unchanged pre-T1 semantics
	// for in-process test construction. Anonymous requests get 403, the
	// legacy system's measured behaviour on /ingest.
	Users map[string]string
	// Auth is the process-wide extraction layer (T1 step 1). The assembled
	// binary wires it; nil defaults to the dev seam over Users.
	Auth *authn.Authenticator
}

type handler struct {
	o Options
}

// NewHandler returns the /ingest HTTP surface.
func NewHandler(o Options) http.Handler {
	if o.Auth == nil {
		o.Auth = authn.DevSeam(o.Users)
	}
	return &handler{o: o}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		// 403 for every auth failure — the legacy system's measured
		// anonymous response on this surface
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}
	h.route(w, r)
}
