// Package coreinfo serves ocng-core's version/compatibility discovery
// endpoint, GET /ocng/version (D-040, closing ADR-012's open question).
//
// The endpoint is UNGATED and lives outside both /api and /admin-ng, so it is
// never itself version-negotiated: a frontend must be able to read it before it
// knows whether it is compatible. It advertises:
//
//   - core: ocng-core's own semver.
//   - adminng: an INTEGER contract revision of the /admin-ng surface, bumped
//     only on a BREAKING shape change, never on an additive one (D-040; the
//     admin UI tolerates unknown keys — yup is form-only, no strict validation,
//     verified 2026-08-16). A frontend states a required minimum and checks it
//     at startup; a rendered "incompatible" message replaces a blank page.
//   - api / api_default: the External API's own media-type-negotiated versions,
//     mirrored here (honour, don't reinvent). The one already-negotiated surface
//     keeps its mechanism.
//   - min_frontend: the oldest frontend build each image's assets, that this
//     core still serves without a soft-warning banner.
package coreinfo

import (
	"encoding/json"
	"net/http"
)

// AdminNGRevision is the /admin-ng contract revision this core serves.
// Increment 5 is the first revision. Bump ONLY on a breaking /admin-ng change.
const AdminNGRevision = 1

// CoreVersion is ocng-core's semver (placeholder until a release process
// stamps it; the shape is the contract, not this literal).
const CoreVersion = "0.5.0"

// Info is the GET /ocng/version body.
type Info struct {
	Core        string            `json:"core"`
	AdminNG     int               `json:"adminng"`
	API         []string          `json:"api"`
	APIDefault  string            `json:"api_default"`
	MinFrontend map[string]string `json:"min_frontend"`
}

// current mirrors the External API versions ocng serves. Measured on
// Opencast 20.2: v1.0.0…v1.11.0, default v1.11.0.
// Increment 4 built a subset; the list is the contract the
// External API negotiates by Accept media type.
func current() Info {
	return Info{
		Core:    CoreVersion,
		AdminNG: AdminNGRevision,
		API: []string{
			"v1.0.0", "v1.1.0", "v1.2.0", "v1.3.0", "v1.4.0", "v1.5.0",
			"v1.6.0", "v1.7.0", "v1.8.0", "v1.9.0", "v1.10.0", "v1.11.0",
		},
		APIDefault:  "v1.11.0",
		MinFrontend: map[string]string{"admin-interface": "0.0.0"},
	}
}

// Handler mounts GET /ocng/version (ungated).
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ocng/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(current())
	})
	return mux
}
