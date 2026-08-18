// Package watchpage serves GET /play/{id} — the player increment's watch
// page. It is the DATAPASS embedding of the paella-opencast web component
// (the upstream api_datapass example's pattern): the page itself fetches
// GET /api/events/{id}?withacl=true&withpublications=true same-origin (the
// serve-auth session cookie flows on the fetch exactly as on the media
// loads), then hands the JSON to <paella-opencast-player> via the
// opencast-episode attribute. The component's default /search/episode.json
// path is deliberately never used.
//
// The page is OURS and tracked; the Paella bundle it loads from /paella/
// is NOT — it is adopter-staged (D-048: upstream declares no license; ocng
// never redistributes it — deploy/README "Paella bundle").
//
// This is also the target of the manifest's publication URL: the text/html
// engage-player publication entry in the event body points here.
package watchpage

import (
	_ "embed"
	"net/http"
)

//go:embed watch.html
var watchHTML []byte

// Handler mounts GET /play/{id}. The page is static: authorization happens
// where the data is (the manifest fetch and the element loads), so serving
// the shell itself is ungated — an unauthorized viewer gets a shell whose
// data fetch answers 404/403, and the page says so.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /play/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(watchHTML)
	})
	return mux
}
