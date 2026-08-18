// Pure-logic tests for the event-manifest helpers: the delivery-URL
// filename synthesis (Paella derives a caption's format from the URL's
// last dot-segment, so the synthesized segment must end in a real
// extension) and the tech-field projection. The end-to-end manifest tests
// (visibility OR, pin-filtered publication listing, the full event body)
// require Postgres and live in the integration suite, which is not part
// of this repository.
package searchapi

import "testing"

func TestElementURL(t *testing.T) {
	cases := []struct {
		name, elID, sourceURL, mimetype, want string
	}{
		{"real basename kept", "e1", "http://old.example/files/lecture.mp4", "video/mp4",
			"/elements/e1/lecture.mp4"},
		{"vtt from mimetype when no source name", "e2", "", "text/vtt",
			"/elements/e2/e2.vtt"},
		{"extensionless basename replaced", "e3", "http://old.example/files/track", "video/mp4",
			"/elements/e3/e3.mp4"},
		{"xml catalog", "e4", "", "text/xml",
			"/elements/e4/e4.xml"},
		{"unknown mimetype falls back to bare id", "e5", "", "application/x-unknown-nonsense",
			"/elements/e5/e5"},
		{"basename is escaped", "e6", "http://old.example/a b.mp4", "video/mp4",
			"/elements/e6/a%20b.mp4"},
	}
	for _, c := range cases {
		if got := elementURL(c.elID, c.sourceURL, c.mimetype); got != c.want {
			t.Errorf("%s: elementURL(%q,%q,%q) = %q, want %q",
				c.name, c.elID, c.sourceURL, c.mimetype, got, c.want)
		}
	}
}

func TestExtForMimePinsPlayerCriticalTypes(t *testing.T) {
	// pinned independent of the host's mime tables — text/vtt is the
	// load-bearing one (caption format derivation)
	for mt, want := range map[string]string{
		"text/vtt":        ".vtt",
		"video/mp4":       ".mp4",
		"image/jpeg":      ".jpg",
		"text/xml":        ".xml",
		"application/xml": ".xml",
	} {
		if got := extForMime(mt); got != want {
			t.Errorf("extForMime(%q) = %q, want %q", mt, got, want)
		}
	}
}

func TestApplyTech(t *testing.T) {
	// video track: full projection
	var el apiEventElement
	el.applyTech(elementTech{DurationMS: 90000, Width: 1280, Height: 720, Framerate: 25, Framecount: 2250, Channels: 2})
	if el.HasAudio == nil || !*el.HasAudio || el.HasVideo == nil || !*el.HasVideo {
		t.Fatal("channels>0 and width>0 must project has_audio/has_video true")
	}
	if el.Width == nil || *el.Width != 1280 || el.DurationMS == nil || *el.DurationMS != 90000 {
		t.Fatal("video dimensions and duration must be projected")
	}
	if el.IsMaster == nil || *el.IsMaster || el.IsLive == nil || *el.IsLive {
		t.Fatal("is_master_playlist/is_live must be explicit false on probed tracks")
	}

	// audio-only track: video fields stay absent, not zero
	var audio apiEventElement
	audio.applyTech(elementTech{DurationMS: 90000, Channels: 2})
	if audio.HasVideo == nil || *audio.HasVideo {
		t.Fatal("width 0 must project has_video false")
	}
	if audio.Width != nil || audio.Framerate != nil {
		t.Fatal("audio-only track must omit video dimensions, not emit zeros")
	}
}
