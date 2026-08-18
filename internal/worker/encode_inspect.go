// The increment-2 worker operations: encode and inspect.
//
// encode runs the LIVE-CAPTURED pinned invocation — the composer's actual
// process-table command line as observed at runtime, not the profile
// string (the composer adds -nostdin -nostats; see the pinned invocations
// record). Byte-diff against the pinned reference outputs is valid for
// exactly this vector on this host class: fast.http carries no VBV, and
// no-VBV x264 is byte-stable per thread count (measured determinism
// verdict).
//
// inspect REALLY probes the bytes (pinned ffprobe) — deliberately not a
// no-op over the loader's metadata: agreement with the stored manifest is
// a free cross-check of loader and probe, disagreement is a finding, and a
// no-op can never disagree. It stores the bounded Tech set relationally
// and does NOT rewrite the DublinCore catalog (recorded increment-2
// deviation: dc:extent re-serialisation is D-015/S1 territory).
package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/cas"
	"ocng/internal/engine"
	"ocng/internal/mediapackage"
	"ocng/internal/search"
)

// applyFlavor resolves a target-flavor pattern against a source flavor:
// '*' parts inherit the source's part (legacy Opencast's derived-flavor
// rule — "*/preview" on "presentation/source" yields
// "presentation/preview").
func applyFlavor(target, source string) string {
	tp := strings.SplitN(target, "/", 2)
	sp := strings.SplitN(source, "/", 2)
	if len(tp) != 2 || len(sp) != 2 {
		return target
	}
	if tp[0] == "*" {
		tp[0] = sp[0]
	}
	if tp[1] == "*" {
		tp[1] = sp[1]
	}
	return tp[0] + "/" + tp[1]
}

func encode(ctx context.Context, pool *pgxpool.Pool, store *cas.Store, cfg Config, task engine.Task) (any, func(context.Context, pgx.Tx) error, error) {
	mpID, err := engine.MediapackageID(ctx, pool, task.ID)
	if err != nil {
		return nil, nil, err
	}
	sourceFlavor := task.Config["source-flavor"]
	targetFlavor := task.Config["target-flavor"]
	profile := task.Config["encoding-profile"]
	if sourceFlavor == "" || targetFlavor == "" {
		return nil, nil, fmt.Errorf("task %d: source-flavor and target-flavor are required", task.ID)
	}
	// the only profile with a pinned, determinism-checked invocation; any
	// other profile would byte-diff against nothing
	if profile != "fast.http" {
		return nil, nil, fmt.Errorf("task %d: encoding-profile %q has no pinned invocation (only fast.http is pinned; a VBV profile would additionally need a semantic reference, which is out of the pinned scope)", task.ID, profile)
	}

	elements, err := mediapackage.Elements(ctx, pool, mpID)
	if err != nil {
		return nil, nil, err
	}
	source, err := selectSourceTrack(elements, sourceFlavor, task.ID)
	if err != nil {
		return nil, nil, err
	}

	dir, err := os.MkdirTemp(cfg.Scratch, fmt.Sprintf("task-%d-", task.ID))
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir)

	inPath := filepath.Join(dir, filepath.Base(source.SourceURL))
	if err := store.GetToFile(ctx, source.SHA256, inPath); err != nil {
		return nil, nil, fmt.Errorf("download: %w", err)
	}

	// the captured composer vector, verbatim:
	// ffmpeg -nostdin -nostats -i <in> -filter:v crop=in_w/2*2:in_h/2*2
	//   -c:a aac -c:v libx264 -preset faster -g 30 -pix_fmt yuv420p <out>
	outPath := filepath.Join(dir, "preview.mp4")
	ff := cfg.Command(ctx, filepath.Join(cfg.ToolsDir, "ffmpeg"),
		"-nostdin", "-nostats", "-i", inPath,
		"-filter:v", "crop=in_w/2*2:in_h/2*2",
		"-c:a", "aac", "-c:v", "libx264", "-preset", "faster", "-g", "30", "-pix_fmt", "yuv420p",
		outPath)
	if out, err := ff.CombinedOutput(); err != nil {
		return nil, nil, fmt.Errorf("ffmpeg: %w\n%s", err, tail(out))
	}
	st, err := os.Stat(outPath)
	if err != nil {
		return nil, nil, fmt.Errorf("ffmpeg produced no output: %w", err)
	}

	sum, err := store.PutFile(ctx, outPath)
	if err != nil {
		return nil, nil, fmt.Errorf("upload: %w", err)
	}

	element := mediapackage.Element{
		ID:             uuid.NewString(),
		MediapackageID: mpID,
		Kind:           "track",
		Flavor:         applyFlavor(targetFlavor, source.Flavor),
		Mimetype:       "video/mp4",
		SHA256:         sum,
		SizeBytes:      st.Size(),
	}
	var tags []string
	if tt := task.Config["target-tags"]; tt != "" {
		for _, tag := range strings.Split(tt, ",") {
			if tag = strings.TrimSpace(tag); tag != "" {
				tags = append(tags, tag)
			}
		}
	}
	result := map[string]string{"element": element.ID, "sha256": sum, "profile": profile, "flavor": element.Flavor}
	mutate := func(ctx context.Context, tx pgx.Tx) error {
		return mediapackage.InsertElement(ctx, tx, element, tags)
	}
	return result, mutate, nil
}

// ---- inspect ----

type ffprobeOut struct {
	Streams []struct {
		CodecType    string `json:"codec_type"`
		Width        int    `json:"width"`
		Height       int    `json:"height"`
		NbFrames     string `json:"nb_frames"`
		AvgFrameRate string `json:"avg_frame_rate"`
		Channels     int    `json:"channels"`
		SampleRate   string `json:"sample_rate"`
	} `json:"streams"`
	Format struct {
		Duration string `json:"duration"`
	} `json:"format"`
}

func inspect(ctx context.Context, pool *pgxpool.Pool, store *cas.Store, cfg Config, task engine.Task) (any, func(context.Context, pgx.Tx) error, error) {
	// ffprobe is op-scoped in the pin set (see pins.go): verify at use
	ffprobe := filepath.Join(cfg.ToolsDir, "ffprobe")
	if err := verifyTool(ffprobe, pinFFprobe); err != nil {
		return nil, nil, err
	}
	mpID, err := engine.MediapackageID(ctx, pool, task.ID)
	if err != nil {
		return nil, nil, err
	}
	elements, err := mediapackage.Elements(ctx, pool, mpID)
	if err != nil {
		return nil, nil, err
	}

	dir, err := os.MkdirTemp(cfg.Scratch, fmt.Sprintf("task-%d-", task.ID))
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir)

	probed := map[string]mediapackage.Tech{} // element id -> tech
	var maxDuration int64
	for _, el := range elements {
		if el.Kind != "track" {
			continue // inspect enriches tracks only (legacy Opencast semantics)
		}
		path := filepath.Join(dir, el.ID+filepath.Ext(el.SourceURL))
		if err := store.GetToFile(ctx, el.SHA256, path); err != nil {
			return nil, nil, fmt.Errorf("download %s: %w", el.ID, err)
		}
		out, err := cfg.Command(ctx, ffprobe,
			"-v", "error", "-show_format", "-show_streams", "-of", "json", path).Output()
		if err != nil {
			return nil, nil, fmt.Errorf("ffprobe %s: %w", el.ID, err)
		}
		var p ffprobeOut
		if err := json.Unmarshal(out, &p); err != nil {
			return nil, nil, fmt.Errorf("ffprobe json %s: %w", el.ID, err)
		}
		tech, err := techFromProbe(p)
		if err != nil {
			return nil, nil, fmt.Errorf("track %s: %w", el.ID, err)
		}
		probed[el.ID] = tech
		if tech.DurationMS > maxDuration {
			maxDuration = tech.DurationMS
		}
	}
	if len(probed) == 0 {
		// accept-no-media=false is legacy Opencast's shipped default: a
		// package with no probe-able track fails the operation
		return nil, nil, fmt.Errorf("task %d: no tracks to inspect", task.ID)
	}

	result := map[string]any{"inspected": len(probed), "duration_ms": maxDuration}
	mutate := func(ctx context.Context, tx pgx.Tx) error {
		for id, tech := range probed {
			if err := mediapackage.SetElementTech(ctx, tx, id, tech); err != nil {
				return err
			}
		}
		// overwrite=false (shipped default): only fill what the loader
		// did not know
		if err := mediapackage.SetDurationIfNull(ctx, tx, mpID, maxDuration); err != nil {
			return err
		}
		// duration_ms is a projected column (search_event) — refresh the
		// projection in the completion transaction (I3), same wiring as
		// every other projected-state writer (assembly finding A3's class)
		return search.ProjectEvent(ctx, tx, mpID)
	}
	return result, mutate, nil
}

func techFromProbe(p ffprobeOut) (mediapackage.Tech, error) {
	var t mediapackage.Tech
	if p.Format.Duration != "" {
		secs, err := strconv.ParseFloat(p.Format.Duration, 64)
		if err != nil {
			return t, fmt.Errorf("duration %q: %w", p.Format.Duration, err)
		}
		t.DurationMS = int64(math.Round(secs * 1000))
	}
	for _, s := range p.Streams {
		switch s.CodecType {
		case "video":
			t.Width, t.Height = s.Width, s.Height
			if s.NbFrames != "" {
				n, err := strconv.ParseInt(s.NbFrames, 10, 64)
				if err != nil {
					return t, fmt.Errorf("nb_frames %q: %w", s.NbFrames, err)
				}
				t.Framecount = n
			}
			if num, den, ok := strings.Cut(s.AvgFrameRate, "/"); ok {
				n, err1 := strconv.ParseFloat(num, 64)
				d, err2 := strconv.ParseFloat(den, 64)
				if err1 == nil && err2 == nil && d != 0 {
					t.Framerate = n / d
				}
			}
		case "audio":
			t.Channels = s.Channels
			if s.SampleRate != "" {
				sr, err := strconv.Atoi(s.SampleRate)
				if err != nil {
					return t, fmt.Errorf("sample_rate %q: %w", s.SampleRate, err)
				}
				t.SampleRate = sr
			}
		}
	}
	return t, nil
}
