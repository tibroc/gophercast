// Package worker implements the increment-1 ephemeral transcription worker
// (ADR-011): created for exactly one assigned task, lease-renewing while it
// works, download-process-upload against CAS (ADR-008), completing its task
// in the same transaction as its mediapackage mutation.
//
// Lineage: the job execution shape follows an earlier proof-of-concept
// worker that ran against live Opencast, with the legacy
// registry protocol replaced by the engine's task client, and the legacy
// whisper invocation replaced by the PINNED reference invocation.
package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/cas"
	"ocng/internal/engine"
	"ocng/internal/mediapackage"
)

type Config struct {
	TaskID   int64
	Owner    string // unique per worker instance
	ToolsDir string // pinned ffmpeg, whisper-cli, ggml-base.bin
	Scratch  string // node-local scratch root
	Lease    time.Duration
	Log      *slog.Logger

	// T3 (ADR-011 A7): the task's resource spec and the opt-in hard-cap
	// flag. When CapScopes is set and the spec states a cpu or memory
	// dimension, tool subprocesses run inside a transient systemd scope
	// from the worker's OWN user manager (`systemd-run --user --scope`) —
	// no socket, no broker, no container. Default off: spec-arithmetic
	// admission without cgroup enforcement.
	TaskSpec  engine.Spec
	CapScopes bool
}

// Command builds a tool invocation — the ONLY way worker code starts a
// subprocess. Always a fixed binary with structured argv (the verified
// assumption-1 property A7 rests on; never a shell). With CapScopes on and
// a stated spec, the argv is prefixed with `systemd-run --user --scope`
// carrying CPUQuota/MemoryMax — still structured argv, still no shell.
func (c Config) Command(ctx context.Context, bin string, args ...string) *exec.Cmd {
	if !c.CapScopes || (c.TaskSpec.CPUMillis <= 0 && c.TaskSpec.MemoryMB <= 0) {
		return exec.CommandContext(ctx, bin, args...)
	}
	argv := []string{"--user", "--scope", "--collect", "--quiet"}
	if c.TaskSpec.CPUMillis > 0 {
		// CPUQuota is percent of one CPU: 1000 millis = 100%
		argv = append(argv, "-p", fmt.Sprintf("CPUQuota=%d%%", c.TaskSpec.CPUMillis/10))
	}
	if c.TaskSpec.MemoryMB > 0 {
		argv = append(argv, "-p", fmt.Sprintf("MemoryMax=%dM", c.TaskSpec.MemoryMB))
	}
	argv = append(argv, "--", bin)
	argv = append(argv, args...)
	return exec.CommandContext(ctx, "systemd-run", argv...)
}

// VerifyToolchain hashes the pinned tools and refuses drift. Called before
// the task is even read — a worker with the wrong toolchain must not touch
// work.
func VerifyToolchain(toolsDir string) error {
	for name, want := range map[string]string{
		"whisper-cli":   pinWhisperCLI,
		"ggml-base.bin": pinModel,
		"ffmpeg":        pinFFmpeg,
	} {
		if err := verifyTool(filepath.Join(toolsDir, name), want); err != nil {
			return err
		}
	}
	return nil
}

func verifyTool(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("pinned tool missing: %w", err)
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	f.Close()
	if err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("toolchain drift: %s is %s, pinned %s — the reference byte-diff is meaningless with this tool; re-derive the reference outputs deliberately", path, got, want)
	}
	return nil
}

// Run executes one task to completion. Any ErrTaskLost — raced at start,
// reaped mid-work, terminal at completion — is a clean silent exit: the
// task belongs to someone else now, and no side effect may follow (a lost
// task must have zero side effects — enforced server-side by the engine
// but honoured here too).
func Run(ctx context.Context, pool *pgxpool.Pool, store *cas.Store, cfg Config) error {
	log := cfg.Log
	if err := VerifyToolchain(cfg.ToolsDir); err != nil {
		return err
	}

	task, err := engine.GetTask(ctx, pool, cfg.TaskID)
	if err != nil {
		return fmt.Errorf("reading assigned task %d: %w", cfg.TaskID, err)
	}

	// operation dispatch — the worker-class ops this binary implements
	// (ADR-009: one worker image, capability by dispatch, not by build)
	var body func(ctx context.Context) (any, func(context.Context, pgx.Tx) error, error)
	switch task.Operation {
	case "speechtotext":
		body = func(ctx context.Context) (any, func(context.Context, pgx.Tx) error, error) {
			return transcribe(ctx, pool, store, cfg, task)
		}
	case "encode":
		body = func(ctx context.Context) (any, func(context.Context, pgx.Tx) error, error) {
			return encode(ctx, pool, store, cfg, task)
		}
	case "inspect":
		body = func(ctx context.Context) (any, func(context.Context, pgx.Tx) error, error) {
			return inspect(ctx, pool, store, cfg, task)
		}
	default:
		// fail LOUDLY through the standard lifecycle — an unsupported op
		// must not strand ASSIGNED until lease exhaustion
		body = func(ctx context.Context) (any, func(context.Context, pgx.Tx) error, error) {
			return nil, nil, fmt.Errorf("operation %q not implemented by this worker", task.Operation)
		}
	}

	// The ONE task lifecycle (engine.ExecuteTask, shared with the inline
	// runner): win or exit silently, renew the lease, commit result and
	// mutation with the terminal write, zero side effects on any lost task.
	if err := engine.ExecuteTask(ctx, pool, task, cfg.Owner, cfg.Lease, body); err != nil {
		log.Error("task failed", "task", task.ID, "err", err)
		return err
	}
	log.Info("task done (or lost cleanly)", "task", task.ID, "operation", task.Operation)
	return nil
}

// selectSourceTrack resolves a source-flavor pattern to exactly one track.
func selectSourceTrack(elements []mediapackage.Element, pattern string, taskID int64) (*mediapackage.Element, error) {
	var source *mediapackage.Element
	for i := range elements {
		el := &elements[i]
		if el.Kind == "track" && mediapackage.FlavorMatches(pattern, el.Flavor) {
			if source != nil {
				return nil, fmt.Errorf("task %d: source-flavor %q matches more than one track (%s, %s)", taskID, pattern, source.ID, el.ID)
			}
			source = el
		}
	}
	if source == nil {
		return nil, fmt.Errorf("task %d: no track matches source-flavor %q", taskID, pattern)
	}
	return source, nil
}

// transcribe runs the pinned invocation:
//
//	ffmpeg -i <media> -ar 16000 -ac 1 -c:a pcm_s16le <wav>
//	whisper-cli <wav> --model ggml-base.bin -ovtt -oj --output-file <base> --language <lang>
//
// and returns the completion mutation that records the captions element.
func transcribe(ctx context.Context, pool *pgxpool.Pool, store *cas.Store, cfg Config, task engine.Task) (map[string]string, func(context.Context, pgx.Tx) error, error) {
	mpID, err := engine.MediapackageID(ctx, pool, task.ID)
	if err != nil {
		return nil, nil, err
	}
	sourceFlavor := task.Config["source-flavor"]
	targetFlavor := task.Config["target-flavor"]
	language := task.Config["language"]
	if sourceFlavor == "" || targetFlavor == "" {
		return nil, nil, fmt.Errorf("task %d: source-flavor and target-flavor are required", task.ID)
	}
	if language == "" {
		language = "en"
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

	// download
	mediaBase := filepath.Base(source.SourceURL)
	if mediaBase == "" || mediaBase == "." {
		mediaBase = "input"
	}
	mediaPath := filepath.Join(dir, mediaBase)
	if err := store.GetToFile(ctx, source.SHA256, mediaPath); err != nil {
		return nil, nil, fmt.Errorf("download: %w", err)
	}

	// process — the pinned invocation, verbatim
	wav := filepath.Join(dir, "audio.wav")
	ff := cfg.Command(ctx, filepath.Join(cfg.ToolsDir, "ffmpeg"),
		"-i", mediaPath, "-ar", "16000", "-ac", "1", "-c:a", "pcm_s16le", wav)
	if out, err := ff.CombinedOutput(); err != nil {
		return nil, nil, fmt.Errorf("ffmpeg: %w\n%s", err, tail(out))
	}
	outBase := filepath.Join(dir, "out")
	wc := cfg.Command(ctx, filepath.Join(cfg.ToolsDir, "whisper-cli"),
		wav, "--model", filepath.Join(cfg.ToolsDir, "ggml-base.bin"),
		"-ovtt", "-oj", "--output-file", outBase, "--language", language)
	if out, err := wc.CombinedOutput(); err != nil {
		return nil, nil, fmt.Errorf("whisper-cli: %w\n%s", err, tail(out))
	}
	vtt := outBase + ".vtt"
	st, err := os.Stat(vtt)
	if err != nil {
		return nil, nil, fmt.Errorf("whisper-cli produced no vtt: %w", err)
	}

	// upload (dedup by construction: re-runs land on the same hash)
	sum, err := store.PutFile(ctx, vtt)
	if err != nil {
		return nil, nil, fmt.Errorf("upload: %w", err)
	}

	element := mediapackage.Element{
		ID:             uuid.NewString(),
		MediapackageID: mpID,
		Kind:           "track",
		Flavor:         targetFlavor,
		Mimetype:       "text/vtt",
		SHA256:         sum,
		SizeBytes:      st.Size(),
	}
	tags := []string{"generator-type:auto", "generator:whisperc++", "lang:" + language}
	result := map[string]string{"element": element.ID, "sha256": sum, "language": language, "engine": "WhisperC++"}
	mutate := func(ctx context.Context, tx pgx.Tx) error {
		return mediapackage.InsertElement(ctx, tx, element, tags)
	}
	return result, mutate, nil
}

func tail(b []byte) []byte {
	if len(b) > 800 {
		return b[len(b)-800:]
	}
	return b
}
