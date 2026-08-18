// The pure half of the fan-out proofs (T3, ADR-011 A7): admission
// arithmetic and the exec wrapper, no database. The task-protocol proofs
// (single-winner assignment, over-provision safety, live spec admission)
// require real Postgres — the engine IS SQL, a mocked database would prove
// nothing — and live in the integration suite, which is not part of this
// repository.
package worker

import (
	"context"
	"strings"
	"testing"

	"ocng/internal/engine"
)

func TestAdmissionArithmetic(t *testing.T) {
	a := &admitter{cap: engine.Spec{CPUMillis: 2000, MemoryMB: 1024, GPU: 0}}

	if !a.tryAdmit(engine.Spec{CPUMillis: 1500, MemoryMB: 512}) {
		t.Fatal("first task fits capacity, must be admitted")
	}
	if a.tryAdmit(engine.Spec{CPUMillis: 1000, MemoryMB: 100}) {
		t.Fatal("1500+1000 > 2000 cpu: over-capacity candidate must wait")
	}
	if !a.tryAdmit(engine.Spec{CPUMillis: 500, MemoryMB: 512}) {
		t.Fatal("a fitting candidate must start even while a larger one waits")
	}
	if a.tryAdmit(engine.Spec{CPUMillis: 1, MemoryMB: 1}) {
		t.Fatal("memory exhausted: must refuse")
	}
	a.release(engine.Spec{CPUMillis: 1500, MemoryMB: 512})
	if !a.tryAdmit(engine.Spec{CPUMillis: 1000, MemoryMB: 100}) {
		t.Fatal("released capacity must re-admit")
	}

	// gpu: capacity 0 means NO gpu — a gpu task is never admitted here,
	// unlike cpu/mem where 0 means unconstrained
	free := &admitter{cap: engine.Spec{}}
	if !free.tryAdmit(engine.Spec{CPUMillis: 99999, MemoryMB: 99999}) {
		t.Fatal("zero cpu/mem capacity means unconstrained")
	}
	if free.tryAdmit(engine.Spec{GPU: 1}) {
		t.Fatal("zero gpu capacity means no gpu, not unconstrained")
	}
}

// TestCommandScopes: the exec wrapper. Caps off (default) = the plain
// pinned invocation; caps on = the same structured argv under
// `systemd-run --user --scope` with CPUQuota/MemoryMax. Never a shell.
func TestCommandScopes(t *testing.T) {
	ctx := context.Background()

	plain := Config{}.Command(ctx, "/opt/tools/ffmpeg", "-i", "in.mp4", "out.mp4")
	if plain.Path != "/opt/tools/ffmpeg" || len(plain.Args) != 4 {
		t.Fatalf("caps off must exec the tool directly: %v", plain.Args)
	}

	capped := Config{CapScopes: true, TaskSpec: engine.Spec{CPUMillis: 1500, MemoryMB: 512}}.
		Command(ctx, "/opt/tools/ffmpeg", "-i", "in.mp4", "out.mp4")
	got := strings.Join(capped.Args, " ")
	want := "systemd-run --user --scope --collect --quiet -p CPUQuota=150% -p MemoryMax=512M -- /opt/tools/ffmpeg -i in.mp4 out.mp4"
	if got != want {
		t.Fatalf("scope argv:\n got  %q\n want %q", got, want)
	}

	// caps flag on but no stated dimensions: nothing to enforce, run plain
	noSpec := Config{CapScopes: true}.Command(ctx, "/opt/tools/ffprobe", "-v", "error")
	if noSpec.Path != "/opt/tools/ffprobe" {
		t.Fatalf("caps with an empty spec must exec the tool directly: %v", noSpec.Args)
	}
}
