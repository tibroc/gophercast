package config

import (
	"strings"
	"testing"
)

// All-errors-at-once: five problems, one message, every var named.
func TestSetCollectsAllErrors(t *testing.T) {
	t.Setenv("T5_INT", "8G")     // the F-1 archetype
	t.Setenv("T5_DUR", "banana") // bad duration
	t.Setenv("T5_I64", "twelve") // bad int64
	// T5_REQ_A / T5_REQ_B unset

	var s Set
	s.Require("T5_REQ_A")
	s.Require("T5_REQ_B")
	if got := s.Int("T5_INT", 0); got != 0 {
		t.Fatalf("bad int returned %d, want the default while erroring", got)
	}
	s.Duration("T5_DUR")
	s.Int64("T5_I64")

	err := s.Err()
	if err == nil {
		t.Fatal("five problems, no error")
	}
	for _, name := range []string{"T5_REQ_A", "T5_REQ_B", "T5_INT", "T5_DUR", "T5_I64"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("exit message does not name %s: %s", name, err)
		}
	}
	if !strings.Contains(err.Error(), "5 problem(s)") {
		t.Errorf("message does not count 5: %s", err)
	}
}

func TestSetHappyPath(t *testing.T) {
	t.Setenv("T5_OK_REQ", "value")
	t.Setenv("T5_OK_INT", "42")
	t.Setenv("T5_OK_DUR", "90s")

	var s Set
	if v := s.Require("T5_OK_REQ"); v != "value" {
		t.Fatalf("Require = %q", v)
	}
	if v := s.Int("T5_OK_INT", 0); v != 42 {
		t.Fatalf("Int = %d", v)
	}
	if d, ok := s.Duration("T5_OK_DUR"); !ok || d.Seconds() != 90 {
		t.Fatalf("Duration = %v ok=%v", d, ok)
	}
	if v := s.String("T5_UNSET", "def"); v != "def" {
		t.Fatalf("String default = %q", v)
	}
	if _, ok := s.Duration("T5_UNSET_DUR"); ok {
		t.Fatal("unset duration reported present")
	}
	if err := s.Err(); err != nil {
		t.Fatalf("clean surface errored: %v", err)
	}
}

// The pilot-gate boot report (T5 step 3): the dev compose shape lists its
// dev-grade postures with the disabled T2 boundary named as a DISABLED
// SECURITY BOUNDARY, not one posture among the others; a production-shaped
// configuration lists none.
func TestBootReportDevShape(t *testing.T) {
	rep := CorePostures{
		ServeEnforcementOff:  true,
		ServePasswordDefault: true,
		DevAuth:              true,
		NoIdentityPath:       true,
	}.BootReport()
	if rep == "" {
		t.Fatal("dev shape produced an empty report")
	}
	// the disabled boundary is its own !!-block, above the gate list
	if !strings.Contains(rep, "SERVE-READ-SET ENFORCEMENT DISABLED") {
		t.Fatalf("report does not name the disabled enforcement:\n%s", rep)
	}
	if !strings.Contains(rep, "disabled security boundary, not a tuning default") {
		t.Fatalf("report does not distinguish the boundary from a tuning default:\n%s", rep)
	}
	for _, want := range []string{"OCNG_SERVE_DB_PASSWORD", "OCNG_DEV_AUTH", "no identity path"} {
		if !strings.Contains(rep, want) {
			t.Fatalf("report missing %q:\n%s", want, rep)
		}
	}
}

func TestBootReportProductionShape(t *testing.T) {
	if rep := (CorePostures{}).BootReport(); rep != "" {
		t.Fatalf("production shape produced a report:\n%s", rep)
	}
}

// Each posture appears alone — no posture is coupled to another.
func TestBootReportSinglePostures(t *testing.T) {
	cases := []struct {
		p    CorePostures
		want string
	}{
		{CorePostures{ServeEnforcementOff: true}, "SERVE-READ-SET ENFORCEMENT DISABLED"},
		{CorePostures{ServePasswordDefault: true}, "OCNG_SERVE_DB_PASSWORD"},
		{CorePostures{DevAuth: true}, "OCNG_DEV_AUTH"},
		{CorePostures{NoIdentityPath: true}, "no identity path"},
	}
	for _, c := range cases {
		rep := c.p.BootReport()
		if !strings.Contains(rep, c.want) {
			t.Errorf("posture %+v report missing %q:\n%s", c.p, c.want, rep)
		}
	}
}
