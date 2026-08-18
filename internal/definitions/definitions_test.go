package definitions

import (
	"strings"
	"testing"
)

const goodYAML = `id: ocng-eval-2
operations:
  - operation: inspect
    config: {}
  - operation: encode
    config:
      source-flavor: "*/source"
      target-flavor: "*/preview"
      encoding-profile: fast.http
    spec:
      cpu_millis: 2000
      memory_mb: 1024
  - operation: snapshot
    config:
      source-flavors: "*/*"
`

func TestParseGood(t *testing.T) {
	id, def, err := Parse([]byte(goodYAML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if id != "ocng-eval-2" {
		t.Fatalf("id = %q", id)
	}
	if len(def.Operations) != 3 {
		t.Fatalf("got %d operations", len(def.Operations))
	}
	if def.Operations[1].Config["encoding-profile"] != "fast.http" {
		t.Fatalf("config lost: %v", def.Operations[1].Config)
	}
	if def.Operations[1].Spec == nil || def.Operations[1].Spec.CPUMillis != 2000 || def.Operations[1].Spec.MemoryMB != 1024 {
		t.Fatalf("spec lost: %+v", def.Operations[1].Spec)
	}
	if def.Operations[0].Spec != nil {
		t.Fatalf("spec invented for inspect")
	}
}

// The authoring surface fails loud on what would otherwise be silent
// misconfiguration: unknown fields (typos), missing id, empty operations,
// nameless operations.
func TestParseRejections(t *testing.T) {
	cases := map[string]struct{ yaml, wantErr string }{
		"unknown field": {
			"id: x\noperations:\n  - operation: inspect\n    confg: {}\n",
			"confg"},
		"missing id": {
			"operations:\n  - operation: inspect\n",
			"no id"},
		"no operations": {
			"id: x\n",
			"no operations"},
		"nameless op": {
			"id: x\noperations:\n  - config: {}\n",
			"no operation name"},
		"not yaml at all": {
			"{{{",
			""},
	}
	for name, c := range cases {
		_, _, err := Parse([]byte(c.yaml))
		if err == nil {
			t.Errorf("%s: parse accepted %q", name, c.yaml)
			continue
		}
		if c.wantErr != "" && !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: error %q does not name %q", name, err, c.wantErr)
		}
	}
}

// The T5 stated limit: `include` is rejected at LOAD time with an error
// naming the limit, converting a runtime failUnrunnable into an
// authoring-time message (ratification 2026-08-18).
func TestParseRejectsInclude(t *testing.T) {
	y := "id: x\noperations:\n  - operation: include\n    config:\n      workflow-id: other\n"
	_, _, err := Parse([]byte(y))
	if err == nil {
		t.Fatal("include accepted at load")
	}
	for _, want := range []string{"include", "not supported", "stated limit"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("include rejection %q does not say %q", err, want)
		}
	}
}

func TestHashStable(t *testing.T) {
	if Hash([]byte("a")) == Hash([]byte("b")) {
		t.Fatal("hash collision on trivial inputs")
	}
	if Hash([]byte(goodYAML)) != Hash([]byte(goodYAML)) {
		t.Fatal("hash not deterministic")
	}
}
