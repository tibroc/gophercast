// Package definitions is the ADR-009 workflow-definition authoring surface
// (T5 step 1): bind mount authors, database executes.
//
//   - A directory of YAML files (one definition per file) is the authoring
//     surface — plain files, edited with an editor, managed by Ansible if
//     the operator prefers (ADR-009 §"Workflow definitions"; D-001: YAML
//     only — the assembly-era definitions.json was an explicit stand-in).
//   - The workflow_definition table is the execution source of truth. The
//     Loader on each core replica watches the directory and upserts changed
//     files (yaml bytes plus content hash); the Registry is what execution
//     reads. Storing the hash makes replica drift DETECTABLE: two cores
//     disagreeing on a definition is a query, not an intermittent behaviour
//     change. Workers never read definitions at all.
//   - Removing a file does NOT delete the definition row: definitions are
//     referenced by running workflows and deletion is not an authoring
//     operation this surface offers.
//
// STATED LIMIT (T5 ratification): definitions containing an `include`
// operation are rejected at load time. ADR-009 names orchestrator-side
// include expansion, but nothing in ocng exercises the construct — no
// definition uses it and no handler exists — so the expansion machinery is
// deferred rather than built untested. The load-time rejection converts what
// would be a runtime failUnrunnable into an authoring-time message.
//
// Failure posture (T5 boot-time load): at BOOT an unreadable directory
// or unparseable file is fail-loud — boot is where loud is cheap. At RUNTIME
// a parse failure keeps the last-good row and logs ERROR — an operator typo
// must not take the core down.
package definitions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"go.yaml.in/yaml/v3"

	"ocng/internal/engine"
)

// Source is what execution surfaces (ingest, the admin write surface) read
// definitions from. The DB-backed Registry is the deployed implementation;
// Static serves in-process tests.
type Source interface {
	// Definition returns the definition registered under id;
	// ok=false when no such definition exists.
	Definition(ctx context.Context, id string) (engine.Definition, bool, error)
}

// Static is a fixed in-memory Source for tests (the pre-T5 map shape).
type Static map[string]engine.Definition

func (s Static) Definition(_ context.Context, id string) (engine.Definition, bool, error) {
	d, ok := s[id]
	return d, ok, nil
}

// The YAML document shape. Deliberately explicit rather than reusing
// engine's json tags: yaml.v3 does not read json tags, and the authoring
// surface should fail loud on unknown fields (KnownFields) instead of
// silently dropping a typo.
type fileDoc struct {
	ID         string  `yaml:"id"`
	Operations []opDoc `yaml:"operations"`
}

type opDoc struct {
	Operation string            `yaml:"operation"`
	Config    map[string]string `yaml:"config"`
	Spec      *specDoc          `yaml:"spec"`
}

type specDoc struct {
	CPUMillis int `yaml:"cpu_millis"`
	MemoryMB  int `yaml:"memory_mb"`
	GPU       int `yaml:"gpu"`
	RuntimeS  int `yaml:"runtime_s"`
}

// Parse parses one YAML definition document into the engine's shape,
// returning the definition id. Strict: unknown fields, a missing id, an
// empty operation list, a nameless operation, and the deferred `include`
// construct are all authoring errors.
func Parse(raw []byte) (string, engine.Definition, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var doc fileDoc
	if err := dec.Decode(&doc); err != nil {
		return "", engine.Definition{}, err
	}
	if doc.ID == "" {
		return "", engine.Definition{}, fmt.Errorf("definition has no id")
	}
	if len(doc.Operations) == 0 {
		return "", engine.Definition{}, fmt.Errorf("definition %q has no operations", doc.ID)
	}
	def := engine.Definition{Operations: make([]engine.OpDef, 0, len(doc.Operations))}
	for i, op := range doc.Operations {
		if op.Operation == "" {
			return "", engine.Definition{}, fmt.Errorf("definition %q: operation %d has no operation name", doc.ID, i)
		}
		if op.Operation == "include" {
			return "", engine.Definition{}, fmt.Errorf(
				"definition %q: `include` is not supported — orchestrator-side include expansion (ADR-009) is a stated limit, deferred until a definition needs it; inline the included operations instead", doc.ID)
		}
		o := engine.OpDef{Operation: op.Operation, Config: op.Config}
		if o.Config == nil {
			o.Config = map[string]string{}
		}
		if op.Spec != nil {
			o.Spec = &engine.Spec{
				CPUMillis: op.Spec.CPUMillis, MemoryMB: op.Spec.MemoryMB,
				GPU: op.Spec.GPU, RuntimeS: op.Spec.RuntimeS,
			}
		}
		def.Operations = append(def.Operations, o)
	}
	return doc.ID, def, nil
}

// Hash is the content hash stored next to the yaml bytes (ADR-009: "content
// plus a hash" — drift between replicas becomes a query).
func Hash(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
