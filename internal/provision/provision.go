// Package provision holds the adapters behind the provisioning port —
// engine.Provisioner, the interface core uses to get an assigned task
// running. The port's contract is fixed by ADR-011 and untouched by A7:
// the task row is COMMITTED before Provision is called (a worker can never
// start and find its task absent), Provision failure is non-fatal (lease
// expiry re-provisions), and everything below assignment-and-lease — the
// single-winner ASSIGNED→RUNNING transition, lease renewal, lease-expiry
// recovery — is identical regardless of who starts the process.
//
// What varies per topology is SOLELY who starts the process (A7,
// D-045):
//
//   - VM topology: None. Core holds NO provisioning credential; the
//     committed ASSIGNED row IS the dispatch, and the resident
//     lease-worker on each worker VM (worker.RunFanout, deployed by the
//     operator's config management) discovers and claims it.
//   - K8s topology: KubernetesJob — one ephemeral Job per task under the
//     S4-demonstrated scoped RBAC grant. DEFERRED: see below.
package provision

import (
	"context"
	"errors"

	"ocng/internal/engine"
)

// compile-time proof both adapters satisfy the port
var (
	_ engine.Provisioner = None{}
	_ engine.Provisioner = (*KubernetesJob)(nil)
)

// None is the VM-topology adapter (A7/D-045): provisioning is nobody's job
// because the workers are already resident. Provision is a no-op — the
// committed ASSIGNED task row is the dispatch (ADR-004 pull posture,
// D-027); if no worker exists, lease expiry cycles attempts until the task
// fails loudly (the ADR-011 recovery path, unchanged). This DELETES the
// gate-item-5 attack surface on VMs — an internet-facing core that can
// create host containers — rather than mitigating it (D-046: the
// amendment-6 broker is dissolved, not deferred).
type None struct{}

func (None) Provision(ctx context.Context, t engine.Task) error { return nil }

// ErrDeferred is returned by adapters that are shaped but deliberately not
// built. Callers must treat it as a configuration error at wiring time,
// never at dispatch time.
var ErrDeferred = errors.New("provision: adapter deferred")

// KubernetesJob is the K8s-topology adapter: one ephemeral Job per task,
// created from core under the S4-demonstrated scoped grant (namespaced
// Role: jobs CRUD + pods read, PSA baseline — the K8s API credential IS
// the scoped grant podman lacks, so core may hold it directly; A7). The
// task's resource spec (engine.GetSpec) maps to the pod's
// requests/limits; RuntimeS maps to activeDeadlineSeconds.
//
// DEFERRED, NOT BUILT (T3 scope decision, TAIL-BUILD-ORDER §T3): a Job
// adapter needs a real cluster to validate against, and the standing
// stance is K8s-deferred until compose is insufficient. The struct exists
// so the port's second implementation has a named home and the interface
// shape is exercised by the compile-time assertion above — wiring it up
// is an error until the adapter is implemented against a cluster.
type KubernetesJob struct{}

func (*KubernetesJob) Provision(ctx context.Context, t engine.Task) error {
	return errors.Join(ErrDeferred, errors.New(
		"kubernetes Job adapter is shaped but deliberately unbuilt — it needs a real cluster to validate (ADR-011 A7; TAIL-BUILD-ORDER §T3)"))
}
