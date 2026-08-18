// The pure half of the migration-plan checks: every shipped package plan
// must pass the blocking-lock classifier without a database. The runner
// invariants themselves (second boot does zero DDL under a held ACCESS
// SHARE, parallel boots pick a single winner, edited applied steps are
// refused) execute against real Postgres in the integration suite, which
// is not part of this repository.
package schemastep_test

import (
	"testing"

	"ocng/internal/acl"
	"ocng/internal/engine"
	"ocng/internal/lti"
	"ocng/internal/mediapackage"
	"ocng/internal/migrate"
	"ocng/internal/schemastep"
	"ocng/internal/search"
)

// bootPlans mirrors cmd/ocng-core's migration list (plus ocng-migrate's).
func bootPlans() []struct {
	pkg   string
	steps []schemastep.Step
} {
	return []struct {
		pkg   string
		steps []schemastep.Step
	}{
		{"engine", engine.MigrationSteps()},
		{"mediapackage", mediapackage.MigrationSteps()},
		{"acl", acl.MigrationSteps()},
		{"search", search.MigrationSteps()},
		{"lti", lti.MigrationSteps()},
		{"migrate", migrate.MigrationSteps()},
	}
}

// Every shipped plan must pass its own blocking-lock check — the mechanism
// refuses nothing it ships (and mediapackage's baseline HAS to be shipped
// guarded, or this fails).
func TestAllPackagesCheckClean(t *testing.T) {
	for _, p := range bootPlans() {
		if err := schemastep.Check(p.steps); err != nil {
			t.Errorf("%s: shipped plan fails its own check: %v", p.pkg, err)
		}
	}
}
