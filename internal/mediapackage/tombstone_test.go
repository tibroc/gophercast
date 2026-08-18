package mediapackage

import (
	"testing"

	"ocng/internal/schemastep"
	"ocng/internal/serveset"
)

// TestTombstoneMigrationForwardProof is T4's forward exercise of the T2
// discipline (the second, after T3's task-resource-spec) — the delete-path §5
// verdict "UNCONSTRAINED (off-set)" is confirmed against the live classifier,
// not assumed:
//
//  1. the classifier ACCEPTS the plan (Check really runs);
//  2. for the right REASON — both tombstone statements are metadata-AEL
//     targeting mediapackage/series, and both tables are OFF the serve-read
//     set (retraction touches the serve set only via ordinary DML, which is
//     not a migration at all);
//  3. not vacuously — the identical nullable-add aimed at a serve-read-set
//     table as a plain TxDDL step is REFUSED.
//
// The live forward path (a T2-era ledger picking up exactly this step, then
// ledger-skipping) is exercised by every e2e suite's fresh migrate and by the
// schemastep runner tests; the t4 e2e suite additionally asserts the ledger
// row and the columns exist.
func TestTombstoneMigrationForwardProof(t *testing.T) {
	steps := MigrationSteps()

	// (1) the classifier accepts the plan
	if err := schemastep.Check(steps); err != nil {
		t.Fatalf("T2's classifier refused the T4 tombstone plan: %v", err)
	}

	// (2) the reason: metadata-AEL on mediapackage/series, both off-set
	var tomb *schemastep.Step
	for i := range steps {
		if steps[i].Name == "t4-tombstone" {
			tomb = &steps[i]
		}
	}
	if tomb == nil {
		t.Fatal("no t4-tombstone step in the mediapackage plan")
	}
	stmts := schemastep.SplitStatements(tomb.SQL)
	if len(stmts) != 2 {
		t.Fatalf("expected 2 ALTER statements, got %d", len(stmts))
	}
	wantTables := map[string]bool{"mediapackage": false, "series": false}
	for _, stmt := range stmts {
		class, table := schemastep.ClassifyStatement(stmt)
		if class != schemastep.ClassMetadataAEL {
			t.Fatalf("statement %q classified %s, want metadata-AEL", stmt, class)
		}
		if _, ok := wantTables[table]; !ok {
			t.Fatalf("statement %q targets %q, want mediapackage or series", stmt, table)
		}
		if serveset.Contains(table) {
			t.Fatalf("%s is in the serve-read set — the off-set premise is wrong", table)
		}
		wantTables[table] = true
	}
	for tbl, seen := range wantTables {
		if !seen {
			t.Fatalf("no tombstone statement targets %s", tbl)
		}
	}

	// (3) counterfactual: the same shape on a serve-read-set table as a plain
	// (unguarded) step must be refused — the pass in (1) has teeth
	bad := []schemastep.Step{schemastep.TxDDL(0, "bad",
		`alter table publication add column if not exists deleted_at timestamptz`)}
	if err := schemastep.Check(bad); err == nil {
		t.Fatal("classifier accepted an unguarded metadata-AEL on publication")
	}
}
