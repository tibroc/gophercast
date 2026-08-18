package engine

import "testing"

// The class table must carry all 98 operations with the S4-measured split —
// 33 worker / 61 inline / 4 unclear (workflow-operations.csv, verified by
// tally in CONTRACTS §3.2). A drifted table silently reroutes operations.
func TestClassTableCounts(t *testing.T) {
	counts := map[ExecClass]int{}
	for _, c := range opClass {
		counts[c]++
	}
	if len(opClass) != 98 {
		t.Errorf("class table has %d operations, want 98", len(opClass))
	}
	if counts[ClassWorker] != 33 || counts[ClassInline] != 61 || counts[ClassUnclear] != 4 {
		t.Errorf("split = %d worker / %d inline / %d unclear, want 33/61/4",
			counts[ClassWorker], counts[ClassInline], counts[ClassUnclear])
	}
	if ClassOf("no-such-operation") != ClassUnknown {
		t.Errorf("unknown operation must map to ClassUnknown")
	}
}
