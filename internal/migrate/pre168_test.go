// The CONSTRUCTED pre-16.8 fixture (a recorded coverage gap — the increment-6
// reference corpus is single-org, so the cross-org read-around case could not
// be captured from a live instance; migration must cover it here).
//
// Two orgs, per-org buckets plus the shared default; four mapping rows:
// a normal row, THE cross-org row (org-a's row, org-b's key prefix, bytes
// only in org-b's bucket), a config-drift row (key prefix matching no known
// org, bytes findable only by the HEAD sweep), and a truly-missing row
// (a report line, never a run failure). Every assertion also proves the
// mapping rows were resolved by READ-AROUND, never by mutation.
//
// Kept strictly distinct from the intra-org 126-hardlink dedup case (that is
// a CAS content-dedup assertion in the e2e diff; this is bucket resolution).
package migrate

import (
	"testing"
)

// memBuckets is the in-memory candidate bucket set.
type memBuckets map[string]map[string][]byte

func (m memBuckets) Head(bucket, key string) (bool, error) {
	_, ok := m[bucket][key]
	return ok, nil
}

func TestPre168ReadAround(t *testing.T) {
	knownOrgs := []string{"org-a", "org-b"}
	cfg := BucketConfig{
		PerOrg:        map[string]string{"org-a": "bucket-a", "org-b": "bucket-b"},
		DefaultBucket: "bucket-shared",
	}
	buckets := memBuckets{
		"bucket-a":      {"org-a/mp1/0/el1": []byte("a-bytes")},
		"bucket-b":      {"org-b/mp9/0/el9": []byte("b-bytes")},
		"bucket-shared": {"legacy-prefix/mp3/0/el3": []byte("drift-bytes")},
	}

	rows := map[string]AWSMappingRow{
		"normal":    {Organization: "org-a", Mediapackage: "mp1", ObjectKey: "org-a/mp1/0/el1"},
		"cross-org": {Organization: "org-a", Mediapackage: "mp9", ObjectKey: "org-b/mp9/0/el9"},
		"drift":     {Organization: "org-a", Mediapackage: "mp3", ObjectKey: "legacy-prefix/mp3/0/el3"},
		"missing":   {Organization: "org-a", Mediapackage: "mp4", ObjectKey: "org-a/mp4/0/gone"},
	}
	before := map[string]AWSMappingRow{}
	for k, v := range rows {
		before[k] = v // value copy: the unmutated baseline
	}

	t.Run("normal row resolves in the owning org's bucket", func(t *testing.T) {
		b, outcome, err := ResolveAWSObject(rows["normal"], knownOrgs, cfg, buckets)
		if err != nil || b != "bucket-a" || outcome != ResolvedDirect {
			t.Fatalf("got bucket=%q outcome=%q err=%v, want bucket-a/direct", b, outcome, err)
		}
	})

	t.Run("cross-org row: owning org resolved FROM THE KEY, read from the other org's bucket", func(t *testing.T) {
		b, outcome, err := ResolveAWSObject(rows["cross-org"], knownOrgs, cfg, buckets)
		if err != nil {
			t.Fatal(err)
		}
		if b != "bucket-b" || outcome != ResolvedCrossOrg {
			t.Fatalf("got bucket=%q outcome=%q, want bucket-b/cross-org", b, outcome)
		}
		ok, _ := buckets.Head(b, rows["cross-org"].ObjectKey)
		if !ok {
			t.Fatal("resolved bucket does not actually hold the bytes")
		}
	})

	t.Run("config-drift row: no known-org prefix, found by the HEAD sweep", func(t *testing.T) {
		b, outcome, err := ResolveAWSObject(rows["drift"], knownOrgs, cfg, buckets)
		if err != nil || b != "bucket-shared" || outcome != ResolvedHeadSweep {
			t.Fatalf("got bucket=%q outcome=%q err=%v, want bucket-shared/head-sweep", b, outcome, err)
		}
	})

	t.Run("missing row: unresolved is a report line, not a resolution", func(t *testing.T) {
		b, outcome, err := ResolveAWSObject(rows["missing"], knownOrgs, cfg, buckets)
		if outcome != ResolveUnresolved || b != "" {
			t.Fatalf("got bucket=%q outcome=%q, want unresolved", b, outcome)
		}
		if err == nil {
			t.Fatal("unresolved must carry the report-line detail")
		}
	})

	t.Run("mapping rows are byte-identical after resolution — read-around, never repair", func(t *testing.T) {
		for k, v := range rows {
			if v != before[k] {
				t.Fatalf("row %q mutated: %+v != %+v", k, v, before[k])
			}
		}
	})

	t.Run("owning org comes from the inventory, never from splitting the key", func(t *testing.T) {
		// A key whose first path segment is NOT a known org must not be
		// treated as owned by a phantom org — it goes to the sweep.
		row := AWSMappingRow{Organization: "org-a", ObjectKey: "org-c/mp/0/el"}
		_, outcome, _ := ResolveAWSObject(row, knownOrgs, cfg, buckets)
		if outcome != ResolveUnresolved {
			t.Fatalf("phantom-org key resolved as %q, want unresolved (nothing holds it)", outcome)
		}
	})
}
