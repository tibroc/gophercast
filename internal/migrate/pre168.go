// The pre-16.8 cross-org read-around, for S3-asset-store sources.
//
// Pre-16.8 Opencast deduplicated across organisations, so an
// oc_aws_asset_mapping row owned by org A can carry an object_key with org
// B's prefix. The table has NO bucket column — bucket resolution was ALWAYS
// read-time policy — so there is no stored value to repair and the row is
// NEVER mutated (the migration-plan §3.3.4 disposition: read around it, do
// not repair it). The rule:
//
//  1. identify the key's OWNING organisation by prefix-match against the
//     known org inventory — never by splitting on the first '/' (the
//     inventory knows; the split guesses),
//  2. resolve the bucket configured for THAT organisation (default-bucket
//     fallback included),
//  3. on a miss, HEAD across the whole candidate bucket set — this also
//     absorbs config drift (an adopter who changed bucket config over time
//     has keys matching no current config, indistinguishable from the
//     cross-org case since the DB never recorded the bucket),
//  4. anything still unresolved is a per-record fidelity-report line under
//     D-010 — the run continues.
//
// The increment-6 reference corpus is single-org, so this case could not be
// captured from a live instance (a recorded coverage gap). It is covered by
// the CONSTRUCTED fixture in pre168_test.go — which tests OUR rule, not
// observed legacy behaviour (the chain is derived from reading the legacy
// source code; no pre-16.8 instance was run).
package migrate

import (
	"fmt"
	"sort"
	"strings"
)

// AWSMappingRow mirrors oc_aws_asset_mapping's resolution-relevant columns.
// Read-only: nothing in this file (or package) writes a mapping row.
type AWSMappingRow struct {
	Organization string
	Mediapackage string
	ObjectKey    string
}

// BucketStore is the minimal read surface over the candidate buckets.
type BucketStore interface {
	Head(bucket, key string) (bool, error)
}

// BucketConfig resolves an organisation's configured bucket; DefaultBucket
// is the shared fallback the shipped config lands everyone on.
type BucketConfig struct {
	PerOrg        map[string]string
	DefaultBucket string
}

func (c BucketConfig) bucketFor(org string) string {
	if b, ok := c.PerOrg[org]; ok {
		return b
	}
	return c.DefaultBucket
}

// candidates returns every distinct bucket the config names.
func (c BucketConfig) candidates() []string {
	seen := map[string]bool{}
	var out []string
	add := func(b string) {
		if b != "" && !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	add(c.DefaultBucket)
	names := make([]string, 0, len(c.PerOrg))
	for o := range c.PerOrg {
		names = append(names, o)
	}
	sort.Strings(names)
	for _, o := range names {
		add(c.PerOrg[o])
	}
	return out
}

// ResolveOutcome says how a key was located — the fidelity report records it.
type ResolveOutcome string

const (
	ResolvedDirect    ResolveOutcome = "direct"     // owning org's bucket had it
	ResolvedCrossOrg  ResolveOutcome = "cross-org"  // key belongs to another org (pre-16.8 dedup); read around, row untouched
	ResolvedHeadSweep ResolveOutcome = "head-sweep" // no configured bucket had it directly; found by sweeping candidates
	ResolveUnresolved ResolveOutcome = "unresolved" // a per-record D-010 report line, not a run failure
)

// ResolveAWSObject applies the rule above to one mapping row and returns the
// bucket holding the bytes. It never mutates the row (it cannot — it only
// reads it) and never guesses an org from the key's shape.
func ResolveAWSObject(row AWSMappingRow, knownOrgs []string, cfg BucketConfig, store BucketStore) (bucket string, outcome ResolveOutcome, err error) {
	// 1. the key's OWNING org, from the inventory — not from the first '/'
	owner := ""
	for _, org := range knownOrgs {
		if strings.HasPrefix(row.ObjectKey, org+"/") {
			owner = org
			break
		}
	}
	if owner != "" {
		// 2. that org's bucket
		b := cfg.bucketFor(owner)
		ok, err := store.Head(b, row.ObjectKey)
		if err != nil {
			return "", "", err
		}
		if ok {
			if owner != row.Organization {
				return b, ResolvedCrossOrg, nil
			}
			return b, ResolvedDirect, nil
		}
	}
	// 3. the HEAD sweep over every candidate bucket
	for _, b := range cfg.candidates() {
		ok, err := store.Head(b, row.ObjectKey)
		if err != nil {
			return "", "", err
		}
		if ok {
			return b, ResolvedHeadSweep, nil
		}
	}
	// 4. unresolved: the caller writes the report line and continues
	return "", ResolveUnresolved, fmt.Errorf(
		"object %s (org %s, mp %s): not in the owning org's bucket nor any of %d candidates — per-record fidelity-report line (D-010)",
		row.ObjectKey, row.Organization, row.Mediapackage, len(cfg.candidates()))
}
