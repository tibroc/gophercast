// The static layer of the serve-read-set proof (§5.2 layer 1, the fast
// complement to the ocng_serve role): every table named in this package's
// SQL must be in serveset.Tables. The structural layer
// (serveset_test.TestServeRoleReadsExactlyTheSet) is the one that cannot
// lie — it also covers queries serve reaches through other packages
// (mediapackage.GetElement), which a source walk of this directory cannot
// see.
package serve

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"ocng/internal/serveset"
)

var reFromJoin = regexp.MustCompile(`(?is)\b(?:from|join|update|insert\s+into|delete\s+from)\s+([a-z_][a-z0-9_]*)`)

func TestServeSQLReadsOnlyTheSet(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sawSQL := false
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		// raw string literals are where this package keeps its SQL
		parts := strings.Split(string(src), "`")
		for i := 1; i < len(parts); i += 2 {
			lit := parts[i]
			if !regexp.MustCompile(`(?is)\bselect\b`).MatchString(lit) {
				continue
			}
			for _, m := range reFromJoin.FindAllStringSubmatch(lit, -1) {
				sawSQL = true
				if !serveset.Contains(m[1]) {
					t.Errorf("%s: serve SQL references table %q outside the serve-read set (internal/serveset/READSET.md)", f, m[1])
				}
			}
		}
	}
	if !sawSQL {
		t.Fatal("found no SQL in internal/serve — the scan is broken, not the code clean")
	}
}
