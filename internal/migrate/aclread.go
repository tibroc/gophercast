// The authoritative archive-ACL read:
// episode ACL = the security-XACML attachments of the LATEST snapshot,
// resolved per merge.mode, cross-checked against the EAV enforcement copy.
// Never a REST endpoint — this package has no HTTP client and reads the
// archive directly.
package migrate

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"

	"ocng/internal/acl"
)

// ACLState mirrors D-032 for the reader's answer.
type archiveACL struct {
	State   string // ABSENT | PRESENT
	Entries []acl.Entry
	Source  string // episode-xacml | series-xacml | absent
}

// resolveArchiveACL reads the episode ACL from the latest snapshot's
// security attachments. Rules, each traceable:
//   - duplicates of one flavor (the archival urn copy + the /static
//     distribution copy) must be byte-equal; the urn copy is read. A
//     last-writer-wins pick between diverging copies would silently shadow
//     one policy with another, so the migration reader must not do that.
//     Divergence is a HOLD, never a pick.
//   - merge.mode "override" (shipped default): episode attachment present →
//     it IS the ACL; else the in-package series copy; else ABSENT. Other
//     modes are unsupported and abort the run (they change the meaning of
//     every ACL — silently proceeding would migrate a different policy).
func resolveArchiveACL(doc document, resolve func(string) (io.ReadCloser, error), mergeMode string) (archiveACL, error) {
	if mergeMode != "override" {
		return archiveACL{}, fmt.Errorf("merge.mode %q unsupported (only the shipped default 'override' is implemented; a different mode changes every ACL's meaning)", mergeMode)
	}
	episode, err := securityAttachmentBytes(doc, "security/xacml+episode", resolve)
	if err != nil {
		return archiveACL{}, err
	}
	series, err := securityAttachmentBytes(doc, "security/xacml+series", resolve)
	if err != nil {
		return archiveACL{}, err
	}
	switch {
	case episode != nil:
		entries, err := parseXACML(episode)
		if err != nil {
			return archiveACL{}, err
		}
		return archiveACL{State: "PRESENT", Entries: entries, Source: "episode-xacml"}, nil
	case series != nil:
		entries, err := parseXACML(series)
		if err != nil {
			return archiveACL{}, err
		}
		return archiveACL{State: "PRESENT", Entries: entries, Source: "series-xacml"}, nil
	default:
		return archiveACL{State: "ABSENT", Source: "absent"}, nil
	}
}

// securityAttachmentBytes returns the bytes of the given security flavor's
// attachment in the document, byte-comparing every copy and preferring the
// archival urn-shape one. nil means no attachment of that flavor.
func securityAttachmentBytes(doc document, flavor string, resolve func(string) (io.ReadCloser, error)) ([]byte, error) {
	type copyOf struct {
		url   string
		bytes []byte
	}
	var copies []copyOf
	for _, el := range doc.Elements {
		if el.Flavor != flavor {
			continue
		}
		r, err := resolve(el.URL)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", flavor, el.URL, err)
		}
		b, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			return nil, err
		}
		copies = append(copies, copyOf{el.URL, b})
	}
	if len(copies) == 0 {
		return nil, nil
	}
	// urn copies first, deterministically
	sort.SliceStable(copies, func(i, j int) bool {
		iu, ju := strings.HasPrefix(copies[i].url, "urn:"), strings.HasPrefix(copies[j].url, "urn:")
		return iu && !ju
	})
	for _, c := range copies[1:] {
		if !bytes.Equal(c.bytes, copies[0].bytes) {
			return nil, fmt.Errorf("%s: duplicate attachments diverge (%s vs %s) — HOLD, a last-of-flavor pick must not silently shadow one policy", flavor, copies[0].url, c.url)
		}
	}
	if !strings.HasPrefix(copies[0].url, "urn:") {
		return nil, fmt.Errorf("%s: no archival urn copy among %d attachments", flavor, len(copies))
	}
	return copies[0].bytes, nil
}

// entrySetEqual compares two ACE sets ignoring order and duplicates — the
// XACML-vs-EAV agreement check (a real mismatch is a per-record HOLD: the
// two representations claim different policies).
func entrySetEqual(a, b []acl.Entry) bool {
	key := func(e acl.Entry) string { return fmt.Sprintf("%s|%s|%v", e.Role, e.Action, e.Allow) }
	am, bm := map[string]bool{}, map[string]bool{}
	for _, e := range a {
		am[key(e)] = true
	}
	for _, e := range b {
		bm[key(e)] = true
	}
	if len(am) != len(bm) {
		return false
	}
	for k := range am {
		if !bm[k] {
			return false
		}
	}
	return true
}

func entriesString(es []acl.Entry) string {
	parts := make([]string, 0, len(es))
	for _, e := range es {
		parts = append(parts, fmt.Sprintf("%s|%s|%v", e.Role, e.Action, e.Allow))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}
