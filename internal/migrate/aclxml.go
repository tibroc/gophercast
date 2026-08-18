// The two ACL document parsers the authoritative representations use:
// XACML (the archive's attachment format) and the plain security-namespace
// <acl><ace>…</ace></acl> shape (OC_SERIES.ACCESS_CONTROL and
// OC_SEARCH.ACCESS_CONTROL). Local-name matching throughout, per the S1
// finding that namespace prefixes vary in the wild.
package migrate

import (
	"encoding/xml"
	"fmt"
	"strings"

	"ocng/internal/acl"
)

// ---- XACML → entries ----------------------------------------------------

type xacmlPolicy struct {
	Rules []xacmlRule `xml:"Rule"`
}

type xacmlRule struct {
	RuleID string `xml:"RuleId,attr"`
	Effect string `xml:"Effect,attr"`
	Target struct {
		Actions []struct {
			AttributeValue string `xml:"ActionMatch>AttributeValue"`
		} `xml:"Actions>Action"`
	} `xml:"Target"`
	Condition struct {
		Apply struct {
			AttributeValue string `xml:"AttributeValue"`
		} `xml:"Apply"`
	} `xml:"Condition"`
}

// parseXACML extracts the ACE list from a legacy-written XACML policy.
// The trailing catch-all Rule without an ActionMatch (the generated
// default-deny) is not an ACE and is skipped — the reference parser applied
// the same rule and the EAV cross-check
// would catch a divergence.
func parseXACML(raw []byte) ([]acl.Entry, error) {
	var p xacmlPolicy
	if err := xml.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("xacml: %w", err)
	}
	var out []acl.Entry
	for _, r := range p.Rules {
		if len(r.Target.Actions) == 0 {
			continue // the generated default-deny catch-all
		}
		role := strings.TrimSpace(r.Condition.Apply.AttributeValue)
		if role == "" {
			return nil, fmt.Errorf("xacml rule %q: action match but no subject role condition", r.RuleID)
		}
		var allow bool
		switch r.Effect {
		case "Permit":
			allow = true
		case "Deny":
			allow = false
		default:
			return nil, fmt.Errorf("xacml rule %q: unknown effect %q", r.RuleID, r.Effect)
		}
		for _, a := range r.Target.Actions {
			action := strings.TrimSpace(a.AttributeValue)
			if action == "" {
				return nil, fmt.Errorf("xacml rule %q: empty action", r.RuleID)
			}
			out = append(out, acl.Entry{Role: role, Action: action, Allow: allow})
		}
	}
	return out, nil
}

// ---- plain <acl><ace> → entries ------------------------------------------

type plainACL struct {
	ACEs []struct {
		Action string `xml:"action"`
		Allow  bool   `xml:"allow"`
		Role   string `xml:"role"`
	} `xml:"ace"`
}

// parsePlainACL parses the security-namespace ACL document stored verbatim
// in OC_SERIES.ACCESS_CONTROL and OC_SEARCH.ACCESS_CONTROL. An <acl/> with
// zero ACEs parses to an empty (non-nil) slice — the EMPTY state, distinct
// from ABSENT (D-032).
func parsePlainACL(raw []byte) ([]acl.Entry, error) {
	var p plainACL
	if err := xml.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("acl xml: %w", err)
	}
	out := []acl.Entry{}
	for _, a := range p.ACEs {
		if a.Role == "" || a.Action == "" {
			return nil, fmt.Errorf("acl xml: ace with empty role or action")
		}
		out = append(out, acl.Entry{Role: a.Role, Action: a.Action, Allow: a.Allow})
	}
	return out, nil
}
