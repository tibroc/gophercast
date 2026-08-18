// Delivery authorization — the D-044 rule (serve-auth).
//
// Authorized against the PUBLISHED PIN (publication.acl_read, pinned
// D-028-evaluated at publish time — delivery authorizes on the pin, never
// the archive ACL), the same rule as the EngageEpisode listing surface
// (search/query.go), so "can see it" and "can fetch it" never diverge:
// there is exactly one enforcement path for delivery.
//
// This function reads no database: the pins come from the serve-read set
// (publication_element → publication), the roles from the validated
// principal (authn, never trusted headers). ABSENT and EMPTY pins both
// refuse, fail-closed (D-032). A stored deny never reaches here: it is
// subtracted from the pin at publish, so a deny can never contribute
// access — by construction, not by convention.
package serve

import "ocng/internal/search"

// PublicationPin is one containing publication's publish-time ACL pin, as
// read from the serve-read set.
type PublicationPin struct {
	MediapackageID string
	Channel        string
	ACLRead        []string
	ACLState       string // D-032: ABSENT / EMPTY / POPULATED — reporting, not decision (both non-POPULATED pins carry ACLRead={})
}

// Authorized is the D-044 delivery decision:
//
//	authorized ⇔ platform admin
//	           ∨ ∃ containing publication: (pin ∩ roles ≠ ∅)
//	                ∨ principal holds ROLE_EPISODE_{mediapackageID}_READ
//
// Zero pins = the element is unpublished → refused to non-admins (F-C, a
// deliberate tightening of increment-2's reference-as-capability serving).
func Authorized(pins []PublicationPin, p search.Principal) bool {
	if p.IsAdmin() {
		return true
	}
	held := make(map[string]bool, len(p.Roles))
	for _, r := range p.Roles {
		held[r] = true
	}
	for _, pin := range pins {
		if held["ROLE_EPISODE_"+pin.MediapackageID+"_READ"] {
			return true
		}
		for _, r := range pin.ACLRead {
			if held[r] {
				return true
			}
		}
	}
	return false
}
