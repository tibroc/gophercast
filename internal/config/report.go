package config

import "strings"

// CorePostures is the input to the pilot-gate boot report (T5 step 3 / F-2):
// the dev-grade postures a booting core may be in. Each true field is a
// posture the pilot-gate table in deploy/CONFIG.md says a real deployment
// must not ship with. GC-disabled is deliberately NOT here: it is the
// correct posture everywhere until the T4 gate's precondition exists, so it
// is info-grade, not dev-grade.
type CorePostures struct {
	// ServeEnforcementOff: OCNG_SERVE_DB_URL is unset. NOT one tuning
	// default among many — T2's structural least-privilege boundary (the
	// ocng_serve role holding SELECT on exactly the serve-read set) is not
	// active, and serve runs on the general pool. A disabled security
	// boundary reads differently from a tuning default (T5 ratification),
	// so the report names it in its own block.
	ServeEnforcementOff bool
	// ServePasswordDefault: OCNG_SERVE_DB_PASSWORD is the dev default,
	// which is public knowledge (it is in this repository).
	ServePasswordDefault bool
	// DevAuth: OCNG_DEV_AUTH=1 — the dev auth seam is open.
	DevAuth bool
	// NoIdentityPath: neither OIDC nor LTI is configured — the system boots
	// but every authenticated surface answers 403 (fail-closed, and now
	// fail-LOUD at boot instead of discovered in production).
	NoIdentityPath bool
}

// BootReport renders the unmissable post-validation block. Empty string
// when no dev-grade posture is in effect (the production shape) — the
// caller logs a one-line all-clear instead.
func (p CorePostures) BootReport() string {
	var b strings.Builder
	if p.ServeEnforcementOff {
		b.WriteString(`!! SERVE-READ-SET ENFORCEMENT DISABLED — OCNG_SERVE_DB_URL is unset.
!! T2's structural boundary is NOT active: the serve surface runs on the
!! general pool instead of the least-privilege ocng_serve role, so an
!! out-of-set serve query would succeed instead of failing at the database.
!! This is a disabled security boundary, not a tuning default. Dev-only.
`)
	}
	var gates []string
	if p.ServePasswordDefault {
		gates = append(gates, "OCNG_SERVE_DB_PASSWORD is the dev default — the value is public knowledge (it is in the ocng repository)")
	}
	if p.DevAuth {
		gates = append(gates, "OCNG_DEV_AUTH=1 — the dev auth seam is OPEN; production must not set it (T1, ADR-012)")
	}
	if p.NoIdentityPath {
		gates = append(gates, "no identity path configured (no OCNG_OIDC_ISSUER, no OCNG_LTI_PLATFORMS_FILE) — every authenticated surface answers 403; nobody can log in")
	}
	for _, g := range gates {
		b.WriteString(" - " + g + "\n")
	}
	if b.Len() == 0 {
		return ""
	}
	return "════════ OCNG BOOT REPORT — DEV-GRADE POSTURES IN EFFECT ════════\n" +
		b.String() +
		"see deploy/CONFIG.md (pilot-gate table) before any real deployment\n" +
		"══════════════════════════════════════════════════════════════════"
}

// AllClear is the production shape's one-line signal that the report ran
// and found nothing (so its absence is never ambiguous in logs).
const AllClear = "boot report: no dev-grade postures in effect"
