// Package config is T5's one validation pass over the env surface: the same
// env vars the binaries always read, collected against a Set that reports
// ALL missing and invalid variables in ONE exit message instead of first-hit
// (pre-T5, an operator fixed five vars one boot at a time).
//
// This is NOT a new configuration format (T5 ratification, §2 of the
// ADR-009: general operator config lives in the deployment
// definitions — quadlet Environment=/Secret= lines, compose environment:
// blocks — and nothing in the ADR authorises a config file read by the
// binaries). It is the existing surface with its validation unified and its
// fail-loud holes closed:
//
//   - every currently-required var stays required;
//   - int and duration parse errors are FATAL everywhere (the F-1 fix —
//     pre-T5, OCNG_CAPACITY_MEMORY_MB=8G silently became 0 = unconstrained,
//     a capacity typo silently removing the admission bound);
//   - conditional requires keep their exact semantics.
//
// The paper twin of this package is deploy/CONFIG.md (the pilot-gate table).
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Set collects reads of the env surface and the errors they produce. Zero
// value is ready to use.
type Set struct {
	errs []string
}

// Errf records a validation error against the set (for checks that live
// outside the getters, e.g. file-content-dependent requires).
func (s *Set) Errf(format string, args ...any) {
	s.errs = append(s.errs, fmt.Sprintf(format, args...))
}

// Require reads a var that must be set and non-empty.
func (s *Set) Require(name string) string {
	v := os.Getenv(name)
	if v == "" {
		s.Errf("%s is required and not set", name)
	}
	return v
}

// String reads an optional var with a default.
func (s *Set) String(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// Raw reads an optional var, reporting whether it was set. No validation —
// presence itself is the signal (mode switches, opt-in features).
func (s *Set) Raw(name string) (string, bool) {
	v := os.Getenv(name)
	return v, v != ""
}

// Int reads an optional integer var. A set-but-unparseable value is a
// FATAL validation error (F-1): a typo must never silently become the
// default.
func (s *Set) Int(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		s.Errf("%s=%q is not an integer", name, v)
		return def
	}
	return n
}

// Int64 reads an optional int64 var (same F-1 posture), reporting presence.
func (s *Set) Int64(name string) (int64, bool) {
	v := os.Getenv(name)
	if v == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		s.Errf("%s=%q is not an integer", name, v)
		return 0, true
	}
	return n, true
}

// Duration reads an optional duration var (same F-1 posture: set-but-bad is
// fatal), reporting presence.
func (s *Set) Duration(name string) (time.Duration, bool) {
	v := os.Getenv(name)
	if v == "" {
		return 0, false
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		s.Errf("%s=%q is not a duration (use forms like 90s, 5m, 24h)", name, v)
		return 0, true
	}
	return d, true
}

// Err returns nil when the surface validated, or ONE error naming every
// missing and invalid variable — the all-errors-at-once exit message.
func (s *Set) Err() error {
	if len(s.errs) == 0 {
		return nil
	}
	return fmt.Errorf("invalid configuration (%d problem(s)):\n  - %s\nsee deploy/CONFIG.md",
		len(s.errs), strings.Join(s.errs, "\n  - "))
}
