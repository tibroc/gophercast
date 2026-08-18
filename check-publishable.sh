#!/usr/bin/env bash
# check-publishable.sh — publication gate for the ocng public tree.
#
# RUN THIS BEFORE EVERY PUBLIC COMMIT, not just at launch. It exits non-zero
# if the tree contains anything that references the private analysis workspace,
# its defect register, or any description of weaknesses in other systems.
# The public repo must describe ocng's OWN behaviour only.
#
# TWO TIERS of pattern:
#
#   HARD — genuine disclosure risk. Scanned EVERYWHERE, including the vendored
#   admin UI bundle. These name defects or exploits and must never appear:
#     - defect-register identifiers  U-<n>, O-<n>, P-<n>  (case-sensitive, word-bounded)
#     - "CVE" (case-sensitive, word-bounded)
#     - security@opencast.org
#     - "privilege escalation" / any "escalat*"
#     - "deny-that-grants" / "deny that grants" / "deny-that-grant"
#     - "DEFECTS-UPSTREAM", "upstream defect"
#     - "incumbent"  — public code must not explain itself by describing
#       another system's behaviour; any hit needs review and rewording
#     - "vulnerabilit*", "exploit*"
#
#   SOFT — private-workspace references. A leak of process, not of an exploit,
#   but still must not ship. Scanned in OUR source ONLY (the vendored,
#   third-party admin UI bundle is EXCLUDED, because minified variable names
#   like W3/W7 and component names like "Skeleton" collide with these and are
#   not our references):
#     - "oracle", "devstack", "opencast-analysis"  — private artefact names
#     - work-item numbers  W<1-2 digits>  (word-bounded)   — private backlog
#     - "skeleton"                          — the private build-order docs
#     - "harvest"                           — the private corpus-capture process
#     - "PROVENANCE" (case-sensitive)       — the private PROVENANCE.md files
#       (the ordinary lowercase English word "provenance" is intentionally
#       NOT matched)
#     - "CLAUDE.md", "archive/poc-worker", "for-the-rewrite"
#
# The vendored admin UI bundle is scanned at MATCH granularity (not line
# granularity) against the HARD patterns only, so one benign match cannot mask
# another on the same minified line. Exactly ONE known-benign HARD match is
# filtered there: the French UI locale string "Système d'exploitation"
# ("Operating System"), which contains "exploitation". Nothing else is exempt.
# If you add an allowlist entry, justify it in this header and anchor it to
# both file and surrounding content.
#
# Exit 0  = no findings, tree is publishable.
# Exit 1  = findings printed below; the tree MUST NOT be committed/pushed.

set -u
cd "$(dirname "$0")"

# HARD tier (everywhere). CI = case-insensitive, CS = case-sensitive.
HARD_CI='security@opencast\.org|privilege escalation|escalat|deny[- ]that[- ]grants?|DEFECTS-UPSTREAM|upstream defect|incumbent|vulnerabilit|exploit'
HARD_CS='\bU-[0-9]+\b|\bO-[0-9]+\b|\bP-[0-9]+\b|\bCVE\b'

# SOFT tier (our source only; bundle excluded).
SOFT_CI='oracle|devstack|opencast-analysis|skeleton|harvest|CLAUDE\.md|archive/poc-worker|for-the-rewrite'
SOFT_CS='\bW[0-9]{1,2}\b|PROVENANCE'

# self-exclusion: this script necessarily contains the patterns it hunts
COMMON=(-rIn --binary-files=without-match --exclude=check-publishable.sh --exclude-dir=.git)

# main tree: HARD + SOFT, bundle excluded
main_hits=$(
  {
    grep "${COMMON[@]}" -Ei "$HARD_CI" . --exclude-dir=admin-ui-bundle 2>/dev/null
    grep "${COMMON[@]}" -E  "$HARD_CS" . --exclude-dir=admin-ui-bundle 2>/dev/null
    grep "${COMMON[@]}" -Ei "$SOFT_CI" . --exclude-dir=admin-ui-bundle 2>/dev/null
    grep "${COMMON[@]}" -E  "$SOFT_CS" . --exclude-dir=admin-ui-bundle 2>/dev/null
  } | sed 's|^\./||' | cut -c1-400 | sort -u
)

# vendored bundle: HARD patterns only, per-match with context
bundle_hits=$(
  find deploy/admin-ui-bundle -type f 2>/dev/null | while read -r f; do
    {
      grep -oiE ".{0,30}($HARD_CI).{0,30}" "$f" --binary-files=without-match 2>/dev/null
      grep -oE  ".{0,30}($HARD_CS).{0,30}" "$f" --binary-files=without-match 2>/dev/null
    } | grep -v "Système d.exploitation" | sed "s|^|$f: match: |"
  done | sort -u
)

hits=$(printf '%s\n%s\n' "$main_hits" "$bundle_hits" | grep -v '^$')

if [ -n "$hits" ]; then
  echo "NOT PUBLISHABLE — gate found the following:"
  echo "$hits"
  echo
  echo "$(echo "$hits" | wc -l) finding(s). Fix or remove every one, then re-run."
  exit 1
fi

echo "publishable: gate found no findings."
exit 0
