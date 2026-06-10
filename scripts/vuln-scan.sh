#!/usr/bin/env bash
#
# vuln-scan.sh — govulncheck across the workspace modules, gated against a
# baseline of known reachable vulnerabilities.
#
# govulncheck is reachability-aware: it only reports advisories whose
# vulnerable code is actually called from our binaries (e.g. the 2026
# x/crypto/ssh CVE never fired here because the ssh package is never
# compiled in). This script fails ONLY on reachable findings that are not
# listed in .github/vuln-baseline.txt — i.e. it catches NEW advisories.
#
# Why a baseline instead of plain pass/fail:
#   An advisory can be published before a fix is shippable here (toolchain
#   pin, dependency not yet released, upgrade needs validation). The
#   baseline records that debt explicitly instead of letting the gate rot
#   red — the Go 1.23 era carried 37 entries until the 2026-06 toolchain
#   + nats-server 2.11 bump cleared them. Remove entries as they get
#   fixed; the script prints stale entries so the file shrinks over time.
#
# GOTOOLCHAIN is forced to go1.26.4 (matching the CI toolchain) so local
# runs on newer dev toolchains produce the same stdlib findings as CI.
# Override with GOTOOLCHAIN env if needed.
#
# Usage:
#   scripts/vuln-scan.sh            # gate against the baseline
#   scripts/vuln-scan.sh --print    # just print current reachable IDs
#                                   # (to regenerate the baseline)
#
# Requires: govulncheck (pinned in CI to v1.3.0 — pin exact, never @latest),
#           jq.

set -euo pipefail
cd "$(dirname "$0")/.."

export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.4}"

MODULES=(api agent proto)
BASELINE=.github/vuln-baseline.txt

found="$(mktemp)"
trap 'rm -f "$found"' EXIT

for m in "${MODULES[@]}"; do
  echo "=== govulncheck: $m ==="
  # Human-readable report for the log. Exit status intentionally ignored —
  # the gate below is the JSON pass filtered through the baseline.
  (cd "$m" && govulncheck ./...) || true

  # Reachable findings only: call-level findings carry a function in the
  # first trace frame; module/package-level (unreached) findings don't.
  (cd "$m" && govulncheck -format json ./...) \
    | jq -r 'select(.finding != null) | .finding
             | select(.trace[0].function != null) | .osv' >>"$found"
done

sort -u -o "$found" "$found"

if [ "${1:-}" = "--print" ]; then
  cat "$found"
  exit 0
fi

baseline_ids="$(mktemp)"
# `|| true`: grep exits 1 when the baseline is all comments (fully clean)
{ grep -vE '^[[:space:]]*(#|$)' "$BASELINE" || true; } | sort -u >"$baseline_ids"

stale="$(comm -13 "$found" "$baseline_ids")"
new="$(comm -23 "$found" "$baseline_ids")"

if [ -n "$stale" ]; then
  echo
  echo "Baseline entries no longer detected — remove them from $BASELINE:"
  echo "$stale"
fi

if [ -n "$new" ]; then
  echo
  echo "::error::New reachable vulnerabilities, not in $BASELINE:"
  echo "$new" | sed 's|^|  https://pkg.go.dev/vuln/|'
  echo "Fix the dependency (pin an exact version — see CLAUDE.md before" \
       "running go get) or, if no fix is shippable yet, add the ID to" \
       "$BASELINE with a comment."
  exit 1
fi

echo
echo "OK: no reachable vulnerabilities outside the baseline" \
     "($(wc -l <"$found" | tr -d ' ') known, tracked in $BASELINE)."
