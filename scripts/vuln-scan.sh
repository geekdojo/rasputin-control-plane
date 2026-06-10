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
#   - CI pins Go 1.23 (see CLAUDE.md "Go gotcha"), which is past EOL.
#     ~20 reachable stdlib advisories are unfixable on this toolchain;
#     their fixes only ship in Go 1.24/1.25.
#   - nats-server fixes for the 2026 advisories live on 2.11.x, which
#     requires Go >= 1.24 — also blocked by the pin.
#   The baseline records that debt explicitly. Remove entries as they get
#   fixed; the script prints stale entries so the file shrinks over time.
#
# GOTOOLCHAIN is forced to go1.23.12 (the final 1.23 release, matching the
# CI toolchain) so local runs on newer dev toolchains produce the same
# stdlib findings as CI. Override with GOTOOLCHAIN env if needed.
#
# Usage:
#   scripts/vuln-scan.sh            # gate against the baseline
#   scripts/vuln-scan.sh --print    # just print current reachable IDs
#                                   # (to regenerate the baseline)
#
# Requires: govulncheck (pinned in CI to v1.1.4 — v1.2.0+ needs Go >= 1.25),
#           jq.

set -euo pipefail
cd "$(dirname "$0")/.."

export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.23.12}"

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
grep -vE '^[[:space:]]*(#|$)' "$BASELINE" | sort -u >"$baseline_ids"

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
       "running go get) or, if unfixable under the Go 1.23 pin, add the" \
       "ID to $BASELINE with a comment."
  exit 1
fi

echo
echo "OK: no reachable vulnerabilities outside the baseline" \
     "($(wc -l <"$found" | tr -d ' ') known, tracked in $BASELINE)."
