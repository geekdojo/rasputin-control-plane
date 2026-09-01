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
# GOTOOLCHAIN is forced to go1.26.6 (matching the CI toolchain) so local
# runs on newer dev toolchains produce the same stdlib findings as CI.
# Override with GOTOOLCHAIN env if needed.
#
# Keep this EXACTLY equal to the GOTOOLCHAIN in .github/workflows/vuln-scan.yml.
# It had drifted to go1.26.5 while the workflow moved to go1.26.6, and the two
# are not cosmetically different: 1.26.6 fixes GO-2026-5972 (encoding/asn1
# recursion depth), which artifactsig reaches through pkcs7.Parse when it parses
# a downloaded .sig. Once artifactsig came into scope, a local run therefore
# reported a reachable advisory that CI could not see — the exact inversion of
# the promise this line exists to make.
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

export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.6}"

# The module list is DERIVED from go.work, not written out here.
#
# It was written out here until 2026-09-01, as `MODULES=(api agent proto)`, and
# it had drifted: go.work grew ./artifactsig and ./tileschema and this list did
# not, so the module that verifies every release signature and the module that
# validates every catalog tile were covered by no run of this gate at all. The
# gate stayed green the whole time, because a hardcoded list cannot report the
# code it was never pointed at.
#
# The derivation itself lives in ONE place, scripts/workspace-modules.sh, which
# also carries the guards (empty list, module with no go.mod) and is shared with
# codeql.yml and ci.yml. It was briefly an awk parser inlined here and copied
# verbatim into the other script — two copies of a parser being one edit away
# from disagreeing about what the workspace contains, which is the original
# hazard one step removed.
#
# Command substitution, NOT `mapfile < <(...)`: process substitution does not
# propagate the helper's exit status, so a failing helper would leave MODULES
# empty and this gate would pass having scanned nothing. `$( )` fails the
# script under `set -e`, which is the behaviour a coverage gate needs.
#
# Word-split into the array rather than `mapfile`, which is bash 4+ and so
# absent on macOS's stock bash 3.2 — these gates are run locally too.
modules_list="$(scripts/workspace-modules.sh)"
# shellcheck disable=SC2206  # deliberate word splitting; module dirs have no spaces
MODULES=($modules_list)

BASELINE=.github/vuln-baseline.txt

found="$(mktemp)"
trap 'rm -f "$found"' EXIT

echo "govulncheck: ${#MODULES[@]} workspace module(s) from go.work — ${MODULES[*]}"

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
echo "OK: no reachable vulnerabilities outside the baseline across" \
     "${#MODULES[@]} module(s) (${MODULES[*]}) —" \
     "$(wc -l <"$found" | tr -d ' ') known, tracked in $BASELINE."
