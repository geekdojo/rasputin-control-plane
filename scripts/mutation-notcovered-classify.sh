#!/usr/bin/env bash
#
# mutation-notcovered-classify.sh — cross-check gremlins' "NOT COVERED"
# mutants against a real Go coverage profile and split them into genuine
# coverage gaps vs. instrumentation artifacts.
#
# WHY THIS EXISTS
# ---------------
# gremlins labels a mutant "NOT COVERED" when it can't find a coverage block
# that OPENS at the mutant's exact line:column. But Go's cover tool opens the
# block for a `switch { case <expr>: }` at the case *body* column, never at the
# case *expression* column. So a mutant on the case expression
#
#     case recoveries >= cfg.MaxRecoveries:        // mutant at col 22
#         doSomething()                            // cover block opens at col 43
#
# is reported "NOT COVERED" even though the line is executed by the tests and
# the mutant is actually killed. The mutation-gate publishes NOT COVERED lines
# under "a fault the tests did not catch" — which, for these, is simply false
# and sends the reader off writing tests for faults the suite already catches.
# See rasputin-control-plane#59.
#
# This script re-checks each NOT COVERED mutant against the coverage profile by
# LINE CONTAINMENT (is the mutant's line inside any executed block?) instead of
# by exact column, which is what the reader actually cares about: "does any test
# run this line?".
#
# CONTRACT
# --------
#   Usage:  mutation-notcovered-classify.sh <module-dir>  < gremlins-notcovered-lines
#
#   stdin  — gremlins output lines, one per NOT COVERED mutant, MODULE-RELATIVE
#            paths, exactly as gremlins prints them, e.g.
#              NOT COVERED CONDITIONALS_BOUNDARY at internal/nameguard/nameguard.go:250:22
#   arg1   — the Go module directory the paths are relative to (e.g. "agent").
#
#   stdout — each input line echoed back verbatim, prefixed with a tab-delimited
#            classification token:
#              REAL<TAB><line>      the line is genuinely not covered — a real gap
#              ARTIFACT<TAB><line>  the line IS covered; NOT COVERED is a mislabel
#
# FAIL-SAFE: if the coverage profile can't be built (e.g. a test failure), every
# mutant is classified REAL and a warning is written to stderr. We never hide a
# potential gap on our own uncertainty — worst case we show a covered line the
# way gremlins already did, which is the pre-existing behaviour.

set -euo pipefail

module="${1:?usage: mutation-notcovered-classify.sh <module-dir> < notcovered-lines}"

# Read stdin once.
input="$(cat)"
if [ -z "${input//[[:space:]]/}" ]; then
  exit 0   # nothing to classify
fi

# Emit every line as REAL and exit — used on any error path.
emit_all_real() {
  printf '%s\n' "$input" | while IFS= read -r line; do
    [ -z "$line" ] && continue
    printf 'REAL\t%s\n' "$line"
  done
}

# The location token is the field right after " at ", e.g.
#   internal/nameguard/nameguard.go:250:22  ->  path=..go line=250 col=22
# Collect the unique package directories so we only build coverage for the
# packages that actually have NOT COVERED mutants (keeps this fast).
pkgs=""
while IFS= read -r line; do
  [ -z "$line" ] && continue
  loc="${line##* at }"                     # strip everything up to and incl " at "
  path="${loc%%:*}"                        # internal/nameguard/nameguard.go
  dir="./$(dirname "$path")/"              # ./internal/nameguard/
  case " $pkgs " in *" $dir "*) : ;; *) pkgs="$pkgs $dir" ;; esac
done <<< "$input"

prof="$(mktemp)"
trap 'rm -f "$prof"' EXIT

# Build coverage for just those packages, from inside the module dir.
if ! ( cd "$module" && go test -covermode=set -coverprofile="$prof" $pkgs ) >/dev/null 2>&1; then
  echo "mutation-notcovered-classify: coverage build failed for '$module' ($pkgs); treating all NOT COVERED as real" >&2
  emit_all_real
  exit 0
fi

# For each mutant, decide covered vs. not by line containment.
#   covered  := ∃ profile block whose path ends with the mutant's relpath,
#               whose [startLine,endLine] contains the mutant's line, count > 0.
printf '%s\n' "$input" | while IFS= read -r line; do
  [ -z "$line" ] && continue
  loc="${line##* at }"
  path="${loc%%:*}"
  rest="${loc#*:}"
  lineno="${rest%%:*}"

  covered=$(awk -v rel="$path" -v want="$lineno" '
    /^mode:/ { next }
    {
      # $1 = "<importpath>/<relpath>:<sL>.<sC>,<eL>.<eC>"; split off the pos on
      # the LAST colon (Go import paths and file paths carry no colon).
      field = $1
      p = field
      pos = ""
      n = split(field, parts, ":")
      pos = parts[n]
      # path is everything before the final ":" + pos
      path = substr(field, 1, length(field) - length(pos) - 1)
      # suffix match: does this profile path end with the mutant relpath?
      if (length(path) < length(rel)) next
      if (substr(path, length(path) - length(rel) + 1) != rel) next
      # pos = sL.sC,eL.eC
      split(pos, se, ",")
      split(se[1], s, ".")
      split(se[2], e, ".")
      sL = s[1] + 0
      eL = e[1] + 0
      count = $NF + 0
      if (count > 0 && sL <= want && want <= eL) { hit = 1 }
    }
    END { print (hit ? "1" : "0") }
  ' "$prof")

  if [ "$covered" = "1" ]; then
    printf 'ARTIFACT\t%s\n' "$line"
  else
    printf 'REAL\t%s\n' "$line"
  fi
done
