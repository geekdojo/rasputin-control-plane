#!/usr/bin/env bash
#
# workspace-modules.sh — print every module in go.work, one per line, as a
# repo-relative directory ("agent", "api", ...).
#
# WHY THIS EXISTS. Four places each carried their own hand-written copy of the
# module list, and all four still said `api agent proto` long after go.work
# grew ./artifactsig and ./tileschema:
#
#   scripts/vuln-scan.sh          govulncheck
#   scripts/sast-register.sh      gosec + staticcheck
#   .github/workflows/codeql.yml  the CodeQL database build
#   .github/workflows/ci.yml      gofmt + vet + test + build
#
# #214 fixed the first two by deriving the list from go.work. It did so with an
# awk parser COPY-PASTED into both scripts, and left the other two untouched —
# so artifactsig was still absent from every CodeQL database and was still
# never built, vetted or tested by CI, tests and all.
#
# This file finishes the job and removes the duplication in the same move. Two
# copies of a parser is the same hazard one step removed: they are one edit
# apart from disagreeing about what the workspace contains, and the copy nobody
# looks at is the one that goes wrong. One derivation, four callers.
#
# `go work edit -json` rather than parsing go.work as text: it is the
# toolchain's own parser, so the block form, the single-line `use` form and
# comments are read exactly as the go command reads them. Hand-rolled matching
# of go.work is a fifth thing that can drift from what Go actually does.
#
# THE GUARDS BELOW ARE THE POINT, not defensive padding. The failure mode a
# derived list must never have is silently yielding nothing (or naming a module
# the scanner then skips), because every caller loops over this output — an
# empty list makes every gate pass having scanned zero code, which is worse
# than the hardcoded list it replaced. So an empty list is a hard error, and
# every module named must actually carry a go.mod.
#
# ONE list in the repo still cannot be derived: the gomod `directories:` block
# in .github/dependabot.yml. Dependabot reads that file directly and has no way
# to call a script, so it is written by hand and can drift exactly as the
# scanners did. --verify-dependabot is the compensating control: it fails when
# that block and go.work disagree, turning the one irreducible literal into a
# checked one. Wired into ci.yml so it runs on every PR.
#
# Usage:
#   scripts/workspace-modules.sh                      # one module per line
#   scripts/workspace-modules.sh --verify-dependabot  # go.work vs dependabot.yml
#   modules="$(scripts/workspace-modules.sh)"         # NOT mapfile < <(...) —
#                                                     # see the callers' notes

set -euo pipefail
cd "$(dirname "$0")/.."

# One {"DiskPath": "./x"} object per member; strip the leading "./" so callers
# get a plain relative dir they can `cd` into. Sorted so log lines and register
# ordering stay stable if someone reorders go.work.
modules="$(
  go work edit -json |
    sed -n 's/^[[:space:]]*"DiskPath":[[:space:]]*"\(.*\)",\{0,1\}$/\1/p' |
    sed 's|^\./||' |
    sort
)"

if [ -z "$modules" ]; then
  echo "::error::no modules found in go.work — every scan gate loops over this" \
       "list, so an empty one would let them all pass having scanned nothing." >&2
  exit 1
fi

# A module named here that the tool then skips (wrong path, missing go.mod) is
# the same silent-coverage-loss failure in a different costume, so prove each
# one is a real module before any caller trusts the list.
missing=""
while IFS= read -r m; do
  [ -f "$m/go.mod" ] || missing="$missing $m"
done <<<"$modules"

if [ -n "$missing" ]; then
  echo "::error::go.work lists module(s) with no go.mod:$missing" >&2
  exit 1
fi

if [ "${1:-}" = "--verify-dependabot" ]; then
  MODULES="$modules" python3 - <<'PY'
import os, re, sys

want = set(os.environ["MODULES"].split())

src = open(".github/dependabot.yml", encoding="utf-8").read()

# Pull the `directories:` list out of the gomod ecosystem block. Deliberately
# narrow: match the gomod entry, then its directories list, then stop at the
# next ecosystem at the same level. A YAML parser is not available by default
# on the runner and this file's shape is fixed by Dependabot's own schema.
m = re.search(
    r"^\s*-\s*package-ecosystem:\s*gomod\s*$(.*?)(?=^\s*-\s*package-ecosystem:|\Z)",
    src, re.M | re.S)
if not m:
    print("::error::no gomod block found in .github/dependabot.yml", file=sys.stderr)
    sys.exit(1)

d = re.search(r"^(\s*)directories:\s*$((?:\n?\s*-\s*\S+)+)", m.group(1), re.M)
if not d:
    print("::error::gomod block in .github/dependabot.yml has no 'directories:' list",
          file=sys.stderr)
    sys.exit(1)

have = {ln.strip().lstrip("-").strip().lstrip("/")
        for ln in d.group(2).splitlines() if ln.strip().startswith("-")}

if have != want:
    print("::error::.github/dependabot.yml gomod directories do not match go.work.",
          file=sys.stderr)
    for x in sorted(want - have):
        print(f"  in go.work but NOT covered by Dependabot: {x}", file=sys.stderr)
    for x in sorted(have - want):
        print(f"  listed for Dependabot but NOT in go.work: {x}", file=sys.stderr)
    print("Dependabot cannot call a script, so this block is written by hand —"
          " update it to match go.work.", file=sys.stderr)
    sys.exit(1)

print(f"dependabot.yml gomod directories match go.work ({len(want)} modules)")
PY
  exit 0
fi

printf '%s\n' "$modules"
