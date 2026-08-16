#!/usr/bin/env bash
#
# sast-scan.sh — static analysis of OUR OWN code across the workspace
# modules (api / agent / proto). Companion to vuln-scan.sh, which asks a
# different question: govulncheck finds known advisories in our
# DEPENDENCIES; nothing before this looked at code we wrote.
#
# Two tools, two policies, on purpose:
#
#   staticcheck — correctness/simplification lint. Gated CLEAN: any finding
#                 fails. It was already clean when this gate landed (two
#                 findings across ~90k lines, both fixed in the same PR),
#                 because quality-sweep.yml has been running it advisorily
#                 since July 2026. A clean gate keeps it that way.
#
#   gosec       — security-focused SAST. Gated against a BASELINE in
#                 .github/gosec-baseline.txt, because the first run over
#                 never-scanned code produced 148 findings. Failing on all
#                 of them would have meant either a red gate or no gate;
#                 the baseline ships the gate now and leaves the burn-down
#                 as tracked work (geekdojo/geekdojo-brain#103).
#
# What the baseline does NOT contain: anything HIGH. All 12 HIGH findings
# from the first run were triaged in the landing PR and are suppressed at
# the source with an explicit `#nosec Gxxx -- reason` naming why each is a
# false positive or deliberate. That is the rule going forward — a HIGH is
# fixed or justified in code, never parked in this file.
#
# Baseline mechanics
# ------------------
# Each finding is fingerprinted as
#
#     sha256(rule_id \0 repo-relative-path \0 normalized-code)[:16]
#
# where normalized-code is gosec's reported snippet with its "NN: " line
# prefixes stripped and each line trimmed. Line numbers are deliberately
# NOT part of the key: they churn on every edit above the finding, and a
# baseline that churns is a baseline nobody updates. Editing the flagged
# line itself DOES change the fingerprint, which re-fires the finding —
# that is intended, since the code under the finding changed.
#
# Identical findings (same rule, same file, same snippet) collapse to one
# fingerprint, so the baseline also records a COUNT. Seeing more than the
# baseline count fails; seeing fewer is reported as stale but passes, so
# the file shrinks as debt is paid rather than rotting. Same contract as
# vuln-scan.sh.
#
# Usage:
#   scripts/sast-scan.sh             # gate (what CI runs)
#   scripts/sast-scan.sh --print     # emit a fresh baseline on stdout,
#                                    # to regenerate .github/gosec-baseline.txt
#   scripts/sast-scan.sh --install   # install the pinned tools (CI uses this)
#
# Requires: go, python3, and the two tools below. Run --install to get them;
# it puts them in $(go env GOPATH)/bin, which must be on PATH.

set -euo pipefail
cd "$(dirname "$0")/.."

# Exact pins, never @latest — a new release of either tool can drag in a
# newer toolchain requirement (the trap vuln-scan.yml documents) or change
# rule behaviour, which would move the gate under us. These two lines are
# the single source of truth: sast.yml installs via `--install` rather than
# repeating the versions in YAML, so the workflow and the script cannot drift.
GOSEC_VERSION=v2.28.0
STATICCHECK_VERSION=2025.1.1

MODULES=(api agent proto)
BASELINE=.github/gosec-baseline.txt

if [ "${1:-}" = "--install" ]; then
  echo "installing gosec ${GOSEC_VERSION} and staticcheck ${STATICCHECK_VERSION}"
  go install "github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION}"
  go install "honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION}"
  exit 0
fi

for tool in gosec staticcheck python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "::error::$tool not found on PATH."
    echo "  gosec/staticcheck: run 'scripts/sast-scan.sh --install' and make sure"
    echo "  \"\$(go env GOPATH)/bin\" is on your PATH. python3 ships with macOS and"
    echo "  with the ubuntu-latest runner."
    exit 1
  fi
done

PRINT_ONLY=false
[ "${1:-}" = "--print" ] && PRINT_ONLY=true

# ── staticcheck: clean gate ──────────────────────────────────────────────
# Skipped entirely in --print mode, which only regenerates the gosec baseline.
if [ "$PRINT_ONLY" = false ]; then
  sc_out="$(mktemp)"
  trap 'rm -f "$sc_out"' EXIT
  for m in "${MODULES[@]}"; do
    echo "=== staticcheck: $m ==="
    (cd "$m" && staticcheck ./...) >>"$sc_out" 2>&1 || true
  done
  if [ -s "$sc_out" ]; then
    echo
    echo "::error::staticcheck findings (this gate is clean — fix them, there is no baseline):"
    cat "$sc_out"
    exit 1
  fi
  echo "OK: staticcheck clean across ${MODULES[*]}."
  echo
fi

# ── gosec: baseline-gated ────────────────────────────────────────────────
# -nosec-require-rules + -nosec-require-justification: an annotation must name
# the rule it silences AND carry a `-- reason`. A bare `#nosec` is rejected,
# so a suppression can't be added without saying what and why.
#
# Test files are left out (gosec's default). They are not shipped, and their
# throwaway file permissions and hardcoded fixture "credentials" would be
# most of the noise for none of the signal.
findings="$(mktemp)"
trap 'rm -f "${sc_out:-}" "$findings"' EXIT
: >"$findings"

for m in "${MODULES[@]}"; do
  [ "$PRINT_ONLY" = false ] && echo "=== gosec: $m ==="
  (cd "$m" && gosec -fmt=json -quiet -no-fail \
    -nosec-require-rules -nosec-require-justification ./... 2>/dev/null) >>"$findings" || true
done

# gosec emits one JSON document per module (and nothing at all for a module
# with no findings), so the fingerprinting step reads a concatenated stream
# rather than a single object.
fingerprints="$(mktemp)"
trap 'rm -f "${sc_out:-}" "$findings" "$fingerprints"' EXIT

REPO_ROOT="$PWD" python3 - "$findings" >"$fingerprints" <<'PY'
import hashlib, json, os, re, sys
from collections import Counter

repo_root = os.environ["REPO_ROOT"].rstrip("/") + "/"
raw = open(sys.argv[1], encoding="utf-8").read()

# Split the concatenated per-module JSON documents.
issues, decoder, idx = [], json.JSONDecoder(), 0
while idx < len(raw):
    while idx < len(raw) and raw[idx].isspace():
        idx += 1
    if idx >= len(raw):
        break
    doc, idx = decoder.raw_decode(raw, idx)
    issues.extend(doc.get("Issues") or [])

LINE_PREFIX = re.compile(r"^\s*\d+:\s?")

counts, meta = Counter(), {}
for i in issues:
    path = i["file"]
    rel = path[len(repo_root):] if path.startswith(repo_root) else path
    code = "\n".join(LINE_PREFIX.sub("", ln).strip()
                     for ln in i.get("code", "").splitlines())
    key = "\x00".join((i["rule_id"], rel, code))
    fp = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    counts[fp] += 1
    meta[fp] = (i["rule_id"], i["severity"], rel, i["details"])

for fp, n in sorted(counts.items(), key=lambda kv: (meta[kv[0]][2], meta[kv[0]][0], kv[0])):
    rule, sev, rel, details = meta[fp]
    print(f"{fp}  {n}  {rule}  {sev}  {rel}  # {details}")
PY

if [ "$PRINT_ONLY" = true ]; then
  cat <<'HDR'
# gosec-baseline.txt — findings that existed when the SAST gate landed.
#
# Regenerate with:  scripts/sast-scan.sh --print > .github/gosec-baseline.txt
# Policy, fingerprint scheme, and why this file exists: scripts/sast-scan.sh
#
# Columns: fingerprint  count  rule  severity  path  # detail
#
# NOTHING HIGH BELONGS HERE. A HIGH finding is fixed, or suppressed at the
# source with `#nosec Gxxx -- reason`. Adding one to this file is how the
# gate stops being worth having.
#
# Shrinking this file is the point. Delete a line once its finding is fixed;
# the gate prints stale entries on every run to make that easy.
HDR
  cat "$fingerprints"
  exit 0
fi

# Compare observed against baseline. Both sides are keyed on fingerprint;
# a higher observed count than the baseline records is a new occurrence.
BASELINE="$BASELINE" python3 - "$fingerprints" <<'PY'
import os, sys

def load(path, comments_ok):
    out = {}
    if not os.path.exists(path):
        return out
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip() if comments_ok else line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        out[parts[0]] = (int(parts[1]), parts[2], parts[3], parts[4])
    return out

found = load(sys.argv[1], False)
base = load(os.environ["BASELINE"], True)

new, grown, stale = [], [], []
for fp, (n, rule, sev, rel) in sorted(found.items(), key=lambda kv: kv[1][3]):
    if fp not in base:
        new.append((fp, n, rule, sev, rel))
    elif n > base[fp][0]:
        grown.append((fp, n, base[fp][0], rule, sev, rel))
for fp, (n, rule, sev, rel) in sorted(base.items(), key=lambda kv: kv[1][3]):
    if fp not in found:
        stale.append((fp, rule, sev, rel))
    elif found[fp][0] < n:
        stale.append((fp, rule, sev, rel + f" ({n} -> {found[fp][0]})"))

if stale:
    print()
    print(f"Baseline entries no longer detected at full count — prune {os.environ['BASELINE']}:")
    for fp, rule, sev, rel in stale:
        print(f"  {fp}  {rule}  {sev}  {rel}")

if new or grown:
    print()
    print(f"::error::New gosec findings, not in {os.environ['BASELINE']}:")
    for fp, n, rule, sev, rel in new:
        print(f"  {fp}  {rule}  {sev}  {rel}  (x{n})")
    for fp, n, was, rule, sev, rel in grown:
        print(f"  {fp}  {rule}  {sev}  {rel}  ({was} -> {n} occurrences)")
    print()
    print("Fix the finding, or — if it is a false positive or deliberate —")
    print("annotate the line with `#nosec Gxxx -- why`, which is required to")
    print("name the rule and carry a justification. Add to the baseline ONLY")
    print("for pre-existing MEDIUM/LOW debt you are explicitly deferring.")
    sys.exit(1)

total = sum(n for n, *_ in found.values())
print()
print(f"OK: no gosec findings outside {os.environ['BASELINE']} "
      f"({total} known, tracked there).")
PY
