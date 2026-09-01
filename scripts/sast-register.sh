#!/usr/bin/env bash
#
# sast-register.sh — maintain .github/sast-register.tsv, the reviewed record of
# every gosec finding in this repo.
#
# The register exists because the FIRST attempt at this (PR #139, reverted in
# #140) shipped a CI gate whose baseline held 148 findings nobody had read, and
# then printed "OK". That pattern was lifted from scripts/vuln-scan.sh without
# re-checking its rationale: a DEPENDENCY baseline is justified because a fix
# may not be shippable yet — upstream hasn't released, the toolchain is pinned.
# For our own code a fix is always available, so the baseline was doing no work
# except keeping the gate green.
#
# The specific error was using SEVERITY as a proxy for REVIEWED. gosec's
# severity is a property of the RULE, not of our code. Reading 11 of those
# baselined MEDIUMs found 6 real or decision-needing — including
# geekdojo/geekdojo-brain#143, where the passkey session cookie shipped without
# Secure on every appliance.
#
# So: every finding carries a recorded verdict and the reasoning behind it.
# "Unreviewed" is a state the register can express and report, not one it hides.
#
# Verdicts
# --------
#   real          a genuine defect. Gets its own issue; the row cites it.
#   false-positive the rule fired but the code is correct. Reasoning must say
#                 WHY, specifically enough that the next reader need not
#                 re-derive it.
#   deliberate    the pattern is real and intended, with a stated tradeoff.
#   blocked       real, but the fix waits on a decision. The row cites the
#                 deciding issue — these are what get revisited when a fix
#                 becomes available, which is the point of the register.
#   unreviewed    nobody has looked yet. Never a resting state.
#
# Fingerprints
# ------------
# sha256(rule_id, repo-relative path, normalized snippet) truncated to 16 hex.
# Line numbers are deliberately EXCLUDED: they churn on every edit above a
# finding, and a register that churns is one nobody updates. Editing the
# flagged line itself DOES change the fingerprint and resets the row to
# unreviewed — intended, since the code the verdict described has changed.
#
# The `line` column is for human navigation only and is refreshed on every run;
# it is not part of the identity.
#
# The gate
# --------
# --gate is what CI runs. It fails on:
#
#   * any staticcheck finding — that gate is CLEAN, with no register and no
#     baseline. It measured 2 findings across ~90k lines, so clean is cheap
#     to hold;
#   * any gosec finding whose fingerprint is not in the register — something
#     new arrived and nobody has looked at it;
#   * any register row still marked `unreviewed` — the state exists to be
#     reported, never to be rested in;
#   * any `real` or `blocked` row with no issue cited — an untracked defect
#     is one that will be forgotten, and a `blocked` row with no deciding
#     issue can never be revisited when the fix becomes available.
#
# It does NOT fail merely because `real` findings exist. Blocking every merge
# until the last defect is fixed is the same over-strictness that produced the
# unread baseline; the contract is that nothing is NEW and nothing is UNSEEN,
# not that the debt is zero.
#
# And it never prints a bare "OK". Every run ends with the posture line and
# the issues tracking open real findings, so a green check reads as "nothing
# new, and here is what we still owe" rather than "the code is clean". The
# reverted attempt printed "OK: no gosec findings outside the baseline", which
# is precisely the sentence that let 148 unread findings look settled.
#
# Usage:
#   scripts/sast-register.sh --gate      # CI gate (staticcheck + gosec)
#   scripts/sast-register.sh --refresh   # rescan, preserve verdicts, add new
#                                        # rows as unreviewed, drop resolved
#   scripts/sast-register.sh --report    # posture summary (counts by verdict)
#   scripts/sast-register.sh --install   # install the pinned tools
#
# Requires: go, python3, gosec, staticcheck. Run --install for the tools; they
# land in "$(go env GOPATH)/bin", which must be on PATH.

set -euo pipefail
cd "$(dirname "$0")/.."

# Exact pin, never @latest — a new gosec release can change rule behaviour or
# drag in a newer toolchain requirement, either of which moves the register
# under us. Bumping this is a deliberate act with a register diff to review.
GOSEC_VERSION=v2.28.0
# Matches the version quality-sweep.yml preinstalls, so the advisory sweep and
# this gate can never disagree about what staticcheck considers a finding.
STATICCHECK_VERSION=2025.1.1

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
REGISTER=.github/sast-register.tsv

# Before the module derivation: --install is the bootstrap path that PUTS gosec
# and staticcheck on PATH, so it must not depend on anything but the go command.
if [ "${1:-}" = "--install" ]; then
  go install "github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION}"
  go install "honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION}"
  exit 0
fi

modules_list="$(scripts/workspace-modules.sh)"
# shellcheck disable=SC2206  # deliberate word splitting; module dirs have no spaces
MODULES=($modules_list)

MODE="${1:---report}"

need=(gosec python3)
[ "$MODE" = "--gate" ] && need+=(staticcheck)
for tool in "${need[@]}"; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "::error::$tool not found on PATH. Run 'scripts/sast-register.sh --install'" \
         "and put \"\$(go env GOPATH)/bin\" on your PATH; python3 ships with macOS and ubuntu-latest."
    exit 1
  }
done

# staticcheck first: it is the cheap clean gate, and a failure here is always
# unambiguous, so there is no reason to make someone read the gosec posture
# before finding out about it.
if [ "$MODE" = "--gate" ]; then
  sc_out="$(mktemp)"
  trap 'rm -f "$sc_out"' EXIT
  for m in "${MODULES[@]}"; do
    (cd "$m" && staticcheck ./...) >>"$sc_out" 2>&1 || true
  done
  if [ -s "$sc_out" ]; then
    echo "::error::staticcheck findings — this gate is clean, there is no baseline:"
    cat "$sc_out"
    exit 1
  fi
  echo "staticcheck: clean across ${MODULES[*]}"
fi

scan="$(mktemp)"
trap 'rm -f "${sc_out:-}" "$scan"' EXIT
echo "gosec: scanning ${#MODULES[@]} workspace module(s) from go.work — ${MODULES[*]}"
for m in "${MODULES[@]}"; do
  # -no-fail: a non-zero exit just means findings exist, which is the normal
  # case here. The register, not the exit code, is the signal.
  (cd "$m" && gosec -fmt=json -quiet -no-fail ./... 2>/dev/null) >>"$scan" || true
done

MODE="$MODE" REGISTER="$REGISTER" REPO_ROOT="$PWD" python3 - "$scan" <<'PY'
import hashlib, json, os, re, sys
from collections import Counter

mode, reg_path = os.environ["MODE"], os.environ["REGISTER"]
root = os.environ["REPO_ROOT"].rstrip("/") + "/"
COLS = ["fingerprint", "rule", "severity", "path", "line", "verdict", "issue", "reasoning"]
VERDICTS = {"real", "false-positive", "deliberate", "blocked", "unreviewed"}
LINE_PREFIX = re.compile(r"^\s*\d+:\s?")

# gosec emits one JSON document per module and nothing at all for a clean one,
# so this reads a concatenated stream rather than a single object.
raw = open(sys.argv[1], encoding="utf-8").read()
issues, dec, i = [], json.JSONDecoder(), 0
while i < len(raw):
    while i < len(raw) and raw[i].isspace():
        i += 1
    if i >= len(raw):
        break
    doc, i = dec.raw_decode(raw, i)
    issues.extend(doc.get("Issues") or [])

found = {}
for it in issues:
    p = it["file"]
    rel = p[len(root):] if p.startswith(root) else p
    code = "\n".join(LINE_PREFIX.sub("", l).strip() for l in it.get("code", "").splitlines())
    fp = hashlib.sha256("\x00".join((it["rule_id"], rel, code)).encode()).hexdigest()[:16]
    # Identical findings in one file collapse to one fingerprint; keep the
    # first line seen so the row points somewhere real.
    found.setdefault(fp, dict(fingerprint=fp, rule=it["rule_id"], severity=it["severity"],
                              path=rel, line=str(it["line"])))

existing = {}
if os.path.exists(reg_path):
    with open(reg_path, encoding="utf-8") as fh:
        for ln in fh:
            if ln.startswith("#") or not ln.strip():
                continue
            parts = ln.rstrip("\n").split("\t")
            if parts[0] == "fingerprint":
                continue
            row = dict(zip(COLS, parts + [""] * (len(COLS) - len(parts))))
            existing[row["fingerprint"]] = row

bad = {r["fingerprint"]: r["verdict"] for r in existing.values() if r["verdict"] not in VERDICTS}
if bad:
    print(f"::error::unknown verdict(s) in {reg_path}: {bad}", file=sys.stderr)
    sys.exit(2)

merged = []
for fp, f in found.items():
    prev = existing.get(fp)
    merged.append({**f,
                   "verdict": prev["verdict"] if prev else "unreviewed",
                   "issue": prev["issue"] if prev else "",
                   "reasoning": prev["reasoning"] if prev else ""})
merged.sort(key=lambda r: (r["path"], r["rule"], r["fingerprint"]))
resolved = [fp for fp in existing if fp not in found]

if mode == "--refresh":
    with open(reg_path, "w", encoding="utf-8") as fh:
        fh.write(
            "# .github/sast-register.tsv — the reviewed record of every gosec finding.\n"
            "# Regenerate with: scripts/sast-register.sh --refresh\n"
            "# Policy, verdict vocabulary and fingerprint scheme: scripts/sast-register.sh\n"
            "#\n"
            "# verdict: real | false-positive | deliberate | blocked | unreviewed\n"
            "# 'line' is navigation only and is refreshed each run; it is NOT part of\n"
            "# the fingerprint, so edits above a finding do not churn this file.\n"
            "# Editing the flagged line DOES change the fingerprint and resets the row\n"
            "# to unreviewed, because the code the verdict described has changed.\n")
        fh.write("\t".join(COLS) + "\n")
        for r in merged:
            fh.write("\t".join(r[c].replace("\t", " ") for c in COLS) + "\n")
    print(f"wrote {reg_path}: {len(merged)} findings"
          f"{f', {len(resolved)} resolved row(s) dropped' if resolved else ''}")

counts = Counter(r["verdict"] for r in merged)
unreviewed = [r for r in merged if r["verdict"] == "unreviewed"]

# The posture line, always. Never a bare "OK" — a green check has to say what
# is still owed, or it reads as "the code is clean".
print(f"{len(merged)} findings · " + " · ".join(f"{v} {counts[v]}" for v in sorted(counts)))
tracked = sorted({r["issue"] for r in merged
                  if r["verdict"] in ("real", "blocked") and r["issue"]})
if tracked:
    print("open, tracked: " + ", ".join(tracked))
if resolved and mode != "--refresh":
    print(f"{len(resolved)} register row(s) no longer detected — "
          f"prune with: scripts/sast-register.sh --refresh")

if mode != "--gate":
    for r in unreviewed:
        print(f"  UNREVIEWED {r['fingerprint']}  {r['rule']}  {r['severity']:<6} "
              f"{r['path']}:{r['line']}")
    sys.exit(0)

# ── gate ────────────────────────────────────────────────────────────────────
# `new` is computed against the register on disk, so it means "arrived without
# anyone recording a verdict" — which is the same failure as `unreviewed`, just
# caught one step earlier.
new = [r for r in merged if r["fingerprint"] not in existing]
untracked = [r for r in merged
             if r["verdict"] in ("real", "blocked") and not r["issue"]]

fail = False
if new:
    fail = True
    print(f"\n::error::{len(new)} gosec finding(s) not in {reg_path}:")
    for r in new:
        print(f"  {r['fingerprint']}  {r['rule']}  {r['severity']:<6} {r['path']}:{r['line']}")
    print("Fix it, or record a verdict: run `scripts/sast-register.sh --refresh`,")
    print("then set verdict + reasoning on the new row(s). A verdict of")
    print("'real' or 'blocked' must cite an issue. Do NOT record a verdict you")
    print("have not derived — that is exactly how the reverted baseline shipped")
    print("148 findings nobody had read.")

# Reachable when someone refreshes the register and commits it without filling
# in the verdicts — the register's own failure mode, so the gate names it.
if unreviewed:
    fail = True
    print(f"\n::error::{len(unreviewed)} row(s) in {reg_path} are still 'unreviewed':")
    for r in unreviewed:
        print(f"  {r['fingerprint']}  {r['rule']}  {r['severity']:<6} {r['path']}:{r['line']}")
    print("Every finding carries a recorded verdict and its reasoning. Triage")
    print("these before merging; 'unreviewed' is a state to report, not to rest in.")

if untracked:
    fail = True
    print(f"\n::error::{len(untracked)} row(s) are 'real' or 'blocked' with no issue cited:")
    for r in untracked:
        print(f"  {r['fingerprint']}  {r['rule']}  {r['verdict']:<8} {r['path']}:{r['line']}")
    print("A real defect with no issue gets forgotten, and a blocked row with no")
    print("deciding issue can never be revisited when the fix becomes available.")

sys.exit(1 if fail else 0)
PY
