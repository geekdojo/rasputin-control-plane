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
# Usage:
#   scripts/sast-register.sh --refresh   # rescan, preserve verdicts, add new
#                                        # rows as unreviewed, drop resolved
#   scripts/sast-register.sh --report    # posture summary (counts by verdict)
#   scripts/sast-register.sh --install   # install the pinned gosec
#
# Requires: go, python3, gosec. Run --install for the last; it lands in
# "$(go env GOPATH)/bin", which must be on PATH.

set -euo pipefail
cd "$(dirname "$0")/.."

# Exact pin, never @latest — a new gosec release can change rule behaviour or
# drag in a newer toolchain requirement, either of which moves the register
# under us. Bumping this is a deliberate act with a register diff to review.
GOSEC_VERSION=v2.28.0

MODULES=(api agent proto)
REGISTER=.github/sast-register.tsv

if [ "${1:-}" = "--install" ]; then
  go install "github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION}"
  exit 0
fi

for tool in gosec python3; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "::error::$tool not found on PATH. For gosec run 'scripts/sast-register.sh --install'" \
         "and put \"\$(go env GOPATH)/bin\" on your PATH; python3 ships with macOS and ubuntu-latest."
    exit 1
  }
done

scan="$(mktemp)"
trap 'rm -f "$scan"' EXIT
for m in "${MODULES[@]}"; do
  # -no-fail: a non-zero exit just means findings exist, which is the normal
  # case here. The register, not the exit code, is the signal.
  (cd "$m" && gosec -fmt=json -quiet -no-fail ./... 2>/dev/null) >>"$scan" || true
done

MODE="${1:---report}" REGISTER="$REGISTER" REPO_ROOT="$PWD" python3 - "$scan" <<'PY'
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
unreviewed = counts["unreviewed"]
print(f"{len(merged)} findings · " + " · ".join(f"{v} {counts[v]}" for v in sorted(counts)))
if unreviewed:
    print(f"\n{unreviewed} UNREVIEWED — posture unknown for these. "
          f"Triage: geekdojo/geekdojo-brain#141")
    for r in merged:
        if r["verdict"] == "unreviewed":
            print(f"  {r['fingerprint']}  {r['rule']}  {r['severity']:<6} {r['path']}:{r['line']}")
PY
