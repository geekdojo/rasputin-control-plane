#!/usr/bin/env bash
#
# codeql-register.sh — maintain .github/codeql-register.tsv, the reviewed record
# of every CodeQL finding in this repo, and gate CI on it.
#
# The companion to scripts/sast-register.sh, and deliberately its sibling in
# shape: same eight columns, same verdict-per-finding discipline, same refusal
# to print a bare "OK". Read that script's header first — the reasoning for why
# a register exists at all lives there and is not repeated here.
#
# What is DIFFERENT here, and why
# -------------------------------
# 1. This script does not run the scanner. CodeQL analysis is done by
#    github/codeql-action (or the CodeQL CLI locally); this consumes the SARIF
#    it writes. So every mode takes a SARIF directory.
#
# 2. The gate is STRICTER, because it sits at a different boundary. The gosec
#    gate asks "is anything new or unseen" and tolerates known `real` findings,
#    on the reasoning that blocking every merge until the debt is zero is what
#    drove its first attempt to launder findings. This gate additionally asks
#    "is this fit to ship": no HIGH or CRITICAL finding that is real — or that
#    nobody has looked at — may exist on a release. That is a deliberate
#    tightening, decided 2026-08-16, and it is why this gate also runs in
#    release.yml and not only on pull requests.
#
# 3. There is no `blocked` verdict. It exists in the gosec register because a
#    fix can be unavailable — but that is DEPENDENCY reasoning, where you wait
#    for someone else to publish. CodeQL analyses code we wrote, and in our own
#    tree a fix is always available; "waiting on a decision" is not a blocked
#    fix, it is an unmade decision, and at HIGH or CRITICAL the point of this
#    gate is to force it rather than park it. A finding whose fix needs a
#    decision is `real`, cites the deciding issue, and stops the release.
#
# 4. Copied third-party code in our tree is OUR code (hard rule, 2026-08-16)
#    and is analysed like anything else. Vendor PACKAGES resolved from a
#    manifest or the module cache are a different lane entirely — govulncheck,
#    trivy/osv-scanner and Dependabot own those. If CodeQL ever starts
#    reporting on them, it is misconfigured, not thorough.
#
# Verdicts
# --------
#   real           a genuine defect. Gets its own issue; the row cites it.
#                  At HIGH/CRITICAL this FAILS the gate — it must be fixed,
#                  not tracked.
#   false-positive the query fired but the code is correct. The reasoning must
#                  say WHY, specifically enough that the next reader need not
#                  re-derive it.
#   deliberate     the pattern is real and intended, and is safe because of a
#                  stated mitigating control. The control must be NAMED.
#   unreviewed     nobody has looked yet. Never a resting state, and always
#                  fails the gate regardless of severity.
#
# Accepted findings are also annotated AT THE SITE in the source, saying why the
# code is secure (Bryce, 2026-08-16). The register is what the gate reads; the
# comment is what the next person reading that function sees. Neither replaces
# the other, and the fingerprint below is why both can be trusted.
#
# Fingerprints
# ------------
# sha256(rule id, repo-relative path, CodeQL's primaryLocationLineHash),
# truncated to 16 hex.
#
# primaryLocationLineHash is CodeQL's own content hash of the flagged line, and
# using it rather than a hand-rolled one is deliberate: it is what GitHub itself
# matches alerts on, so this register and the Security tab cannot develop
# different opinions about whether two findings are the same finding.
#
# Its property is exactly the one a register needs. Moving a finding down the
# file does NOT change it, so the register does not churn on every edit above a
# finding — a register that churns is one nobody updates. Editing the flagged
# line ITSELF does change it, which resets the row to unreviewed, because the
# code the verdict described has changed.
#
# That trip-wire is load-bearing here in a way it is not for gosec, because
# several verdicts in this repo rest on an ADJACENT line rather than the flagged
# one — go/disabled-certificate-check at turingpi.go is safe only because
# VerifyPeerCertificate is assigned on the following line. The fingerprint will
# not catch that line being deleted. Where a verdict depends on something the
# fingerprint cannot see, the reasoning MUST carry an explicit TRIP-WIRE note
# naming the condition, exactly as the gosec register does for the BMC
# ClientSessionCache case.
#
# The `line` column is for human navigation only, is refreshed on every run, and
# is not part of the identity.
#
# Usage:
#   scripts/codeql-register.sh --gate    <sarif-dir>   # CI gate
#   scripts/codeql-register.sh --refresh <sarif-dir>   # rescan, keep verdicts
#   scripts/codeql-register.sh --report               # posture summary
#
# Requires: python3 only. Producing the SARIF requires the CodeQL CLI locally,
# or just read it off a CI run: gh run download <id> -n sarif-<language>.

set -euo pipefail
cd "$(dirname "$0")/.."

REGISTER=.github/codeql-register.tsv

MODE="${1:---report}"
SARIF_DIR="${2:-}"

case "$MODE" in
  --gate|--refresh)
    if [ -z "$SARIF_DIR" ]; then
      echo "::error::$MODE needs a SARIF directory: $0 $MODE <sarif-dir>"
      exit 1
    fi
    if [ ! -d "$SARIF_DIR" ]; then
      echo "::error::$SARIF_DIR is not a directory. CodeQL wrote no SARIF, which" \
           "means the analysis did not run — that is a broken gate, not a clean one."
      exit 1
    fi
    ;;
  --report) ;;
  *)
    echo "::error::unknown mode '$MODE'. Use --gate, --refresh or --report."
    exit 1
    ;;
esac

command -v python3 >/dev/null 2>&1 || {
  echo "::error::python3 not found on PATH; it ships with macOS and ubuntu-latest."
  exit 1
}

MODE="$MODE" REGISTER="$REGISTER" python3 - "$SARIF_DIR" <<'PY'
import collections
import glob
import hashlib
import json
import os
import sys

MODE = os.environ["MODE"]
REGISTER = os.environ["REGISTER"]
SARIF_DIR = sys.argv[1] if len(sys.argv) > 1 else ""

COLUMNS = ["fingerprint", "rule", "severity", "path", "line",
           "verdict", "issue", "reasoning"]
VERDICTS = {"real", "false-positive", "deliberate", "unreviewed"}
# The bands that decide whether a finding can ship. Mirrors GitHub's own
# mapping of security-severity, so this register and the Security tab agree
# about what "high" means.
BLOCKING = {"critical", "high"}

HEADER = """\
# .github/codeql-register.tsv — the reviewed record of every CodeQL finding.
# Regenerate with: scripts/codeql-register.sh --refresh <sarif-dir>
# Policy, verdict vocabulary and fingerprint scheme: scripts/codeql-register.sh
#
# verdict: real | false-positive | deliberate | unreviewed
#
# A critical/high finding that is `real` or `unreviewed` FAILS the gate and
# blocks the release — such code is never built into an image. Medium and low
# are reported and must still carry a verdict, but do not block.
#
# There is deliberately no `blocked` verdict: this is code we wrote, so a fix
# is always available, and an undecided fix is an unmade decision rather than
# an unavailable one.
#
# Accepted findings are ALSO annotated at the site in the source. Where a
# verdict depends on a condition the fingerprint cannot see — an adjacent line,
# a caller, a config value — the reasoning must carry an explicit TRIP-WIRE
# note naming it.
#
# 'line' is navigation only and is refreshed each run; it is NOT part of the
# identity. The fingerprint is sha256(rule, path, CodeQL's line-content hash),
# so a finding that MOVES keeps its verdict and a finding whose flagged line is
# EDITED resets to unreviewed.
"""


def severity_band(score):
    if score is None:
        return "none"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def fingerprint(rule, path, line_hash):
    raw = "\x00".join([rule, path, line_hash])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def load_sarif(directory):
    """Every finding in every .sarif under `directory`, keyed by fingerprint."""
    files = sorted(glob.glob(os.path.join(directory, "**", "*.sarif"),
                             recursive=True))
    if not files:
        print(f"::error::no .sarif files under {directory} — CodeQL produced "
              f"nothing. An empty analysis is a broken gate, not a clean repo.")
        sys.exit(1)

    findings = {}
    for path in files:
        with open(path, encoding="utf-8") as handle:
            sarif = json.load(handle)
        for run in sarif.get("runs", []):
            rules = {}
            tool = run.get("tool", {})
            for component in [tool.get("driver", {})] + list(
                    tool.get("extensions", []) or []):
                for rule in component.get("rules", []) or []:
                    rid = rule.get("id")
                    if not rid:
                        continue
                    raw = (rule.get("properties", {}) or {}).get(
                        "security-severity")
                    try:
                        rules[rid] = float(raw) if raw is not None else None
                    except (TypeError, ValueError):
                        rules[rid] = None

            for result in run.get("results", []):
                rid = result.get("ruleId", "<unknown>")
                locations = result.get("locations") or []
                if not locations:
                    continue
                physical = locations[0].get("physicalLocation", {})
                uri = physical.get("artifactLocation", {}).get("uri", "?")
                line = physical.get("region", {}).get("startLine", 0)

                # CodeQL's own content hash of the flagged line. Absent only if
                # the analysis was produced by something that is not CodeQL, in
                # which case fall back to the line number so the register still
                # functions — noisily, since it will then churn on every edit.
                line_hash = (result.get("partialFingerprints", {}) or {}).get(
                    "primaryLocationLineHash")
                if not line_hash:
                    line_hash = f"noline:{line}"

                fpr = fingerprint(rid, uri, line_hash)
                findings[fpr] = {
                    "fingerprint": fpr,
                    "rule": rid,
                    "severity": severity_band(rules.get(rid)),
                    "path": uri,
                    "line": str(line),
                }
    return findings


def read_register():
    rows = {}
    if not os.path.exists(REGISTER):
        return rows
    with open(REGISTER, encoding="utf-8") as handle:
        for raw in handle:
            if raw.startswith("#") or not raw.strip():
                continue
            parts = raw.rstrip("\n").split("\t")
            if parts[0] == "fingerprint":
                continue
            parts += [""] * (len(COLUMNS) - len(parts))
            row = dict(zip(COLUMNS, parts[:len(COLUMNS)]))
            rows[row["fingerprint"]] = row
    return rows


def write_register(rows):
    ordered = sorted(rows.values(), key=lambda r: (r["path"],
                                                   int(r["line"] or 0),
                                                   r["rule"]))
    with open(REGISTER, "w", encoding="utf-8") as handle:
        handle.write(HEADER)
        handle.write("\t".join(COLUMNS) + "\n")
        for row in ordered:
            handle.write("\t".join(row.get(col, "") for col in COLUMNS) + "\n")


def posture(rows):
    counts = collections.Counter(r["verdict"] for r in rows.values())
    summary = " · ".join(f"{k} {counts[k]}" for k in sorted(counts))
    return f"{len(rows)} findings · {summary}" if rows else "0 findings"


def open_issues(rows):
    issues = sorted({r["issue"] for r in rows.values()
                     if r["verdict"] == "real" and r["issue"]})
    return issues


def main():
    if MODE == "--report":
        rows = read_register()
        print(posture(rows))
        for issue in open_issues(rows):
            print(f"  open, tracked: {issue}")
        return 0

    found = load_sarif(SARIF_DIR)
    rows = read_register()

    if MODE == "--refresh":
        merged = {}
        for fpr, finding in found.items():
            existing = rows.get(fpr)
            row = dict(finding)
            if existing:
                # Verdict and reasoning survive; severity/line are refreshed
                # from the scan, since a rule's severity can move under us.
                row["verdict"] = existing.get("verdict") or "unreviewed"
                row["issue"] = existing.get("issue", "")
                row["reasoning"] = existing.get("reasoning", "")
            else:
                row["verdict"] = "unreviewed"
                row["issue"] = ""
                row["reasoning"] = ""
            merged[fpr] = row

        added = len(set(found) - set(rows))
        dropped = len(set(rows) - set(found))
        write_register(merged)
        print(f"refreshed {REGISTER}: {len(merged)} findings "
              f"({added} new, {dropped} resolved and removed)")
        print(posture(merged))
        return 0

    # --gate
    failures = []

    unregistered = [f for fpr, f in sorted(found.items()) if fpr not in rows]
    for finding in unregistered:
        failures.append(
            f"NEW, unrecorded {finding['severity'].upper()} finding: "
            f"{finding['rule']} at {finding['path']}:{finding['line']}\n"
            f"    Nobody has recorded a verdict for this. Review it, then run "
            f"scripts/codeql-register.sh --refresh <sarif-dir>.")

    for fpr, finding in sorted(found.items()):
        row = rows.get(fpr)
        if row is None:
            continue
        verdict = row.get("verdict", "unreviewed")
        severity = finding["severity"]
        where = f"{finding['rule']} at {finding['path']}:{finding['line']}"

        if verdict not in VERDICTS:
            failures.append(
                f"unknown verdict '{verdict}' on {where}\n"
                f"    Valid verdicts: {', '.join(sorted(VERDICTS))}.")
            continue

        if verdict == "unreviewed":
            failures.append(
                f"UNREVIEWED {severity.upper()} finding: {where}\n"
                f"    `unreviewed` is a state to report, never one to rest in.")
            continue

        if verdict == "real" and severity in BLOCKING:
            failures.append(
                f"REAL {severity.upper()} finding: {where}\n"
                f"    A real critical/high finding is never built into an "
                f"image. Fix it — this gate has no override at this severity."
                + (f" Tracked: {row['issue']}." if row.get("issue") else
                   "\n    It also cites no issue."))
            continue

        if verdict == "real" and not row.get("issue"):
            failures.append(
                f"REAL {severity} finding citing no issue: {where}\n"
                f"    An untracked defect is one that gets forgotten.")
            continue

        if verdict in ("false-positive", "deliberate") and not \
                row.get("reasoning", "").strip():
            failures.append(
                f"{verdict.upper()} verdict with no reasoning: {where}\n"
                f"    A verdict nobody can re-check is indistinguishable from "
                f"a dismissal.")

    # The posture line prints on success AND failure. A green check that reads
    # as "the code is clean" is precisely how 148 unread gosec findings looked
    # settled, so this gate always says what it actually found.
    print("-" * 68)
    print(f"CodeQL register: {posture(rows)}")
    counts = collections.Counter(f["severity"] for f in found.values())
    print(f"this scan: {len(found)} findings · "
          + " · ".join(f"{k} {counts[k]}" for k in sorted(counts)))
    blocking_real = [f"{f['rule']} at {f['path']}:{f['line']}"
                     for fpr, f in sorted(found.items())
                     if f["severity"] in BLOCKING
                     and rows.get(fpr, {}).get("verdict") == "real"]
    print(f"critical/high that are real: {len(blocking_real)} "
          f"(any is a release stopper)")
    for issue in open_issues(rows):
        print(f"  open, tracked: {issue}")
    print("-" * 68)

    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        print(f"\ncodeql gate FAILED: {len(failures)} problem(s) above.")
        return 1

    print("codeql gate passed: nothing new, nothing unreviewed, and no real "
          "critical/high finding. Known findings are listed above.")
    return 0


sys.exit(main())
PY
