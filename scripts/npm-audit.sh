#!/usr/bin/env bash
#
# npm-audit.sh — known-vulnerability scan of the UI's npm dependency tree,
# gated against a register of reviewed exceptions.
#
# This closes the last hole in the supply-chain surface. Until now the three
# static gates covered our Go dependencies and our own source, and nothing at
# all read ui/package-lock.json:
#
#   vuln-scan.yml  govulncheck — are our GO dependencies known-vulnerable?
#   sast.yml       gosec + staticcheck — did we write an insecure PATTERN?
#   codeql.yml     CodeQL — does a value FLOW somewhere it shouldn't?
#   npm-audit.yml  this — are our NPM dependencies known-vulnerable?
#
# CodeQL does analyse ui/ source, but it excludes node_modules by design, so
# roughly 450 packages of transitive dependency shipped into every appliance
# image without one advisory lookup. The comment at codeql.yml:15 has been naming
# "CP-7's npm audit" as an existing companion gate; this is that gate.
#
# What it gates on
# ----------------
# HIGH and CRITICAL advisories fail the build. MODERATE, LOW and INFO are
# reported on every run but do not block.
#
# That split is not a comfort threshold, it is the same line codeql.yml draws
# ("medium and low findings still require a recorded verdict, but do not
# block") and it is chosen so the blocking set stays small enough that the
# response to a red gate is always "fix it", never "loosen it". If a moderate
# advisory matters here, the fix is to upgrade the package — not to argue the
# threshold down, and never to argue it up.
#
# The register, and why it is not vuln-scan.sh's flat baseline
# -----------------------------------------------------------
# scripts/vuln-scan.sh gates govulncheck against .github/vuln-baseline.txt: a
# bare list of GO-* IDs, with the reasoning living in file-level comments. That
# shape is defensible there and was deliberately NOT copied here, because this
# repo has already paid for the difference. scripts/sast-register.sh's header
# records it: PR #139 shipped a gate whose baseline held 148 findings nobody
# had read and then printed "OK", and it was reverted in #140.
#
# The lesson that survived is that an accepted finding must carry its own
# reason, attached to the row rather than floating in a comment that drifts out
# of correspondence with the list below it. So .github/npm-audit-register.tsv
# is a TSV with a mandatory `reason` and a mandatory `issue` per exception.
#
# The vuln-scan rationale for having ANY escape hatch still holds, and it is
# the dependency-specific one sast-register.sh names: for code we wrote a fix
# is always available, but for a DEPENDENCY it may genuinely not be shippable
# yet — no upstream release, a fix only in a major version that needs
# validation, a transitive pin we do not control. The register records that
# debt explicitly instead of letting the gate rot red.
#
# There is deliberately NO --refresh mode, unlike sast-register.sh. There, a
# refresh is how you enumerate findings in code you must then triage. Here the
# default response to an advisory is to UPGRADE THE PACKAGE, and a one-command
# way to mass-generate exception rows is exactly how a dependency gate decays
# into a list nobody reads. Exceptions are added by hand, one at a time, by
# someone who has read the advisory and can write down why it is being
# accepted. `--print` will show you the rows to paste; it will not write them.
#
# The gate fails on:
#
#   * any high/critical advisory not in the register — something new arrived
#     and nobody has looked at it;
#   * any register row with no reason, or no issue cited — an accepted
#     vulnerability with no written justification is indistinguishable from
#     one that was silently baselined, and one with no issue can never be
#     revisited when the fix becomes available;
#   * the audit failing to RUN. A registry outage must not read as "clean".
#     npm can exit zero having printed an error object, so a parse of the
#     report's shape is the check, not the exit status.
#
# Stale rows — an advisory in the register that the audit no longer reports —
# are printed but do not fail, matching both sibling gates. The file is meant
# to shrink.
#
# Runtime vs dev
# --------------
# Every advisory is labelled `runtime` or `dev` by re-running the audit with
# --omit=dev and checking which side it lands on. Both are gated identically:
# a dev-only advisory is still a build-machine compromise vector, and this
# repo's build machines sign release artifacts. The label exists to tell a
# reviewer how urgent a red gate is, not to excuse one.
#
# Usage:
#   scripts/npm-audit.sh --gate     # CI gate
#   scripts/npm-audit.sh --report   # posture summary (default)
#   scripts/npm-audit.sh --print    # every advisory, as pasteable register rows
#
# Requires: node/npm (Node 22, matching ci.yml), python3. No `npm ci` — the
# audit runs --package-lock-only and reads ui/package-lock.json directly, so it
# needs no node_modules and installs nothing.

set -euo pipefail
cd "$(dirname "$0")/.."

UI_DIR=ui
REGISTER=.github/npm-audit-register.tsv

command -v npm >/dev/null 2>&1 || {
  echo "::error::npm not found on PATH (Node 22 — see ci.yml's frontend job)."
  exit 1
}
command -v python3 >/dev/null 2>&1 || {
  echo "::error::python3 not found on PATH (ships with macOS and ubuntu-latest)."
  exit 1
}

MODE="${1:---report}"
case "$MODE" in
  --gate|--report|--print) ;;
  *) echo "::error::unknown mode '$MODE' (want --gate, --report or --print)"; exit 2 ;;
esac

full="$(mktemp)"
prod="$(mktemp)"
trap 'rm -f "$full" "$prod"' EXIT

# `|| true` on both: npm audit exits non-zero merely because advisories exist,
# which is the case this script is written to interpret. A genuine failure —
# registry unreachable, malformed lockfile — is caught by the shape check in
# the Python below, because npm can and does exit zero after printing an error
# object, and a gate that reads that as "no vulnerabilities" is worse than no
# gate at all.
(cd "$UI_DIR" && npm audit --package-lock-only --json) >"$full" 2>/dev/null || true
(cd "$UI_DIR" && npm audit --package-lock-only --omit=dev --json) >"$prod" 2>/dev/null || true

MODE="$MODE" REGISTER="$REGISTER" python3 - "$full" "$prod" <<'PY'
import json, os, re, sys
from collections import Counter

mode, reg_path = os.environ["MODE"], os.environ["REGISTER"]
COLS = ["advisory", "package", "severity", "scope", "reason", "issue"]
BLOCKING = {"high", "critical"}
SEV_ORDER = {"critical": 0, "high": 1, "moderate": 2, "low": 3, "info": 4}
GHSA = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.I)


def load(path, what):
    """Parse an npm audit report, failing loudly if it is not one.

    npm prints a JSON error object (and sometimes exits zero) when the
    registry is unreachable. Requiring the report's actual shape is what
    stops an outage from being reported as a clean tree.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"::error::the {what} npm audit did not produce a JSON report "
              f"({exc}). The audit did not run — this is NOT a clean result.",
              file=sys.stderr)
        sys.exit(2)
    if not isinstance(doc, dict) or "vulnerabilities" not in doc \
            or "vulnerabilities" not in (doc.get("metadata") or {}):
        # npm puts the readable text in a top-level `message` and leaves
        # `error` as a pair of empty strings, so prefer the former or the
        # failure is undiagnosable from the CI log.
        err = doc.get("message") if isinstance(doc, dict) else None
        if not err and isinstance(doc, dict):
            e = doc.get("error")
            err = json.dumps(e) if e else None
        print(f"::error::the {what} npm audit returned no advisory report: "
              f"{err or 'no error detail'}. The audit did not run — this is "
              f"NOT a clean result.", file=sys.stderr)
        sys.exit(2)
    return doc


def advisories(doc):
    """Flatten the report into {advisory_id: {...}}.

    `vulnerabilities` is keyed by affected package; the actual advisories are
    the object entries in each package's `via` (string entries are just
    transitive links back to another package in the same map).
    """
    out = {}
    for pkg, entry in (doc.get("vulnerabilities") or {}).items():
        fix = entry.get("fixAvailable")
        for via in entry.get("via") or []:
            if not isinstance(via, dict):
                continue
            url = via.get("url") or ""
            m = GHSA.search(url)
            ident = m.group(0).upper() if m else f"npm-{via.get('source', 'unknown')}"
            rec = out.setdefault(ident, {
                "advisory": ident,
                "package": via.get("name") or via.get("dependency") or pkg,
                "severity": (via.get("severity") or "unknown").lower(),
                "title": via.get("title") or "",
                "url": url,
                "range": via.get("range") or "",
                "fix": False,
            })
            # fixAvailable lives on the containing package entry, so an
            # advisory reachable through several packages is fixable if any
            # route to it is.
            rec["fix"] = rec["fix"] or bool(fix)
    return out


full_doc = load(sys.argv[1], "full")
full = advisories(full_doc)
prod = advisories(load(sys.argv[2], "production-only"))
for ident, rec in full.items():
    rec["scope"] = "runtime" if ident in prod else "dev"

# ── the register ────────────────────────────────────────────────────────────
existing, dupes = {}, []
if os.path.exists(reg_path):
    with open(reg_path, encoding="utf-8") as fh:
        for lineno, ln in enumerate(fh, 1):
            if ln.startswith("#") or not ln.strip():
                continue
            parts = ln.rstrip("\n").split("\t")
            if parts[0] == "advisory":
                continue
            row = dict(zip(COLS, parts + [""] * (len(COLS) - len(parts))))
            row["_line"] = lineno
            key = row["advisory"].strip().upper()
            if key in existing:
                dupes.append(key)
            existing[key] = row

detected = sorted(full.values(), key=lambda r: (SEV_ORDER.get(r["severity"], 9), r["package"]))
counts = Counter(r["severity"] for r in detected)
blocking = [r for r in detected if r["severity"] in BLOCKING]
stale = [k for k in existing if k not in full]

# ── report ──────────────────────────────────────────────────────────────────
# Never a bare "OK". A green check has to say what was scanned and what is
# still owed, or it reads as a clean bill of health it has not earned.
deps = (full_doc.get("metadata") or {}).get("dependencies") or {}
n_pkgs, n_prod, n_dev = deps.get("total", "?"), deps.get("prod", "?"), deps.get("dev", "?")
summary = " · ".join(f"{s} {counts[s]}" for s in sorted(counts, key=lambda s: SEV_ORDER.get(s, 9))) or "none"
print(f"npm audit · ui/package-lock.json · {n_pkgs} packages ({n_prod} prod, {n_dev} dev) · "
      f"{len(detected)} advisories · {summary}")
print(f"register: {len(existing)} accepted exception(s) in {reg_path}")

if mode == "--print":
    # Blocking severities only. A moderate or low row in the register would
    # suppress nothing — the register says as much — so offering one here as a
    # ready-to-paste line would be inviting a meaningless exception. Use
    # --report to see everything.
    for r in blocking:
        print("\t".join([r["advisory"], r["package"], r["severity"], r["scope"],
                         f"TODO: why is no fix shippable? ({r['title']})",
                         "TODO: issue"]))
    if not blocking:
        print("(no high/critical advisories — nothing that a register row could suppress)")
    sys.exit(0)

for r in detected:
    mark = "BLOCKS" if r["severity"] in BLOCKING else "      "
    known = " [registered]" if r["advisory"] in existing else ""
    fix = "fix available" if r["fix"] else "NO FIX AVAILABLE"
    print(f"  {mark} {r['severity']:<8} {r['scope']:<7} {r['package']} {r['range']}"
          f" — {r['title']} ({fix}){known}")
    if r["url"]:
        print(f"           {r['url']}")

if stale:
    print(f"\n{len(stale)} register row(s) no longer detected — remove them from {reg_path}:")
    for k in stale:
        print(f"  {k}  {existing[k]['package']}")

if mode != "--gate":
    sys.exit(0)

# ── gate ────────────────────────────────────────────────────────────────────
fail = False

if dupes:
    fail = True
    print(f"\n::error::duplicate advisory id(s) in {reg_path}: {sorted(set(dupes))}")
    print("One row per advisory — a duplicate means one of the two reasons is")
    print("being silently ignored.")

unregistered = [r for r in blocking if r["advisory"] not in existing]
if unregistered:
    fail = True
    print(f"\n::error::{len(unregistered)} high/critical npm advisory(ies) not in {reg_path}:")
    for r in unregistered:
        print(f"  {r['advisory']}  {r['severity']:<8} {r['scope']:<7} {r['package']} {r['range']}")
        print(f"    {r['title']}")
        print(f"    {r['url']}")
    print("Upgrade the package — that is the fix, and for a dependency it is")
    print("almost always available. Only if no fix is shippable yet, add a row")
    print(f"to {reg_path} with a written reason and a tracking issue. Do NOT")
    print("lower the severity threshold; that is not an exception, it is a")
    print("blindfold.")

# An exception is only worth more than a silent baseline if it carries the
# reasoning. These two checks are the whole difference.
no_reason = [r for r in existing.values() if not r["reason"].strip()]
if no_reason:
    fail = True
    print(f"\n::error::{len(no_reason)} register row(s) have no reason:")
    for r in no_reason:
        print(f"  {r['advisory']} ({reg_path}:{r['_line']})")
    print("Every accepted advisory says why it is accepted — specifically")
    print("enough that the next reader need not re-derive it. An unexplained")
    print("row is the unread baseline this register exists to prevent.")

no_issue = [r for r in existing.values() if not r["issue"].strip()]
if no_issue:
    fail = True
    print(f"\n::error::{len(no_issue)} register row(s) cite no tracking issue:")
    for r in no_issue:
        print(f"  {r['advisory']} ({reg_path}:{r['_line']})")
    print("An accepted vulnerability with no issue can never be revisited when")
    print("the fix ships, which is the entire point of accepting it temporarily.")

if not fail:
    accepted = f", {len(existing)} accepted exception(s) tracked" if existing else ""
    print(f"\nPASS: no unregistered high/critical npm advisories{accepted}.")
    if counts.get("moderate") or counts.get("low") or counts.get("info"):
        print("Note: moderate/low advisories above are reported, not gated. They")
        print("are still worth an upgrade.")

sys.exit(1 if fail else 0)
PY
