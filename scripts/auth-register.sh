#!/usr/bin/env bash
#
# auth-register.sh — maintain .github/auth-register.tsv, the record of which
# authentication method is canonical for each cell, and of every second method
# that is allowed to exist alongside it.
#
# The rule it enforces
# --------------------
# A "cell" is one use case over one protocol — "browser authenticates to the
# api over HTTPS", "node authenticates to the control plane over NATS". Each
# cell gets exactly ONE canonical method. Differences between humans and
# machines, and between protocols, are expected and are not exceptions: they
# are different cells.
#
# A SECOND method inside one cell is allowed only as a row in this register.
# The register exists because the count of distinct authentication methods in
# this system grew one reasonable-sounding local decision at a time, and no
# single change ever looked like sprawl. Adding a new auth class now requires
# an edit to this file, so the review happens on that edit rather than on a
# diff where the new method is a detail.
#
# What counts as a justification (all four, or the row is not valid):
#
#   1. It names a CONSTRAINT that forces the difference. An account of how the
#      difference came about is not a constraint. A recorded decision by Bryce
#      can hold a difference in place, but it is recorded as `decision`, not as
#      `true-now`, so it can be revisited on its own terms.
#   2. The constraint is true today, evidenced by our code (the `anchor`
#      column) or by a pinned upstream reference (the `cite` column). A premise
#      nobody has checked is recorded `unverified` — a state to report, never
#      to rest in.
#   3. It justifies only the NARROWEST difference it actually forces.
#   4. It names a revisit trigger that is a CHECKABLE FACT. **A date is never a
#      trigger.** The gate rejects a `revisit` value that reads like one.
#
# Things that have been offered here and do not count: "nothing is gained by
# changing it"; a premise that was never true; a premise that has gone stale;
# tooling habit; a control that exists only in the UI; a development
# convenience that is live in production.
#
# Clock bounds are rows too. A credential TTL that decides validity is
# clock-driven state, which principles.md forbids, so each TTL either names the
# fact it is a safety net over, or says that no such fact exists.
#
# Transitional differences — migration ladders, windows where an old and a new
# route are both served — are rows too. Each names the fact that lets it be
# deleted.
#
# Why a separate file from sast-register.tsv
# ------------------------------------------
# Only because these rows are written by HAND. Everything else is deliberately
# the same: the same fingerprint idea, the same "a changed anchor resets the
# row" behaviour, the same refusal to print a bare "OK". A tool produces the
# gosec register's rows; a person produces these, so there is nothing to
# rescan, and `--refresh` recomputes anchors and fingerprints over rows a human
# wrote rather than discovering rows.
#
# Visibility
# ----------
# This file is PUBLIC, like the rest of this repo and its CI logs. It carries
# canonical rows and exception rows. It does NOT carry rows describing a
# fail-open that is unfixed and reachable — those live in private
# geekdojo/geekdojo-brain issues, and a row moves here in the same pull request
# that fixes the thing it describes. The gate cannot check that split; it is a
# review rule, stated here so the next person writing a row knows it.
#
# Anchoring
# ---------
# Line numbers churn on every edit above a row and a register that churns is
# one nobody updates, so identity does not use them. The `line` column is
# navigation only and is rewritten on every --refresh.
#
# A row's anchor is one of:
#
#   go:<path>#<Symbol>        a Go declaration — func, method (Type.Method),
#                             type, or a const/var name, including inside a
#                             grouped const(...) / var(...) block. The anchored
#                             text is that declaration's line.
#   text:<path>#<literal>     a literal string that must appear EXACTLY ONCE in
#                             the file. The anchored text is the literal.
#   none:                     nothing in this repo anchors the row — it is held
#                             by a recorded decision, or by code in another
#                             repo, or by an upstream project. Such a row MUST
#                             carry a `cite`, and the posture line reports how
#                             many rows the gate therefore cannot check.
#
# fingerprint = sha256(id, anchor-path, normalized anchored text)[:16].
#
# So editing the anchored declaration changes the fingerprint and the gate
# fails until someone re-reads the row against the changed code and refreshes
# it. That is the whole point: a register whose rows quietly outlive the code
# they describe is worse than no register, because it reads as review.
#
# The gate
# --------
# --gate is what CI runs. It fails on:
#
#   * an anchor that no longer resolves — the symbol is gone, or the literal is
#     absent, or the literal now matches more than once;
#   * a stored fingerprint that does not match the recomputed one — the code
#     the row described has changed;
#   * a `revisit` value that reads like a date rather than a checkable fact;
#   * `status: unverified` with no `cite` — an unchecked premise recorded with
#     no probe scheduled to settle it;
#   * a missing required field, an unknown `kind` or `status`, a duplicate id;
#   * `status: decision` or `anchor: none:` with no `cite` — a decision nobody
#     can look up cannot be revisited on its own terms;
#   * a canonical row that carries an exception, or an exception row that does
#     not.
#
# It does NOT fail merely because exceptions exist. Exceptions are the point of
# a register; the contract is that every one of them is recorded, justified,
# anchored to code that still looks the way the row says, and revisitable.
#
# And it never prints a bare "OK". Every run ends with the posture line — how
# many cells, how many exceptions, how many rows the gate cannot check — so a
# green check reads as "nothing has drifted, and here is what we carry" rather
# than "there are no exceptions".
#
# Usage:
#   scripts/auth-register.sh --gate      # CI gate
#   scripts/auth-register.sh --refresh   # recompute fingerprints + line numbers
#   scripts/auth-register.sh --report    # posture summary, lists what is owed
#
# Requires: python3 only (ships with macOS and ubuntu-latest). No Go, no
# network — this gate reads the tree and nothing else.

set -euo pipefail
cd "$(dirname "$0")/.."

REGISTER="${AUTH_REGISTER:-.github/auth-register.tsv}"
MODE="${1:---report}"

case "$MODE" in
  --gate|--refresh|--report) ;;
  *) echo "::error::unknown mode '$MODE'; expected --gate, --refresh or --report" >&2; exit 2 ;;
esac

command -v python3 >/dev/null 2>&1 || {
  echo "::error::python3 not found on PATH; it ships with macOS and ubuntu-latest" >&2
  exit 1
}

MODE="$MODE" REGISTER="$REGISTER" python3 - <<'PY'
import hashlib, os, re, sys
from collections import Counter

mode, reg_path = os.environ["MODE"], os.environ["REGISTER"]

COLS = ["fingerprint", "id", "kind", "cell", "method", "exception",
        "constraint", "status", "revisit", "anchor", "cite", "line"]
KINDS = {"canonical", "exception"}
STATUSES = {"true-now", "unverified", "decision"}

# Fields that must be non-empty on every row, whatever its kind. `revisit` is
# required on exception rows only: a canonical method is not a difference being
# held in place, so there is nothing for it to be revisited against.
REQUIRED_ALWAYS = ["id", "kind", "cell", "method", "status", "anchor"]
REQUIRED_EXCEPTION = ["exception", "constraint", "revisit"]

# A date is never a revisit trigger (§2 rule 4). These are the shapes a date
# actually takes in a register someone is writing in a hurry.
#
# The bare-year pattern deliberately refuses to fire when the year is followed
# by `.`, `-` or a word character, because upstream versions read like years in
# this project — "Buildroot 2026.08", "OpenWrt 25.12.5", a CalVer release. A
# version pin is exactly the kind of checkable fact the column is FOR, so a
# detector that rejected it would push people to write worse triggers.
DATEISH = [
    (re.compile(r"\b(19|20)\d{2}-\d{2}-\d{2}\b"), "an ISO date"),
    (re.compile(r"\b(19|20)\d{2}/\d{1,2}/\d{1,2}\b"), "a date"),
    (re.compile(r"\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)"
                r"(uary|ruary|ch|il|e|y|ust|tember|ober|ember)?\b\.?\s*(19|20)?\d{2}\b",
                re.I), "a month and year"),
    (re.compile(r"\bQ[1-4]\b", re.I), "a quarter"),
    (re.compile(r"\b(in|after|within|by|before|from)\s+\d+\s*"
                r"(day|week|month|year|quarter)s?\b", re.I), "an elapsed-time trigger"),
    (re.compile(r"\b(annually|quarterly|monthly|weekly|daily|yearly)\b", re.I),
     "a recurring schedule"),
    (re.compile(r"\b(19|20)\d{2}(?![.\-\w])"), "a bare year"),
]

# ── anchor resolution ───────────────────────────────────────────────────────
# Returns (path_for_fingerprint, anchored_text) or raises ValueError with a
# message the gate prints verbatim. Every failure mode here is a real signal:
# it means the code a row describes is not where the row says it is.

GO_DECL = "func|type|const|var"


def norm(s):
    """Collapse whitespace so reindentation does not churn a fingerprint."""
    return " ".join(s.split())


def strip_line_comment(s):
    """Drop a trailing // comment, but not one inside a string literal.

    Comments beside a declaration are where people leave notes, and a note
    being reworded is not the code changing. Quote tracking is deliberately
    simple — it only has to survive Go declaration lines, which is the only
    thing this function is ever shown.
    """
    out, quote, i = [], None, 0
    while i < len(s):
        c = s[i]
        if quote:
            if c == "\\" and quote != "`":
                out.append(c)
                i += 1
                if i < len(s):
                    out.append(s[i])
                    i += 1
                continue
            if c == quote:
                quote = None
        elif c in "\"'`":
            quote = c
        elif c == "/" and i + 1 < len(s) and s[i + 1] == "/":
            break
        out.append(c)
        i += 1
    return "".join(out)


def resolve_go(path, symbol):
    try:
        src = open(path, encoding="utf-8").read().splitlines()
    except OSError as e:
        raise ValueError(f"cannot read {path}: {e}")

    recv, _, name = symbol.rpartition(".")
    pats = []
    if recv:
        # Method on T or *T. The receiver variable is unconstrained; only the
        # type name and the method name identify the declaration.
        pats.append(re.compile(r"^func\s*\(\s*\w+\s+\*?" + re.escape(recv) + r"\s*\)\s*"
                               + re.escape(name) + r"\b"))
    else:
        pats.append(re.compile(r"^(" + GO_DECL + r")\s+" + re.escape(name) + r"\b"))

    # A name inside a grouped const(...) / var(...) block: `Name = x`,
    # `Name Type = x`, or `Name,` in a multi-name spec.
    grouped = re.compile(r"^\s+" + re.escape(name) + r"\b\s*([\w.\[\]*]+\s*)?(=|,|$)")

    hits = []
    in_group = False
    for n, raw in enumerate(src, 1):
        if re.match(r"^(const|var)\s*\($", raw.strip()):
            in_group = True
        elif in_group and raw.strip() == ")":
            in_group = False
        for p in pats:
            if p.match(raw):
                hits.append((n, raw))
                break
        else:
            if in_group and not recv and grouped.match(raw):
                hits.append((n, raw))

    if not hits:
        raise ValueError(f"no Go declaration of `{symbol}` in {path} — the symbol was "
                         f"renamed, moved or deleted")
    if len(hits) > 1:
        lines = ", ".join(str(n) for n, _ in hits)
        raise ValueError(f"`{symbol}` matches {len(hits)} declarations in {path} "
                         f"(lines {lines}) — the anchor is ambiguous")
    n, raw = hits[0]
    return n, norm(strip_line_comment(raw))


def resolve_text(path, literal):
    try:
        src = open(path, encoding="utf-8").read().splitlines()
    except OSError as e:
        raise ValueError(f"cannot read {path}: {e}")
    want = norm(literal)
    hits = [n for n, raw in enumerate(src, 1) if want in norm(raw)]
    if not hits:
        raise ValueError(f"the literal {literal!r} no longer appears in {path}")
    if len(hits) > 1:
        raise ValueError(f"the literal {literal!r} appears {len(hits)} times in {path} "
                         f"(lines {', '.join(str(n) for n in hits)}) — an anchor must be "
                         f"unique, so narrow it")
    return hits[0], want


def resolve(anchor):
    """anchor -> (line, fingerprint-path, anchored-text)."""
    if anchor == "none:":
        return "", "", ""
    kind, _, rest = anchor.partition(":")
    if kind not in ("go", "text") or not rest:
        raise ValueError(f"unknown anchor form {anchor!r}; expected go:<path>#<Symbol>, "
                         f"text:<path>#<literal> or none:")
    path, sep, target = rest.partition("#")
    if not sep or not target:
        raise ValueError(f"anchor {anchor!r} has no '#<target>' part")
    if not os.path.exists(path):
        raise ValueError(f"{path} does not exist — the file the row describes was moved "
                         f"or deleted")
    n, text = (resolve_go if kind == "go" else resolve_text)(path, target)
    return str(n), path, text


def fingerprint(row_id, fp_path, text):
    return hashlib.sha256("\x00".join((row_id, fp_path, text)).encode()).hexdigest()[:16]


# ── read ────────────────────────────────────────────────────────────────────
if not os.path.exists(reg_path):
    print(f"::error::{reg_path} does not exist", file=sys.stderr)
    sys.exit(2)

rows, errors = [], []
header_seen = False
with open(reg_path, encoding="utf-8") as fh:
    for lineno, ln in enumerate(fh, 1):
        if ln.startswith("#") or not ln.strip():
            continue
        parts = ln.rstrip("\n").split("\t")
        if parts[0] == "fingerprint":
            if parts != COLS:
                errors.append(f"{reg_path}:{lineno}: header is {parts}, expected {COLS}")
            header_seen = True
            continue
        if len(parts) != len(COLS):
            errors.append(f"{reg_path}:{lineno}: {len(parts)} fields, expected "
                          f"{len(COLS)} — every column is tab-separated and present, "
                          f"empty where it does not apply")
            continue
        row = dict(zip(COLS, parts))
        row["_lineno"] = lineno
        rows.append(row)

if not header_seen:
    errors.append(f"{reg_path}: no header row")

if errors:
    for e in errors:
        print(f"::error::{e}", file=sys.stderr)
    sys.exit(2)

# ── validate + resolve ──────────────────────────────────────────────────────
problems = []          # (id, message) — every one of these fails the gate
unchecked = 0          # rows anchored `none:` — reported, not failed
seen_ids = {}

for r in rows:
    rid, at = r["id"], f"{reg_path}:{r['_lineno']}"

    if not rid:
        problems.append(("?", f"{at}: row has no id"))
        continue
    if rid in seen_ids:
        problems.append((rid, f"{at}: duplicate id (also at line {seen_ids[rid]})"))
    seen_ids[rid] = r["_lineno"]

    for f in REQUIRED_ALWAYS:
        if not r[f].strip():
            problems.append((rid, f"`{f}` is empty"))

    if r["kind"] not in KINDS:
        problems.append((rid, f"unknown kind {r['kind']!r}; expected one of "
                              f"{sorted(KINDS)}"))
    if r["status"] not in STATUSES:
        problems.append((rid, f"unknown status {r['status']!r}; expected one of "
                              f"{sorted(STATUSES)}"))

    if r["kind"] == "exception":
        for f in REQUIRED_EXCEPTION:
            if not r[f].strip():
                problems.append((rid, f"`{f}` is empty — an exception row names the "
                                      f"constraint that forces it and the fact that "
                                      f"retires it"))
    elif r["kind"] == "canonical" and r["exception"].strip():
        problems.append((rid, "a canonical row carries no `exception`; a second method "
                              "in the same cell is its own row"))

    # A date is never a revisit trigger.
    for pat, what in DATEISH:
        if r["revisit"] and pat.search(r["revisit"]):
            problems.append((rid, f"`revisit` reads like {what}: {r['revisit']!r}. A date "
                                  f"is never a trigger — name a fact someone can check."))
            break

    # `unverified` is a state the register can EXPRESS — §2 requires it when a
    # premise has not been checked — but it is not a resting state. The price
    # of recording it is a scheduled probe, and the `cite` is that probe. A row
    # that says "unverified" and names nothing to run is a guess wearing a
    # status.
    if r["status"] == "unverified" and not r["cite"].strip():
        problems.append((rid, "status is `unverified` with no `cite` — an unchecked "
                              "premise is recorded together with the probe that will "
                              "settle it. File the probe and cite it here."))
    if r["status"] == "decision" and not r["cite"].strip():
        problems.append((rid, "status is `decision` with no `cite` — a decision nobody "
                              "can look up cannot be revisited on its own terms"))

    if r["anchor"] == "none:":
        unchecked += 1
        if not r["cite"].strip():
            problems.append((rid, "anchor is `none:` with no `cite` — a row this gate "
                                  "cannot check must at least say where its evidence is"))
        r["_line"], r["_fp"] = "", fingerprint(rid, "", "")
        continue

    try:
        line, fp_path, text = resolve(r["anchor"])
    except ValueError as e:
        problems.append((rid, f"{e}. Re-read the row against the code as it is now, then "
                              f"`scripts/auth-register.sh --refresh`."))
        r["_line"], r["_fp"] = r["line"], r["fingerprint"]
        continue
    r["_line"], r["_fp"] = line, fingerprint(rid, fp_path, text)

drifted = [r for r in rows if r.get("_fp") and r["_fp"] != r["fingerprint"]]

# ── refresh ─────────────────────────────────────────────────────────────────
HEADER = (
    "# .github/auth-register.tsv — one canonical authentication method per cell,\n"
    "# and every second method that is allowed to exist alongside it.\n"
    "#\n"
    "# Rows are written BY HAND. Recompute fingerprints and line numbers with:\n"
    "#   scripts/auth-register.sh --refresh\n"
    "# The rule, the four conditions a justification must meet, the anchor forms\n"
    "# and what the gate fails on: scripts/auth-register.sh\n"
    "#\n"
    "# kind:   canonical | exception\n"
    "# status: true-now | unverified | decision\n"
    "# revisit: a CHECKABLE FACT. A date is never a trigger, and the gate says so.\n"
    "# anchor: go:<path>#<Symbol> | text:<path>#<literal> | none: (needs a cite)\n"
    "#\n"
    "# 'line' is navigation only and is refreshed each run; it is NOT part of the\n"
    "# fingerprint, so edits above a row do not churn this file. Editing the\n"
    "# ANCHORED declaration does change the fingerprint, and the gate then fails\n"
    "# until someone re-reads the row against the code that changed.\n"
    "#\n"
    "# This file is PUBLIC. A row describing a fail-open that is unfixed and\n"
    "# reachable does not belong here; it lives in a private geekdojo-brain issue\n"
    "# and moves here in the pull request that fixes it.\n")

if mode == "--refresh":
    with open(reg_path, "w", encoding="utf-8") as fh:
        fh.write(HEADER)
        fh.write("\t".join(COLS) + "\n")
        for r in sorted(rows, key=lambda r: (r["kind"] != "canonical", r["id"])):
            r["fingerprint"] = r.get("_fp") or r["fingerprint"]
            r["line"] = r.get("_line", r["line"])
            fh.write("\t".join(r[c].replace("\t", " ") for c in COLS) + "\n")
    print(f"wrote {reg_path}: {len(rows)} row(s)")

# ── posture, always ─────────────────────────────────────────────────────────
kinds = Counter(r["kind"] for r in rows)
statuses = Counter(r["status"] for r in rows)
cells = {r["cell"] for r in rows}
print(f"{len(rows)} rows · {len(cells)} cells · "
      f"canonical {kinds['canonical']} · exception {kinds['exception']} · "
      + " · ".join(f"{s} {statuses[s]}" for s in sorted(statuses)))
if unchecked:
    print(f"{unchecked} row(s) anchored `none:` — held by a recorded decision, another "
          f"repo or an upstream project, so this gate cannot check them; their evidence "
          f"is the `cite` column")
unver = [r for r in rows if r["status"] == "unverified"]
if unver:
    print(f"{len(unver)} row(s) rest on a premise nobody has checked: "
          + ", ".join(f"{r['id']} ({r['cite']})" for r in unver))
owed = sorted({r["cite"] for r in rows
               if r["status"] in ("decision", "unverified") and r["cite"]})
if owed:
    print("open, tracked: " + ", ".join(owed))

if mode != "--gate":
    for rid, msg in problems:
        print(f"  PROBLEM {rid}: {msg}")
    # Not in --refresh: refresh is what RESOLVES drift, so listing it after the
    # rewrite would name rows that are no longer drifted.
    if mode == "--report":
        for r in drifted:
            print(f"  DRIFTED {r['id']}: anchored code changed "
                  f"({r['fingerprint']} -> {r['_fp']})")
    # --refresh is a maintenance action: it fills in what it can and leaves the
    # problems for the gate to refuse, so it does not fail on them. --report is
    # a person asking the question, so it answers with its exit status too.
    sys.exit(0 if mode == "--refresh" else (1 if problems else 0))

# ── gate ────────────────────────────────────────────────────────────────────
fail = False

if drifted:
    fail = True
    print(f"\n::error::{len(drifted)} row(s) whose anchored code has changed:")
    for r in drifted:
        print(f"  {r['id']}  {r['anchor']}  {r['fingerprint']} -> {r['_fp']}")
    print("The code a row describes changed, so the row is no longer evidence for")
    print("anything. Re-read each one against the code as it is now — the exception")
    print("may have been closed by the same edit — then run")
    print("`scripts/auth-register.sh --refresh` and commit the result.")

if problems:
    fail = True
    print(f"\n::error::{len(problems)} problem(s) in {reg_path}:")
    for rid, msg in problems:
        print(f"  {rid}: {msg}")

sys.exit(1 if fail else 0)
PY
