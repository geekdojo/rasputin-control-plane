#!/usr/bin/env bash
#
# test-codeql-register.sh — tests for scripts/codeql-register.sh's coverage
# detection.
#
# Run:  ./scripts/test-codeql-register.sh
#
# The gate reads a scan's coverage from the SARIF: a run that was diff-limited
# lists the codeql-action/pr-diff-range extension pack in tool.extensions.
# codeql.yml turns diff-informed analysis off, so every real CI run is a full
# scan and never reaches the branch that catches a diff-limited one. These
# cases are the only thing that does, so a change to load_sarif that stopped
# seeing the pack fails here rather than staying green
# (geekdojo/geekdojo-brain#825, F-825-25 and F-825-26).
#
# Every case runs the gate from a scratch copy of the repo layout it needs
# (scripts/ and .github/), because the gate resolves its register from the repo
# root. The committed register is never read or written.
#
# No network. python3 only, same as the gate.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
GATE_SRC="${GATE:-$here/codeql-register.sh}"

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT

tree="$tmp/tree"
mkdir -p "$tree/scripts" "$tree/.github"
cp "$GATE_SRC" "$tree/scripts/codeql-register.sh"
chmod +x "$tree/scripts/codeql-register.sh"
GATE="$tree/scripts/codeql-register.sh"
REGISTER="$tree/.github/codeql-register.tsv"

PACK="codeql-action/pr-diff-range"

# sarif FILE [extension...] — a one-run SARIF whose tool.extensions lists the
# given pack names. One result when RESULT=1, otherwise none.
sarif() {
	local file="$1"
	shift
	mkdir -p "$(dirname "$file")"
	RESULT="${RESULT:-0}" python3 - "$file" "$@" <<'PY'
import json
import os
import sys

path, packs = sys.argv[1], sys.argv[2:]
results = []
if os.environ["RESULT"] == "1":
    results.append({
        "ruleId": "go/test-rule",
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "api/x.go"},
            "region": {"startLine": 3}}}],
        "partialFingerprints": {"primaryLocationLineHash": "abc:1"},
    })
run = {
    "tool": {
        "driver": {"name": "CodeQL", "rules": [
            {"id": "go/test-rule", "properties": {"security-severity": "5.0"}}]},
        "extensions": [{"name": name} for name in packs],
    },
    "results": results,
}
with open(path, "w", encoding="utf-8") as handle:
    json.dump({"version": "2.1.0", "runs": [run]}, handle)
PY
}

# An empty register: header only, no rows.
empty_register() {
	printf 'fingerprint\trule\tseverity\tpath\tline\tverdict\tissue\treasoning\n' >"$REGISTER"
}

failures=0

# check NAME WANT_STATUS WANT_OUTPUT OUTPUT STATUS
check() {
	local name="$1" want_status="$2" want_output="$3" output="$4" status="$5"
	if [ "$status" != "$want_status" ]; then
		printf 'FAIL %s: exit %s, want %s\n%s\n' "$name" "$status" "$want_status" "$output"
		failures=$((failures + 1))
	elif ! grep -qF -- "$want_output" <<<"$output"; then
		printf 'FAIL %s: output lacks %q\n%s\n' "$name" "$want_output" "$output"
		failures=$((failures + 1))
	else
		printf 'ok   %s\n' "$name"
	fi
}

# run_gate MODE DIR [EVENT] — sets $out and $rc.
run_gate() {
	rc=0
	out="$(GITHUB_EVENT_NAME="${3:-}" "$GATE" "$1" "$2" 2>&1)" || rc=$?
}

# ── (a) a diff-limited SARIF fails the gate ─────────────────────────────────
# The event is `push` on purpose: coverage comes from the SARIF, so even a run
# that says it is not a PR fails when its analysis used the pack.

empty_register
sarif "$tmp/a/go.sarif" "$PACK" codeql/go-queries
run_gate --gate "$tmp/a" push
check "(a) a SARIF naming $PACK fails --gate as DIFF-LIMITED" 1 "DIFF-LIMITED" "$out" "$rc"

# ── (b) the same SARIF without the pack passes on a pull_request ────────────
# The old gate called every pull_request scan diff-limited. This proves the
# event name no longer decides coverage.

empty_register
sarif "$tmp/b/go.sarif" codeql/go-queries
run_gate --gate "$tmp/b" pull_request
check "(b) a full SARIF passes --gate under GITHUB_EVENT_NAME=pull_request" 0 \
	"scan COVERAGE: full" "$out" "$rc"

# ── (c) --refresh refuses a diff-limited SARIF and leaves the register alone ─
# One row in the register and one different finding in the scan, so the count
# guard (more rows dropped than found) does NOT fire: the refusal can only come
# from the diff-limited detection.

{
	printf 'fingerprint\trule\tseverity\tpath\tline\tverdict\tissue\treasoning\n'
	printf '0123456789abcdef\tgo/other-rule\thigh\tapi/y.go\t9\tfalse-positive\t\tthe input is a constant\n'
} >"$REGISTER"
cp "$REGISTER" "$tmp/register.before"
RESULT=1 sarif "$tmp/c/go.sarif" "$PACK" codeql/go-queries
run_gate --refresh "$tmp/c" pull_request
check "(c) --refresh refuses a diff-limited SARIF" 1 "the SARIF is diff-limited" "$out" "$rc"
if cmp -s "$tmp/register.before" "$REGISTER"; then
	printf 'ok   (c) the register is byte-identical after the refusal\n'
else
	printf 'FAIL (c) the register changed after a refused refresh\n'
	diff "$tmp/register.before" "$REGISTER" || true
	failures=$((failures + 1))
fi

# ── (d) one diff-limited run among several fails the gate ───────────────────
# The pack is in the FIRST file read, so a detection that only kept the last
# file's answer would pass this.

empty_register
sarif "$tmp/d/a.sarif" "$PACK" codeql/go-queries
sarif "$tmp/d/b.sarif" codeql/go-queries
run_gate --gate "$tmp/d" push
check "(d) two SARIFs, only one diff-limited, fail --gate" 1 "DIFF-LIMITED" "$out" "$rc"

# ── result ──────────────────────────────────────────────────────────────────

if [ "$failures" -ne 0 ]; then
	printf '\ncodeql-register: %d check(s) failed\n' "$failures"
	exit 1
fi
printf '\ncodeql-register: all checks passed\n'
