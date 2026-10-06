#!/usr/bin/env bash
#
# test-npm-audit.sh — tests for scripts/npm-audit.sh's fix labelling.
#
# Run:  ./scripts/test-npm-audit.sh
#
# npm's fixAvailable is false, true, or {name, version, isSemVerMajor}. The gate
# used to print "fix available" for any truthy value, so a semver-major object —
# for braces (GHSA-vfj7-8cjw-p6xm) a DOWNGRADE of eslint-config-next 16 -> 14 —
# read as an upgrade waiting to be taken. The live tree only ever shows whatever
# the advisory database says today, so these cases are the only thing that
# feeds the gate each shape on purpose, including one advisory reached through
# several packages with different answers.
#
# Every case runs the gate from a scratch copy of the repo layout it needs
# (scripts/, .github/ and an empty ui/), with a stub `npm` first on PATH that
# prints a fixture report. The committed register and lockfile are never read.
#
# No network. python3 only, same as the gate.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
GATE_SRC="${GATE:-$here/npm-audit.sh}"

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT

tree="$tmp/tree"
mkdir -p "$tree/scripts" "$tree/.github" "$tree/ui" "$tmp/bin"
cp "$GATE_SRC" "$tree/scripts/npm-audit.sh"
chmod +x "$tree/scripts/npm-audit.sh"
GATE="$tree/scripts/npm-audit.sh"
REGISTER="$tree/.github/npm-audit-register.tsv"
FULL="$tmp/full.json"
PROD="$tmp/prod.json"

# The stub npm: the gate runs `npm audit --package-lock-only [--omit=dev] --json`
# and nothing else, so the --omit=dev flag is the only thing it has to read.
cat >"$tmp/bin/npm" <<EOF
#!/usr/bin/env bash
case " \$* " in
	*" --omit=dev "*) cat "$PROD" ;;
	*) cat "$FULL" ;;
esac
EOF
chmod +x "$tmp/bin/npm"

# report FILE SPEC... — an npm audit report. Each SPEC is
# package:ghsa:severity:fix, where fix is false, true, or name@version@major
# (major is 0 or 1). Two SPECs naming the same ghsa are one advisory reached
# through two packages, which is how npm reports a transitive chain.
report() {
	local file="$1"
	shift
	python3 - "$file" "$@" <<'PY'
import json
import sys

path, specs = sys.argv[1], sys.argv[2:]
vulns = {}
for spec in specs:
    pkg, ghsa, severity, fix = spec.split(":")
    if fix in ("true", "false"):
        fix_available = fix == "true"
    else:
        name, version, major = fix.split("@")
        fix_available = {"name": name, "version": version,
                         "isSemVerMajor": major == "1"}
    vulns[pkg] = {
        "name": pkg,
        "severity": severity,
        "via": [{
            "source": 1,
            "name": "vulnpkg",
            "title": f"test advisory {ghsa}",
            "url": f"https://github.com/advisories/{ghsa}",
            "severity": severity,
            "range": "<=1.0.0",
        }],
        "fixAvailable": fix_available,
    }
doc = {
    "vulnerabilities": vulns,
    "metadata": {
        "vulnerabilities": {},
        "dependencies": {"total": 1, "prod": 0, "dev": 1},
    },
}
with open(path, "w", encoding="utf-8") as handle:
    json.dump(doc, handle)
PY
}

# An empty production-only report: every advisory below is dev scope.
report "$PROD"

# register [ghsa...] — the header plus one valid row per id given.
register() {
	printf 'advisory\tpackage\tseverity\tscope\treason\tissue\n' >"$REGISTER"
	local id
	for id in "$@"; do
		printf '%s\tvulnpkg\thigh\tdev\ttest reason\tgeekdojo/test#1\n' "$id" >>"$REGISTER"
	done
}

failures=0

# check NAME WANT_STATUS WANT_OUTPUT OUTPUT STATUS [UNWANTED_OUTPUT]
check() {
	local name="$1" want_status="$2" want_output="$3" output="$4" status="$5" unwanted="${6:-}"
	if [ "$status" != "$want_status" ]; then
		printf 'FAIL %s: exit %s, want %s\n%s\n' "$name" "$status" "$want_status" "$output"
		failures=$((failures + 1))
	elif ! grep -qF -- "$want_output" <<<"$output"; then
		printf 'FAIL %s: output lacks %q\n%s\n' "$name" "$want_output" "$output"
		failures=$((failures + 1))
	elif [ -n "$unwanted" ] && grep -qF -- "$unwanted" <<<"$output"; then
		printf 'FAIL %s: output contains %q\n%s\n' "$name" "$unwanted" "$output"
		failures=$((failures + 1))
	else
		printf 'ok   %s\n' "$name"
	fi
}

# run_gate MODE — sets $out and $rc.
run_gate() {
	rc=0
	out="$(PATH="$tmp/bin:$PATH" "$GATE" "$1" 2>&1)" || rc=$?
}

A=GHSA-aaaa-aaaa-aaaa

# ── (a) fixAvailable: true is a fix ─────────────────────────────────────────
register "$A"
report "$FULL" "vulnpkg:$A:high:true"
run_gate --report
check "(a) fixAvailable true reads 'fix available'" 0 "(fix available)" "$out" "$rc"

# ── (b) a non-major fix object is a fix ─────────────────────────────────────
report "$FULL" "vulnpkg:$A:high:parent@2.1.4@0"
run_gate --report
check "(b) a non-major fixAvailable object reads 'fix available'" 0 \
	"(fix available)" "$out" "$rc"

# ── (c) a semver-major fix object is NOT "fix available" ────────────────────
# The braces shape: the only route npm offers is a major change of the parent.

report "$FULL" "vulnpkg:$A:high:parent@14.2.35@1"
run_gate --report
check "(c) a semver-major fixAvailable object names the major-only route" 0 \
	"(major-version fix only: parent@14.2.35)" "$out" "$rc" "(fix available)"

# ── (d) fixAvailable: false has no fix ──────────────────────────────────────
report "$FULL" "vulnpkg:$A:high:false"
run_gate --report
check "(d) fixAvailable false reads 'NO FIX AVAILABLE'" 0 "(NO FIX AVAILABLE)" "$out" "$rc"

# ── (e) a non-major route anywhere wins over a major one ────────────────────
# Same advisory through two packages. The non-major route is FIRST, so a merge
# that kept only the last package's answer would print the major label.

report "$FULL" "vulnpkg:$A:high:true" "parent:$A:high:parent@3.0.0@1"
run_gate --report
check "(e) one advisory, a non-major and a major route: 'fix available'" 0 \
	"(fix available)" "$out" "$rc" "major-version"

# ── (f) several major-only routes are all named ─────────────────────────────
report "$FULL" "vulnpkg:$A:high:zeta@2.0.0@1" "parent:$A:high:alpha@9.0.0@1"
run_gate --report
check "(f) two major-only routes are both named, sorted" 0 \
	"(major-version fix only: alpha@9.0.0, zeta@2.0.0)" "$out" "$rc"

# ── (g) the label does not gate: major-only still blocks when unregistered ──
# Labelling only. An unregistered high advisory fails --gate whatever the fix
# kind, and a registered one passes.

register
report "$FULL" "vulnpkg:$A:high:parent@14.2.35@1"
run_gate --gate
check "(g) an unregistered major-only high advisory fails --gate" 1 \
	"not in .github/npm-audit-register.tsv" "$out" "$rc"

register "$A"
run_gate --gate
check "(g) the same advisory, registered, passes --gate" 0 "PASS:" "$out" "$rc"

# ── result ──────────────────────────────────────────────────────────────────

if [ "$failures" -ne 0 ]; then
	printf '\nnpm-audit: %d check(s) failed\n' "$failures"
	exit 1
fi
printf '\nnpm-audit: all checks passed\n'
