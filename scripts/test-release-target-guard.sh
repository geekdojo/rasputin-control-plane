#!/usr/bin/env bash
#
# test-release-target-guard.sh — tests for scripts/release-target-guard.sh.
#
# Run:  ./scripts/test-release-target-guard.sh
#
# Builds a throwaway git remote with two commits and a mix of lightweight,
# annotated and nested annotated tags, then checks every exit status of the
# guard against it: tag on the built commit, tag on another commit, tag absent,
# unreadable remote, bad arguments. No network, no GitHub.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
GUARD="${GUARD:-$here/release-target-guard.sh}"

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT

# Hermetic git: no user or system config (signing, hooks, default branch).
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid

remote="$tmp/remote.git"
git init -q --bare "$remote"
git init -q "$tmp/work"
w() { git -C "$tmp/work" "$@"; }
w commit -q --allow-empty -m A
a="$(w rev-parse HEAD)"
w tag light-a
w tag -a annotated-a -m "annotated on A"
w -c advice.nestedTag=false tag -a nested-a -m "annotated tag of an annotated tag" annotated-a
w tag v1.1 # a longer name that shares a prefix with the absent tag v1
w commit -q --allow-empty -m B
b="$(w rev-parse HEAD)"
w tag light-b
w tag -a annotated-b -m "annotated on B"
w push -q "$remote" HEAD:refs/heads/main --tags

failures=0
# check NAME WANT_STATUS WANT_OUTPUT ARGS... — WANT_OUTPUT is a fixed string
# the combined output must contain ("" = anything).
check() {
	local name="$1" want_status="$2" want_output="$3"
	shift 3
	local status=0 output
	output="$("$GUARD" "$@" 2>&1)" || status=$?
	if [ "$status" != "$want_status" ]; then
		printf 'FAIL %s: exit %s, want %s\n%s\n' "$name" "$status" "$want_status" "$output"
		failures=$((failures + 1))
	elif [ -n "$want_output" ] && ! grep -qF -- "$want_output" <<<"$output"; then
		printf 'FAIL %s: output lacks %q\n%s\n' "$name" "$want_output" "$output"
		failures=$((failures + 1))
	else
		printf 'ok   %s\n' "$name"
	fi
}

check "lightweight tag on the built commit passes" 0 "$a" "$remote" light-a "$a"
check "annotated tag on the built commit passes (peeled)" 0 "$a" "$remote" annotated-a "$a"
check "tag of an annotated tag on the built commit passes (fully peeled)" 0 "$a" "$remote" nested-a "$a"
check "lightweight tag on another commit fails with both SHAs" 1 "points at $b, but this run built $a" "$remote" light-b "$a"
check "annotated tag on another commit fails with the peeled SHA" 1 "points at $b, but this run built $a" "$remote" annotated-b "$a"
check "annotated tag is not compared by its tag-object SHA" 1 "points at $a" "$remote" annotated-a "$(git -C "$remote" rev-parse annotated-a)"
check "an absent tag is status 3" 3 "does not exist" "$remote" v1 "$a"
check "an unreadable remote is status 2, never 'absent'" 2 "could not read tags" "$tmp/no-such-remote.git" light-a "$a"
check "a short SHA is refused" 2 "not a full 40-character SHA" "$remote" light-a "${a:0:7}"
check "an upper-case SHA is refused" 2 "not a full 40-character SHA" "$remote" light-a "$(tr 'a-f' 'A-F' <<<"$a")"
check "a tag name with glob characters is refused" 2 "refusing tag name" "$remote" 'light-*' "$a"
check "a tag name starting with a dash is refused" 2 "refusing tag name" "$remote" '-light-a' "$a"
check "missing arguments are a usage error" 2 "usage" "$remote" light-a

if [ "$failures" -ne 0 ]; then
	echo "$failures release-target-guard test(s) failed"
	exit 1
fi
echo "all release-target-guard tests passed"
