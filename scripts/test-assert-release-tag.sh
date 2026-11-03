#!/usr/bin/env bash
#
# test-assert-release-tag.sh — tests for scripts/assert-release-tag.sh and its
# place in scripts/build-release.sh (geekdojo/geekdojo-brain#529, TC-529-19).
#
# Run:  ./scripts/test-assert-release-tag.sh
#
# Builds a throwaway Go program with and without -tags release and runs the
# assertion on each: the tagged binary passes and is kept; the untagged one
# exits 1, is named, and is deleted, so build-release.sh (which runs the
# assertion between `go build` and `tar`, and runs under set -e) cannot pack
# it. Needs go; no network.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
ASSERT="${ASSERT:-$here/assert-release-tag.sh}"
BUILD="$here/build-release.sh"

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT

failures=0
ok() { printf 'ok   %s\n' "$1"; }
fail() { printf 'FAIL %s\n%s\n' "$1" "${2:-}"; failures=$((failures + 1)); }

mkdir -p "$tmp/src"
printf 'module example.invalid/probe\n\ngo 1.26\n' > "$tmp/src/go.mod"
printf 'package main\n\nfunc main() {}\n' > "$tmp/src/main.go"
build() { (cd "$tmp/src" && GOWORK=off CGO_ENABLED=0 go build -trimpath "$@"); }
build -tags release -o "$tmp/tagged"
build -tags other,release,more -o "$tmp/tagged-among-others"
build -o "$tmp/untagged"
build -tags releasex -o "$tmp/near-miss"

for b in tagged tagged-among-others; do
	rc=0; out="$("$ASSERT" "$tmp/$b" 2>&1)" || rc=$?
	if [ "$rc" = 0 ] && [ -f "$tmp/$b" ]; then ok "a binary built with the release tag ($b) passes and is kept"
	else fail "a binary built with the release tag ($b) passes and is kept (exit $rc)" "$out"; fi
done

for b in untagged near-miss; do
	rc=0; out="$("$ASSERT" "$tmp/$b" 2>&1)" || rc=$?
	if [ "$rc" != 1 ]; then fail "$b: exit $rc, want 1" "$out"
	elif ! grep -qF -- "$tmp/$b was built without -tags release" <<<"$out"; then fail "$b: the refusal does not name the binary" "$out"
	elif [ -e "$tmp/$b" ]; then fail "$b: the refused binary was left for packing"
	else ok "$b: refused with exit 1, named, and deleted"; fi
done

rc=0; out="$("$ASSERT" "$tmp/absent" 2>&1)" || rc=$?
if [ "$rc" = 2 ]; then ok "an unreadable binary is exit 2"; else fail "an unreadable binary: exit $rc, want 2" "$out"; fi
rc=0; out="$("$ASSERT" 2>&1)" || rc=$?
if [ "$rc" = 2 ]; then ok "missing arguments are a usage error"; else fail "missing arguments: exit $rc, want 2" "$out"; fi

# build-release.sh: every binary is built with the tag, and asserted after the
# build and before the first tar, under set -e.
build_line="$(grep -n 'go build ' "$BUILD" | head -1 | cut -d: -f1)"
# shellcheck disable=SC2016  # a literal $out, matched in the script text
assert_line="$(grep -n 'assert-release-tag.sh" "\$out"' "$BUILD" | head -1 | cut -d: -f1)"
tar_line="$(grep -n 'tar -C ' "$BUILD" | head -1 | cut -d: -f1)"
if grep -q 'go build -trimpath -tags release ' "$BUILD"; then ok "build-release.sh builds with -tags release"
else fail "build-release.sh builds with -tags release"; fi
if [ -n "$build_line" ] && [ -n "$assert_line" ] && [ -n "$tar_line" ] &&
	[ "$build_line" -lt "$assert_line" ] && [ "$assert_line" -lt "$tar_line" ]; then
	ok "build-release.sh asserts each binary between go build and tar"
else fail "build-release.sh asserts each binary between go build and tar (build=$build_line assert=$assert_line tar=$tar_line)"; fi
if grep -q '^set -euo pipefail' "$BUILD"; then ok "build-release.sh stops on the first failure"
else fail "build-release.sh stops on the first failure"; fi

if [ "$failures" -ne 0 ]; then
	echo "$failures assert-release-tag test(s) failed"
	exit 1
fi
echo "all assert-release-tag tests passed"
