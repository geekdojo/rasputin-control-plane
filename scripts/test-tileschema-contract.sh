#!/usr/bin/env bash
#
# test-tileschema-contract.sh — tests for scripts/tileschema-contract.sh.
#
# Run:  ./scripts/test-tileschema-contract.sh
#
# Builds throwaway git repositories holding only tileschema/contract.go and the
# contract surface golden, tags them, and checks every verb and exit status of
# the script against them: version, check (passes, refusals, fail-closed cases,
# numeric tag order) and tag (against a throwaway bare remote). No network, no
# GitHub, no Go toolchain. Cases are named by their geekdojo/geekdojo-brain#897
# test-case IDs.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${SCRIPT:-$here/tileschema-contract.sh}"

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT

# Hermetic git: no user or system config (signing, hooks, default branch).
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid

failures=0
n=0
repo=""

pass() { printf 'ok   %s\n' "$1"; }
flunk() {
	printf 'FAIL %s: %s\n' "$1" "$2"
	failures=$((failures + 1))
}

# fresh_repo — a new empty repository, which becomes $repo.
fresh_repo() {
	n=$((n + 1))
	repo="$tmp/repo$n"
	git init -q "$repo"
}

g() { git -C "$repo" "$@"; }

# write_contract MAJOR MINOR PATCH — contract.go with gofmt-aligned constants.
write_contract() {
	mkdir -p "$repo/tileschema"
	cat >"$repo/tileschema/contract.go" <<EOF
package tileschema

const (
	ContractMajor = $1
	ContractMinor = $2
	ContractPatch = $3
)
EOF
}

# write_golden TEXT | write_golden — (no argument: remove it)
write_golden() {
	mkdir -p "$repo/tileschema/testdata"
	if [ "$#" -eq 0 ]; then
		rm -f "$repo/tileschema/testdata/contract-surface.txt"
	else
		printf '%s\n' "$1" >"$repo/tileschema/testdata/contract-surface.txt"
	fi
}

# state MAJOR MINOR PATCH [GOLDEN] — write and commit a tree; no GOLDEN means
# the tree has no golden file (the shape of tileschema/v1.4.0).
state() {
	write_contract "$1" "$2" "$3"
	if [ "$#" -ge 4 ]; then write_golden "$4"; else write_golden; fi
	g add -A
	g commit -q --allow-empty -m "contract $1.$2.$3"
}

# run VERB... — runs the script inside $repo; sets status, out, err.
run() {
	status=0
	out="$(cd "$repo" && "$SCRIPT" "$@" 2>"$tmp/err")" || status=$?
	err="$(cat "$tmp/err")"
}

# expect NAME WANT_STATUS [FIXED STRING the stderr must contain]...
expect() {
	local name="$1" want="$2" s
	shift 2
	if [ "$status" != "$want" ]; then
		flunk "$name" "exit $status, want $want; stdout: $out; stderr: $err"
		return
	fi
	for s in "$@"; do
		if ! grep -qF -- "$s" <<<"$err"; then
			flunk "$name" "stderr lacks '$s': $err"
			return
		fi
	done
	pass "$name"
}

G1="schemaVersion int"
G2="schemaVersion int
schemaMinor int"
G3="$G2
tiles []tileschema.BundleTile"
FIX_MINOR="Bump ContractMinor in tileschema/contract.go"
FIX_UPDATE="go test ./tileschema -run TestContractSurface -update"

# --- TC-897-09: version ------------------------------------------------------

fresh_repo
state 1 5 0 "$G1"
run version
if [ "$status" = 0 ] && [ "$out" = "1.5.0" ]; then
	pass "TC-897-09 version prints exactly 1.5.0"
else
	flunk "TC-897-09 version prints exactly 1.5.0" "exit $status, stdout '$out', stderr '$err'"
fi

grep -v ContractPatch "$repo/tileschema/contract.go" >"$tmp/contract.go"
mv "$tmp/contract.go" "$repo/tileschema/contract.go"
run version
expect "TC-897-09 a missing ContractPatch exits 2" 2 "ContractPatch must be declared exactly once" "0 declarations were found."
[ -z "$out" ] || flunk "TC-897-09 a missing ContractPatch prints nothing on stdout" "stdout '$out'"

write_contract 1 5 0
printf 'const ContractMinor = 6\n' >>"$repo/tileschema/contract.go"
run version
expect "TC-897-09 a doubly declared ContractMinor exits 2" 2 "ContractMinor must be declared exactly once" "2 declarations were found."
[ -z "$out" ] || flunk "TC-897-09 a doubly declared ContractMinor prints nothing on stdout" "stdout '$out'"

# --- TC-897-10: check accepts legitimate bumps ------------------------------

fresh_repo
state 1 4 0 # v1.4.0's shape: no golden
g tag tileschema/v1.4.0
state 1 5 0 "$G1"
run check
expect "TC-897-10a a tag with no golden and a tree at 1.5 passes" 0
grep -qF "checked against tileschema/v1.4.0" <<<"$out" ||
	flunk "TC-897-10a the pass line names the tag compared" "stdout '$out'"

g tag tileschema/v1.5.0
run check
expect "TC-897-10b an unchanged golden at the same version passes" 0

state 1 6 0 "$G2"
run check
expect "TC-897-10c a changed golden with a minor bump passes" 0

state 1 5 1 "$G1"
run check
expect "TC-897-10d an unchanged golden with a patch-only bump passes" 0

# --- TC-897-11: check refuses an unbumped contract change -------------------

state 1 5 0 "$G2"
run check
expect "TC-897-11a a changed golden at the same version is refused" 1 \
	"tileschema/v1.5.0" "1.5.0" "$FIX_MINOR" "$FIX_UPDATE"

state 1 5 1 "$G2"
run check
expect "TC-897-11b a changed golden with a patch-only bump is refused" 1 \
	"tileschema/v1.5.0" "1.5.1" "1.5.0" "$FIX_MINOR" "$FIX_UPDATE"

fresh_repo
state 1 4 0
g tag tileschema/v1.4.0
state 1 4 1 "$G1"
run check
expect "TC-897-11c a tag with no golden and no minor bump is refused" 1 \
	"tileschema/v1.4.0" "1.4.1" "1.4.0" "$FIX_MINOR" "$FIX_UPDATE"

fresh_repo
state 1 5 0 "$G1"
g tag tileschema/v1.5.0
state 1 4 0 "$G1"
run check
expect "TC-897-11d a tree lower than the tag is refused" 1 \
	"tileschema/v1.5.0" "1.4.0" "1.5.0" "$FIX_MINOR" "$FIX_UPDATE"

# --- TC-897-12: check fails closed ------------------------------------------

fresh_repo
state 1 5 0 "$G1"
run check
expect "TC-897-12 no tileschema/v1.* tag exits 2" 2 "No tileschema/v1.* tag is present"

g tag tileschema/v1.4.0
rm "$repo/tileschema/contract.go"
run check
expect "TC-897-12 an unreadable contract.go exits 2" 2 "Cannot read tileschema/contract.go"

# Beyond the case list, the other fail-closed inputs: a malformed highest tag
# and a missing tree golden.
fresh_repo
state 1 5 0 "$G1"
g tag tileschema/v1.9.0-rc1
run check
expect "check exits 2 when the highest tag is not vM.m.p" 2 "is not of the form tileschema/vM.m.p"
g tag -d tileschema/v1.9.0-rc1 >/dev/null
g tag tileschema/v1.4.0
write_golden
run check
expect "check exits 2 when the tree has no golden" 2 "Cannot read tileschema/testdata/contract-surface.txt"

# --- TC-897-13: tags are ordered by version number --------------------------

fresh_repo
state 1 9 0 "$G1"
g tag tileschema/v1.9.0
state 1 10 0 "$G2"
g tag tileschema/v1.10.0
state 1 10 0 "$G1"
run check
expect "TC-897-13 tree 1.10.0 is compared with v1.10.0, not v1.9.0, and refused" 1 \
	"tileschema/v1.10.0"
if grep -qF "tileschema/v1.9.0" <<<"$err"; then
	flunk "TC-897-13 the refusal names v1.9.0" "$err"
fi

state 1 11 0 "$G3"
run check
expect "TC-897-13 tree 1.11.0 with a changed golden passes" 0
grep -qF "checked against tileschema/v1.10.0" <<<"$out" ||
	flunk "TC-897-13 the pass names tileschema/v1.10.0" "stdout '$out'"

# --- TC-897-14: tag ---------------------------------------------------------

peeled() { git ls-remote "$remote" "refs/tags/$1^{}" | cut -f1; }
direct() { git ls-remote "$remote" "refs/tags/$1" | cut -f1; }

remote="$tmp/remote.git"
git init -q --bare "$remote"
fresh_repo
state 1 4 0
g tag tileschema/v1.4.0
state 1 5 0 "$G1"
sha="$(g rev-parse HEAD)"
g push -q "$remote" HEAD:refs/heads/main refs/tags/tileschema/v1.4.0

run tag "$remote" "$sha"
expect "TC-897-14 tag creates tileschema/v1.5.0 and the guard passes" 0
grep -qF "release-target-guard: tag tileschema/v1.5.0 points at the built commit $sha" <<<"$out" ||
	flunk "TC-897-14 the guard proved where the tag landed" "stdout '$out'"
if [ "$(peeled tileschema/v1.5.0)" = "$sha" ] && [ "$(git -C "$remote" cat-file -t refs/tags/tileschema/v1.5.0)" = tag ]; then
	pass "TC-897-14 the remote tag is annotated and peels to the commit"
else
	flunk "TC-897-14 the remote tag is annotated and peels to the commit" "$(git ls-remote "$remote")"
fi

before="$(direct tileschema/v1.5.0)"
run tag "$remote" "$sha"
expect "TC-897-14 a second run exits 0" 0
grep -qF "already exists" <<<"$out" || flunk "TC-897-14 a second run says the tag exists" "stdout '$out'"
[ "$(direct tileschema/v1.5.0)" = "$before" ] ||
	flunk "TC-897-14 a second run leaves the tag object unchanged" "$(git ls-remote "$remote")"

# The tag already on another commit: it is found, not moved.
state 1 5 0 "$G1"
other="$(g rev-parse HEAD)"
g tag -d tileschema/v1.5.0 >/dev/null
run tag "$remote" "$other"
expect "TC-897-14 a tag already on another commit exits 0" 0
if [ "$(peeled tileschema/v1.5.0)" = "$sha" ] && [ "$(direct tileschema/v1.5.0)" = "$before" ]; then
	pass "TC-897-14 the existing tag still peels to the original commit"
else
	flunk "TC-897-14 the existing tag still peels to the original commit" "$(git ls-remote "$remote")"
fi

# A tree that fails check cuts nothing.
g fetch -q "$remote" refs/tags/tileschema/v1.5.0:refs/tags/tileschema/v1.5.0
refs_before="$(git ls-remote "$remote")"
state 1 5 0 "$G2"
run tag "$remote" "$(g rev-parse HEAD)"
expect "TC-897-14 a tree that fails check exits non-zero" 1 "$FIX_MINOR"
[ "$(git ls-remote "$remote")" = "$refs_before" ] ||
	flunk "TC-897-14 a refused tree adds no ref to the remote" "$(git ls-remote "$remote")"

run tag "$remote" "${sha:0:7}"
expect "tag refuses a short SHA" 2 "not a full 40-character SHA"

state 1 6 0 "$G2"
run tag "$tmp/no-such-remote.git" "$(g rev-parse HEAD)"
expect "tag exits 2 on an unreadable remote, and cuts nothing" 2 "Could not read tags"
if g rev-parse --quiet --verify refs/tags/tileschema/v1.6.0 >/dev/null; then
	flunk "tag on an unreadable remote created no local tag" "tileschema/v1.6.0 exists"
fi

run bogus
expect "an unknown verb is a usage error" 2 "Usage"

if [ "$failures" -ne 0 ]; then
	echo "$failures tileschema-contract test(s) failed"
	exit 1
fi
echo "all tileschema-contract tests passed"
