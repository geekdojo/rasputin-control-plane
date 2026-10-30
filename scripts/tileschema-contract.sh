#!/usr/bin/env bash
#
# tileschema-contract.sh version
# tileschema-contract.sh check
# tileschema-contract.sh tag REMOTE SHA
#
# The tileschema contract version and its own tag line, tileschema/vM.m.p,
# independent of the CalVer release train (ADR-0012 Decisions 2 and 3,
# geekdojo/geekdojo-brain#897). Runs against the git repository containing the
# current directory.
#
#   version  Prints M.m.p, read from ContractMajor, ContractMinor and
#            ContractPatch in tileschema/contract.go. Each must be declared
#            exactly once as a plain integer constant.
#
#   check    Compares this tree with the highest tileschema/vM.* tag for the
#            tree's major, ordered by version number (git's v:refname sort, so
#            v1.10.0 ranks above v1.9.0). The contract surface golden
#            (tileschema/testdata/contract-surface.txt, written by
#            TestContractSurface) is compared with the tag's copy; a tag with no
#            golden counts as changed. Refused when the tree's version is lower
#            than the tag's, or when the surface changed and the tree's M.m is
#            not above the tag's.
#
#   tag      Runs check, then cuts the annotated tag tileschema/vM.m.p on SHA
#            and pushes that one ref to REMOTE, unless REMOTE already has it:
#            an existing tag is never moved, and finding it is success. After a
#            push, scripts/release-target-guard.sh proves where the tag landed.
#            .github/workflows/tileschema-tag.yml runs this on every push to
#            main that touches tileschema/.
#
# Exit status:
#   0  pass, or the tag already exists on REMOTE
#   1  the contract change is refused (the message says how to fix it)
#   2  usage or environment error: an unreadable contract.go or golden, no tag
#      for the major, a malformed tag, an unreadable remote. Never a pass.
#
# scripts/test-tileschema-contract.sh covers every verb and status.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
contract_rel="tileschema/contract.go"
golden_rel="tileschema/testdata/contract-surface.txt"
semver_re='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

fail() {
	local status="$1"
	shift
	printf 'tileschema-contract: %s\n' "$*" >&2
	exit "$status"
}

usage() {
	fail 2 "Usage: tileschema-contract.sh version | check | tag REMOTE SHA."
}

repo_root() {
	git rev-parse --show-toplevel 2>/dev/null ||
		fail 2 "The current directory is not inside a git repository."
}

# read_const NAME — prints the value of the integer constant NAME, declared
# exactly once in contract.go in gofmt form (optionally with a leading const).
read_const() {
	local name="$1" file="$root/$contract_rel" matches count
	[ -r "$file" ] || fail 2 "Cannot read $contract_rel, so the contract version is unknown."
	matches="$(grep -E "^[[:space:]]*(const[[:space:]]+)?${name}[[:space:]]*=[[:space:]]*(0|[1-9][0-9]*)[[:space:]]*$" "$file" || true)"
	if [ -z "$matches" ]; then
		count=0
	else
		count="$(printf '%s\n' "$matches" | wc -l | tr -d ' ')"
	fi
	[ "$count" -eq 1 ] ||
		fail 2 "$name must be declared exactly once in $contract_rel as a plain integer constant, but $count declarations were found."
	printf '%s\n' "$matches" | sed -E 's/.*=[[:space:]]*([0-9]+)[[:space:]]*$/\1/'
}

# tree_version — sets major, minor, patch from contract.go.
tree_version() {
	major="$(read_const ContractMajor)" || exit "$?"
	minor="$(read_const ContractMinor)" || exit "$?"
	patch="$(read_const ContractPatch)" || exit "$?"
}

cmd_version() {
	tree_version
	printf '%s.%s.%s\n' "$major" "$minor" "$patch"
}

# cmd_check — sets tag and version on a pass; exits 1 or 2 otherwise.
cmd_check() {
	tree_version
	version="$major.$minor.$patch"

	local latest tag_version tag_major tag_minor tag_patch golden="$root/$golden_rel" changed
	latest="$(git -C "$root" tag -l --sort=-v:refname "tileschema/v$major.*" | head -n 1)"
	[ -n "$latest" ] ||
		fail 2 "No tileschema/v$major.* tag is present, so contract $version cannot be checked. Fetch the tags with: git fetch origin '+refs/tags/tileschema/*:refs/tags/tileschema/*'."
	tag_version="${latest#tileschema/v}"
	[[ "$tag_version" =~ $semver_re ]] ||
		fail 2 "The highest tag, $latest, is not of the form tileschema/vM.m.p, so contract $version cannot be checked against it."
	tag_major="${BASH_REMATCH[1]}"
	tag_minor="${BASH_REMATCH[2]}"
	tag_patch="${BASH_REMATCH[3]}"
	git -C "$root" rev-parse --quiet --verify "$latest^{commit}" >/dev/null ||
		fail 2 "The tag $latest names no commit present in this repository, so contract $version cannot be checked against it."
	[ -r "$golden" ] ||
		fail 2 "Cannot read $golden_rel. Generate it with: go test ./tileschema -run TestContractSurface -update."

	local fix="Bump ContractMinor in $contract_rel above $tag_major.$tag_minor (and set ContractPatch to 0), then rerun go test ./tileschema -run TestContractSurface -update and commit the golden."

	if ((major < tag_major ||
		(major == tag_major && minor < tag_minor) ||
		(major == tag_major && minor == tag_minor && patch < tag_patch))); then
		fail 1 "This tree's contract version $version is lower than the latest tag, $latest ($tag_version). Update this branch from main. $fix"
	fi

	changed=1
	if git -C "$root" cat-file -e "$latest:$golden_rel" 2>/dev/null &&
		git -C "$root" show "$latest:$golden_rel" | cmp -s - "$golden"; then
		changed=0
	fi
	if [ "$changed" -eq 1 ] && ((minor <= tag_minor)); then
		fail 1 "The contract surface differs from $latest ($tag_version), but this tree's contract version $version does not raise the minor above $tag_major.$tag_minor. $fix"
	fi

	tag="tileschema/v$version"
	printf 'tileschema contract %s checked against %s (%s): ok.\n' "$version" "$latest" "$tag_version"
}

cmd_tag() {
	local remote="$1" sha="$2" status existing
	[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || fail 2 "The commit '$sha' is not a full 40-character SHA."
	cmd_check

	status=0
	existing="$(git -C "$root" ls-remote --exit-code --tags -- "$remote" "refs/tags/$tag^{}" "refs/tags/$tag" 2>/dev/null)" || status=$?
	if [ "$status" -eq 0 ]; then
		printf '%s already exists on %s and is left where it is:\n%s\n' "$tag" "$remote" "$existing"
		return 0
	fi
	[ "$status" -eq 2 ] || fail 2 "Could not read tags from $remote (git ls-remote exited $status), so $tag was not cut."

	git -C "$root" tag -a "$tag" -m "tileschema contract $version" "$sha" ||
		fail 2 "Could not create the tag $tag on $sha."
	git -C "$root" push "$remote" "refs/tags/$tag:refs/tags/$tag" ||
		fail 2 "Could not push $tag to $remote."
	"$here/release-target-guard.sh" "$remote" "$tag" "$sha" ||
		fail 2 "The pushed tag $tag could not be proven to point at $sha."
}

[ "$#" -ge 1 ] || usage
verb="$1"
shift
root="$(repo_root)"
case "$verb" in
version)
	[ "$#" -eq 0 ] || usage
	cmd_version
	;;
check)
	[ "$#" -eq 0 ] || usage
	cmd_check
	;;
tag)
	[ "$#" -eq 2 ] || usage
	cmd_tag "$1" "$2"
	;;
*) usage ;;
esac
