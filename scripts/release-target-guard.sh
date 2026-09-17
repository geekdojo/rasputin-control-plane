#!/usr/bin/env bash
#
# release-target-guard.sh REMOTE TAG BUILT_SHA
#
# Proves a release tag points at the commit the release was built from.
#
# A release job builds the commit it checked out, but `gh release create TAG`
# creates a missing TAG on whatever the default branch points at when it runs,
# unless it is given --target. A PR merged during the build then leaves the tag
# on a commit the artifacts were never built from. The release jobs pass
# --target; this guard is the tripwire that fails the job if a tag still ends up
# anywhere else (a regression, or a tag that already existed on another commit).
#
# Reads the tag from REMOTE with `git ls-remote`, so it checks what everyone else
# sees rather than a local ref. Annotated tags are peeled to their commit. REMOTE
# is a URL or a path; for an https URL, `gh` supplies the credentials (GH_TOKEN
# in Actions), so nothing is written to .git/config.
#
# Exit status:
#   0  TAG exists on REMOTE and points at BUILT_SHA
#   1  TAG exists on REMOTE and points at a different commit (both SHAs printed)
#   2  usage error, or REMOTE could not be read (never reported as "absent")
#   3  TAG does not exist on REMOTE
#
# Run before creating a release to refuse a tag that already sits on another
# commit (1), and after creating it to prove where it landed (anything but 0 is
# a failure). scripts/test-release-target-guard.sh covers every status.

set -euo pipefail

fail() {
	local status="$1"
	shift
	printf '::error::release-target-guard: %s\n' "$*" >&2
	exit "$status"
}

[ "$#" -eq 3 ] || fail 2 "usage: release-target-guard.sh REMOTE TAG BUILT_SHA"
remote="$1"
tag="$2"
built="$3"

# Tag names here are CalVer, SemVer, catalog-vN or sha256-<hex>. Refusing
# anything else keeps glob and ref-syntax characters out of the ls-remote
# patterns below.
[[ "$tag" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ ]] || fail 2 "refusing tag name '$tag'"
[[ "$built" =~ ^[0-9a-f]{40}$ ]] || fail 2 "built commit '$built' is not a full 40-character SHA"

errfile="$(mktemp)"
trap 'rm -f -- "$errfile"' EXIT

# The ^{} pattern asks for the peeled line an annotated tag carries; ls-remote
# does not list it for the bare ref pattern alone.
if ! refs="$(GIT_TERMINAL_PROMPT=0 git \
	-c credential.helper= -c 'credential.helper=!gh auth git-credential' \
	ls-remote --tags -- "$remote" "refs/tags/$tag" "refs/tags/$tag^{}" 2>"$errfile")"; then
	fail 2 "could not read tags from $remote: $(tr '\n' ' ' <"$errfile")"
fi

direct=""
peeled=""
while IFS=$'\t' read -r sha ref; do
	case "$ref" in
	"refs/tags/$tag") direct="$sha" ;;
	"refs/tags/$tag^{}") peeled="$sha" ;;
	esac
done <<<"$refs"

tagged="${peeled:-$direct}"
[ -n "$tagged" ] || fail 3 "tag $tag does not exist on $remote"

if [ "$tagged" != "$built" ]; then
	fail 1 "tag $tag points at $tagged, but this run built $built"
fi

echo "release-target-guard: tag $tag points at the built commit $built"
