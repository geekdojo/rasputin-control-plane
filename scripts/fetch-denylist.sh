#!/usr/bin/env bash
#
# fetch-denylist.sh — fetch the pinned password deny list and its licence
# notices, and cut the list to the realm's minimum length
# (geekdojo/geekdojo-brain#1145).
#
# Usage: scripts/fetch-denylist.sh OUT-DIR [KEEP-DIR]
#
# Downloads, from raw.githubusercontent.com at the commits
# api/internal/identitytest/pin.go pins:
#   - SecLists' DenylistSourcePath at DenylistRelease, checked against
#     DenylistSourceSHA256;
#   - SecLists' LICENSE at the same commit, against DenylistLicenceSHA256;
#   - Pwdb-Public's LICENSE at DenylistOriginRelease, the list's data source,
#     against DenylistOriginLicenceSHA256.
# Then writes:
#   OUT-DIR/password-blacklists/<DenylistFile>   the source's lines of at
#       least N bytes, in source order, each ending in LF, where N is the
#       length(N) that starts flows.PasswordPolicy. A shorter password is
#       already refused by that rule, and a line's UTF-8 byte length is never
#       less than its UTF-16 length, which is what Keycloak's length rule
#       counts, so the cut drops no password the realm would accept.
#   OUT-DIR/licenses/SecLists-LICENSE and OUT-DIR/licenses/Pwdb-Public-LICENSE
# Both names are read from api/internal/identity/flows/realm.go, so there is
# one source for each. No list is kept in this repository.
#
# With KEEP-DIR, the downloads are kept there and a file already there is used
# instead of downloading it again (CI restores it from the Actions cache with
# install-identity.sh's downloads). A kept file gets the same sha256 check as a
# fresh download, and one that fails it is refused, never replaced.
#
# Everything is fetched, checked and cut in a temporary directory first; only
# then are OUT-DIR's password-blacklists/ and licenses/ replaced. A refusal
# writes nothing under OUT-DIR.
#
# Exit status: 0 written; 1 a download, a check, a pin or the cut was refused;
# 2 bad usage. Each failure prints one sentence on stderr.
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ] || [ -z "$1" ]; then
	echo "Usage: $0 OUT-DIR [KEEP-DIR], where OUT-DIR receives password-blacklists/ and licenses/ and KEEP-DIR keeps the downloads." >&2
	exit 2
fi
out="$1"
keep="${2:-}"

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
pin="$repo_root/api/internal/identitytest/pin.go"
realm="$repo_root/api/internal/identity/flows/realm.go"
# shellcheck source=SCRIPTDIR/lib/release-lib.sh
. "$repo_root/scripts/lib/release-lib.sh"   # pin_const, fetch_pinned

refuse() {
	echo "fetch-denylist: $1" >&2
	exit 1
}
need() {
	local v
	v="$(pin_const "$1" "$2")"
	[ -n "$v" ] || refuse "$1 has no $2 constant, so the deny list cannot be fetched."
	printf '%s' "$v"
}

release="$(need "$pin" DenylistRelease)"
source_path="$(need "$pin" DenylistSourcePath)"
source_sha256="$(need "$pin" DenylistSourceSHA256)"
licence_sha256="$(need "$pin" DenylistLicenceSHA256)"
origin_release="$(need "$pin" DenylistOriginRelease)"
origin_licence_sha256="$(need "$pin" DenylistOriginLicenceSHA256)"

list_name="$(need "$realm" DenylistFile)"
[[ "$list_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
	|| refuse "$realm names the deny list '$list_name', which is not a plain file name."
# The policy's own line: PasswordPolicy = "length(N) ..., anchored like pin_const.
min_len="$(sed -n -E 's/^[[:space:]]*PasswordPolicy[[:space:]]*=[[:space:]]*"length\(([0-9]+)\).*$/\1/p' "$realm")"
[[ "$min_len" =~ ^[0-9]+$ ]] && [ "$min_len" -gt 0 ] \
	|| refuse "$realm has no PasswordPolicy line starting with length(N), so the deny list cannot be cut to the realm's minimum length."

raw="https://raw.githubusercontent.com"
source_file="${source_path##*/}"
source_url="$raw/${release%:*}/${release##*:}/$source_path"
licence_url="$raw/${release%:*}/${release##*:}/LICENSE"
origin_licence_url="$raw/${origin_release%:*}/${origin_release##*:}/LICENSE"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
if [ -n "$keep" ]; then
	mkdir -p "$keep"
	work="$keep"
else
	work="$stage/download"
	mkdir "$work"
fi

fetch_pinned "$work" "$source_file" "$source_url" "$source_sha256" fetch-denylist || exit 1
fetch_pinned "$work" SecLists-LICENSE "$licence_url" "$licence_sha256" fetch-denylist || exit 1
fetch_pinned "$work" Pwdb-Public-LICENSE "$origin_licence_url" "$origin_licence_sha256" fetch-denylist || exit 1

mkdir "$stage/password-blacklists" "$stage/licenses"
cut="$stage/password-blacklists/$list_name"
# LC_ALL=C: length() counts bytes.
LC_ALL=C awk -v n="$min_len" 'length($0) >= n' "$work/$source_file" >"$cut" \
	|| refuse "The deny list could not be cut from $work/$source_file."
kept="$(wc -l <"$cut" | tr -d ' ')"
[ "$kept" -gt 0 ] \
	|| refuse "No line of $source_file is $min_len bytes or longer, so the cut would be an empty deny list."
cp "$work/SecLists-LICENSE" "$work/Pwdb-Public-LICENSE" "$stage/licenses/" \
	|| refuse "The licence notices could not be copied."
chmod 0644 "$cut" "$stage/licenses/SecLists-LICENSE" "$stage/licenses/Pwdb-Public-LICENSE"

mkdir -p "$out" || refuse "The output directory $out could not be created."
for d in password-blacklists licenses; do
	rm -rf "${out:?}/$d.new"
	{ cp -R "$stage/$d" "$out/$d.new" && rm -rf "${out:?}/$d" && mv "$out/$d.new" "$out/$d"; } \
		|| refuse "$out/$d could not be written."
done
echo "fetch-denylist: $out/password-blacklists/$list_name holds the $kept passwords of $min_len bytes or more from ${release%:*} at ${release##*:}; the licence notices are in $out/licenses/"
