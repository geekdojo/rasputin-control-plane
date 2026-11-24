# shellcheck shell=bash
#
# release-lib.sh — the pin reader, the hash helper and the pinned download the
# release and install scripts share (geekdojo/geekdojo-brain#980, #1145).
# Source it; it defines functions and runs nothing.
#
# Sourced by scripts/pack-identity.sh, scripts/build-release.sh,
# scripts/install-identity.sh, scripts/install-openbao.sh,
# scripts/fetch-denylist.sh and release.yml's "api tarballs carry the identity
# release" step. Its tests are TC-980-18 in scripts/test-pack-identity.sh and,
# for fetch_pinned, TC-1145-01 to TC-1145-05 in scripts/test-fetch-denylist.sh.

# pin_const FILE NAME prints the string value of `NAME = "value"` in the Go
# file FILE, anchored to a line of its own, so `NAMEX = ...` and a commented
# `// NAME = ...` never match. It prints nothing when no line matches.
pin_const() {
	sed -n -E 's/^[[:space:]]*'"$2"'[[:space:]]*=[[:space:]]*"([^"]+)"[[:space:]]*$/\1/p' "$1"
}

# sha256_of FILE prints FILE's sha256 as lowercase hex.
sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
	else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# fetch_pinned WORK FILE URL SHA256 TAG uses the kept WORK/FILE, or downloads
# URL to WORK/FILE.part and renames it to WORK/FILE, then checks the file
# against SHA256. A kept file gets the same check as a fresh download, and a
# file that fails it is refused and left in place, never replaced. TAG
# prefixes each line. Progress goes to stdout; a failure is one sentence on
# stderr and a return of 1, so the caller exits.
fetch_pinned() {
	local work="$1" file="$2" url="$3" sum="$4" tag="$5" rc=0 got
	if [ -f "$work/$file" ]; then
		echo "$tag: using the kept $work/$file"
	else
		echo "$tag: downloading $url"
		curl -fsL --retry 2 -o "$work/$file.part" "$url" || rc=$?
		if [ "$rc" -ne 0 ] || ! mv -f "$work/$file.part" "$work/$file"; then
			rm -f "$work/$file.part"
			echo "$tag: The download of $url failed (curl exit $rc), so $file was not fetched." >&2
			return 1
		fi
	fi
	got="$(sha256_of "$work/$file")"
	if [ "$got" != "$sum" ]; then
		echo "$tag: $work/$file has sha256 ${got:-that cannot be read}, not the pinned $sum, so it is refused; it is left in place, not replaced." >&2
		return 1
	fi
}
