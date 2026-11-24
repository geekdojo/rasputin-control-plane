#!/usr/bin/env bash
#
# pack-identity.sh — build the identity service's release directory for the
# api tarball (geekdojo/geekdojo-brain#980; platform.md §2.5, §4).
#
# Usage: scripts/pack-identity.sh SRC PIN DEST DENYLIST [THEME]
#
#   SRC       the repository's identity/ directory: realm-baseline.json,
#             realm-baseline.lock and keycloak-build.conf
#   PIN       api/internal/identitytest/pin.go, the one pin
#   DEST      the directory to create, <dist>/identity
#   DENYLIST  scripts/fetch-denylist.sh's output directory: the password deny
#             list in password-blacklists/ and its notices in licenses/
#             (geekdojo/geekdojo-brain#1145)
#   THEME     optional: a built theme tree, copied into DEST/theme/ (Identity 4.6)
#
# DEST receives realm-baseline.json and keycloak-build.conf byte for byte at
# mode 0644, a pins.json generated from PIN (never committed, so it cannot lag a
# bump), password-blacklists/<DenylistFile> and licenses/ at 0644, and theme/,
# empty unless THEME is given. The lock is checked, not shipped. rasputin-os
# installs DEST under /usr/share/rasputin/identity/, and stages the deny list
# into the identity service's data directory on every start.
#
# Everything is checked before DEST is created:
#   - each keycloak-build.conf line is blank, a # comment, or key=value with
#     the key in the allowlist below. `kc.sh build` accepts an unknown key
#     silently (probed at 26.8.2: exit 0, no warning), so this is the only
#     check that catches a misspelt option;
#   - realm-baseline.lock holds exactly one armed-at= line (none or a v-tag)
#     and one sha256= line of 64 lowercase hex, and that hash is the
#     baseline's. A missing or malformed lock is refused, never read as
#     "nothing to compare";
#   - PIN holds KeycloakRelease, KCDistSHA256, JRERelease and
#     JRELinuxX64SHA256;
#   - DENYLIST holds a non-empty password-blacklists/<DenylistFile>, the name
#     read from api/internal/identity/flows/realm.go, and both notices, so no
#     tarball ships a realm policy naming a list it does not carry;
#   - THEME, when given, is a directory.
#
# Exit status: 0 packed; 1 an input is missing or refused, or a copy failed;
# 2 bad usage. Each failure prints one sentence on stderr.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=SCRIPTDIR/lib/release-lib.sh
. "$here/lib/release-lib.sh"

if [ "$#" -lt 4 ] || [ "$#" -gt 5 ] || [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ] || [ -z "$4" ] || { [ "$#" -eq 5 ] && [ -z "$5" ]; }; then
	echo "Usage: $0 SRC PIN DEST DENYLIST [THEME], where SRC is the identity/ directory, PIN is identitytest/pin.go, DEST is the directory to create, DENYLIST is fetch-denylist.sh's output and THEME a built theme tree." >&2
	exit 2
fi
src=$1 pin=$2 dest=$3 denylist=$4 theme=${5:-}

baseline="$src/realm-baseline.json"
conf="$src/keycloak-build.conf"
lock="$src/realm-baseline.lock"

for f in "$baseline" "$conf"; do
	if [ ! -f "$f" ]; then
		echo "The identity source $src has no $(basename "$f"), so the api tarball would ship without the identity service's $(basename "$f")." >&2
		exit 1
	fi
done

# The build options Keycloak's build accepts that the product sets
# (platform.md §2.3). A new option is added here in the same change that adds
# it to keycloak-build.conf.
allowed=" db transaction-xa-enabled health-enabled metrics-enabled event-metrics-user-enabled https-client-auth vault features-disabled "
n=0
while IFS= read -r line || [ -n "$line" ]; do
	n=$((n + 1))
	[[ "$line" =~ ^[[:space:]]*$ ]] && continue
	[[ "$line" =~ ^[[:space:]]*# ]] && continue
	if ! [[ "$line" =~ ^([A-Za-z0-9._-]+)=(.+)$ ]]; then
		echo "$conf line $n is not blank, a # comment or key=value, so the build options cannot be read." >&2
		exit 1
	fi
	key=${BASH_REMATCH[1]}
	if [[ "$allowed" != *" $key "* ]]; then
		echo "$conf line $n sets $key, which is not an allowed Keycloak build option; Keycloak ignores an unknown key silently, so this check is the only one that catches it." >&2
		exit 1
	fi
done <"$conf"

# The lock: fail closed on anything but exactly one well-formed line of each.
lock_refused() {
	echo "The baseline lock $lock $1, so the baseline cannot be checked against it and the pack refuses." >&2
	exit 1
}
[ -f "$lock" ] || lock_refused "is missing"
[ -s "$lock" ] || lock_refused "is empty"
armed_lines=0 sha_lines=0 armed_at="" locked=""
while IFS= read -r line || [ -n "$line" ]; do
	case "$line" in
	'' | '#'*) ;;
	armed-at=*) armed_lines=$((armed_lines + 1)) armed_at=${line#armed-at=} ;;
	sha256=*) sha_lines=$((sha_lines + 1)) locked=${line#sha256=} ;;
	*) lock_refused "holds a line that is not a comment, armed-at= or sha256=" ;;
	esac
done <"$lock"
[ "$armed_lines" -eq 1 ] || lock_refused "holds $armed_lines armed-at= lines, want exactly one"
[ "$sha_lines" -eq 1 ] || lock_refused "holds $sha_lines sha256= lines, want exactly one"
[[ "$armed_at" == none || "$armed_at" =~ ^v[0-9][0-9A-Za-z.+-]*$ ]] || lock_refused "has armed-at=$armed_at, want none or a v-tag"
[[ "$locked" =~ ^[0-9a-f]{64}$ ]] || lock_refused "has a sha256 that is not 64 lowercase hex characters"

got="$(sha256_of "$baseline")"
if [ "$got" != "$locked" ]; then
	if [ "$armed_at" = none ]; then
		echo "$baseline has sha256 $got but $lock records $locked; the baseline is not armed yet, so record the new hash in realm-baseline.lock in the same change." >&2
	else
		echo "$baseline has sha256 $got but $lock records $locked; the baseline was frozen at $armed_at, so restore the file and change the realm through a migration (Identity 3.5), and never edit the lock." >&2
	fi
	exit 1
fi

if [ ! -f "$pin" ]; then
	echo "The pin file $pin does not exist, so pins.json cannot be written." >&2
	exit 1
fi
read_pin() {
	local v
	v="$(pin_const "$pin" "$1")"
	if [ -z "$v" ]; then
		echo "The pin file $pin has no $1 constant, so pins.json cannot be written." >&2
		exit 1
	fi
	printf '%s' "$v"
}
kc_release="$(read_pin KeycloakRelease)"
kc_sha256="$(read_pin KCDistSHA256)"
jre_release="$(read_pin JRERelease)"
jre_sha256="$(read_pin JRELinuxX64SHA256)"

# The deny list the realm's policy names (geekdojo/geekdojo-brain#1145).
realm_go="$here/../api/internal/identity/flows/realm.go"
list_name="$(pin_const "$realm_go" DenylistFile)"
if [ -z "$list_name" ]; then
	echo "$realm_go has no DenylistFile constant, so the password deny list cannot be packed." >&2
	exit 1
fi
if [ ! -d "$denylist" ]; then
	echo "The deny list directory $denylist does not exist, so the api tarball would ship a password policy naming a list it does not carry." >&2
	exit 1
fi
list="$denylist/password-blacklists/$list_name"
if [ ! -f "$list" ] || [ ! -s "$list" ]; then
	echo "The password deny list $list is missing or empty, so the api tarball would ship a password policy naming a list it does not carry." >&2
	exit 1
fi
for f in SecLists-LICENSE Pwdb-Public-LICENSE; do
	if [ ! -f "$denylist/licenses/$f" ]; then
		echo "The deny list's licence notice $denylist/licenses/$f is missing, so the list cannot ship." >&2
		exit 1
	fi
done

if [ -n "$theme" ] && [ ! -d "$theme" ]; then
	echo "The theme $theme is not a directory, so it cannot fill the identity theme slot." >&2
	exit 1
fi

mkdir -p "$dest/theme"
for f in "$baseline" "$conf"; do
	if ! install -m 0644 "$f" "$dest/$(basename "$f")"; then
		echo "The identity file $f could not be copied into $dest." >&2
		exit 1
	fi
done
mkdir -p "$dest/password-blacklists" "$dest/licenses"
for f in "$list" "$denylist/licenses/SecLists-LICENSE" "$denylist/licenses/Pwdb-Public-LICENSE"; do
	to="$dest/licenses"
	[ "$f" = "$list" ] && to="$dest/password-blacklists"
	if ! install -m 0644 "$f" "$to/$(basename "$f")"; then
		echo "The deny list file $f could not be copied into $dest." >&2
		exit 1
	fi
done
jq -n \
	--arg kr "${kc_release##*:}" --arg ks "$kc_sha256" \
	--arg jr "${jre_release##*:}" --arg js "$jre_sha256" \
	'{keycloak: {release: $kr, sha256: $ks}, jre: {release: $jr, linux_x64_sha256: $js}}' >"$dest/pins.json"
chmod 0644 "$dest/pins.json"
if [ -n "$theme" ]; then
	if ! cp -R "$theme/." "$dest/theme/"; then
		echo "The theme $theme could not be copied into $dest/theme." >&2
		exit 1
	fi
fi
echo "   identity: realm-baseline.json, keycloak-build.conf, pins.json (Keycloak ${kc_release##*:}, JRE ${jre_release##*:}), password-blacklists/$list_name, licenses/, theme/${theme:+ from $theme}"
