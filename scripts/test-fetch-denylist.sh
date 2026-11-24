#!/usr/bin/env bash
#
# test-fetch-denylist.sh — tests for scripts/fetch-denylist.sh and the pinned
# download it shares with the installers, fetch_pinned in
# scripts/lib/release-lib.sh (geekdojo/geekdojo-brain#1145, TC-1145-01 to
# TC-1145-05), and the repository holding no list of its own (TC-1145-07's
# git ls-files half).
#
# Run:  ./scripts/test-fetch-denylist.sh
#
# The real fetch-denylist.sh and release-lib.sh run in a scratch copy of the
# repository layout, with a fixture pin.go whose hashes are the fixtures' and,
# per case, a fixture or the real realm.go. curl is a PATH stub that serves the
# fixtures by URL and counts its calls, or fails. No network.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
# shellcheck source=SCRIPTDIR/lib/release-lib.sh
. "$here/lib/release-lib.sh"

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT

failures=0
ok() { printf 'ok   %s\n' "$1"; }
fail() { printf 'FAIL %s\n%s\n' "$1" "${2:-}"; failures=$((failures + 1)); }
check() { if [ "$2" = 0 ]; then ok "$1"; else fail "$1" "${3:-}"; fi; }
yes_if() { if "$@"; then echo 0; else echo 1; fi; }

# --- the fixtures -----------------------------------------------------------
fx="$tmp/fixtures"
mkdir -p "$fx"
# The source: 14 and 15 ASCII bytes, a 16-character Cyrillic entry (32 bytes,
# 16 UTF-16 units), a 13-character one of 25 bytes, leading and trailing
# spaces, 12 bytes, and a last line with no newline.
{
	printf 'fourteen-bytes\n'
	printf 'fifteen-bytes!!\n'
	printf '\320\277\320\260\321\200\320\276\320\273\321\214-\320\277\320\260\321\200\320\276\320\273\321\214-\320\277\320\260\n'
	printf '\320\277\320\260\321\200\320\276\320\273\321\214-\320\277\320\260\321\200\320\276\320\273\321\214\n'
	printf '  leading-spaces\n'
	printf 'trailing-space  \n'
	printf 'twelve-bytes\n'
	printf 'eleven-byte\n'
	printf 'the-last-line-without-newline'
} >"$fx/source.txt"
# What length(15) keeps, written out rather than derived.
{
	printf 'fifteen-bytes!!\n'
	printf '\320\277\320\260\321\200\320\276\320\273\321\214-\320\277\320\260\321\200\320\276\320\273\321\214-\320\277\320\260\n'
	printf '\320\277\320\260\321\200\320\276\320\273\321\214-\320\277\320\260\321\200\320\276\320\273\321\214\n'
	printf '  leading-spaces\n'
	printf 'trailing-space  \n'
	printf 'the-last-line-without-newline\n'
} >"$fx/want-15.txt"
# And length(12): the 14-byte and 12-byte lines too, in source order.
{
	printf 'fourteen-bytes\n'
	cat "$fx/want-15.txt" | head -n 5
	printf 'twelve-bytes\n'
	printf 'the-last-line-without-newline\n'
} >"$fx/want-12.txt"
printf 'MIT License\n\nCopyright (c) SecLists fixture\n' >"$fx/seclists-license"
printf 'MIT License\n\nCopyright (c) Pwdb-Public fixture\n' >"$fx/pwdb-license"

src_sha="$(sha256_of "$fx/source.txt")"
lic_sha="$(sha256_of "$fx/seclists-license")"
origin_sha="$(sha256_of "$fx/pwdb-license")"
release="example/SecLists:aaaa1111"
origin="example/Pwdb-Public:bbbb2222"
src_url="https://raw.githubusercontent.com/example/SecLists/aaaa1111/Passwords/Fixture/fixture-source.txt"
lic_url="https://raw.githubusercontent.com/example/SecLists/aaaa1111/LICENSE"
origin_url="https://raw.githubusercontent.com/example/Pwdb-Public/bbbb2222/LICENSE"

# The served files, by URL; a case swaps one to serve other bytes.
served="$tmp/served"
key() { printf '%s' "$1" | tr '/:' '__'; }
serve_fixtures() {
	rm -rf "$served"; mkdir -p "$served"
	cp "$fx/source.txt" "$served/$(key "$src_url")"
	cp "$fx/seclists-license" "$served/$(key "$lic_url")"
	cp "$fx/pwdb-license" "$served/$(key "$origin_url")"
}

# The curl stub: `curl ... -o FILE URL`. It logs each call, fails with exit 22
# when $tmp/curl-fails exists, and otherwise copies the served file for URL.
mkdir -p "$tmp/bin"
cat >"$tmp/bin/curl" <<EOF
#!/usr/bin/env bash
echo "\$*" >>"$tmp/curl.log"
[ -e "$tmp/curl-fails" ] && exit 22
o="" url=""
while [ "\$#" -gt 0 ]; do
	case "\$1" in
		-o) o="\$2"; shift 2 ;;
		-*) shift ;;
		*) url="\$1"; shift ;;
	esac
done
f="$served/\$(printf '%s' "\$url" | tr '/:' '__')"
[ -f "\$f" ] || exit 22
cp "\$f" "\$o"
EOF
chmod 0755 "$tmp/bin/curl"
calls() { if [ -f "$tmp/curl.log" ]; then grep -c . "$tmp/curl.log"; else echo 0; fi; }

# repo REALM — a scratch repository with the real script and library, the
# fixture pin.go and REALM as flows/realm.go; prints its root.
pin_go() {
	cat <<EOF
package identitytest

const (
	DenylistRelease             = "$release"
	DenylistSourcePath          = "Passwords/Fixture/fixture-source.txt"
	DenylistSourceSHA256        = "$src_sha"
	DenylistLicenceSHA256       = "$lic_sha"
	DenylistOriginRelease       = "$origin"
	DenylistOriginLicenceSHA256 = "$origin_sha"
)
EOF
}
realm_go() { # N NAME — a fixture realm.go in the real file's const shape.
	cat <<EOF
package flows

const (
	DenylistFile = "$2"
	PasswordPolicy = "length($1) and maxLength(128) and passwordBlacklist(" + DenylistFile + ")"
)
EOF
}
n=0
repo() {
	n=$((n + 1))
	local r="$tmp/repo$n"
	mkdir -p "$r/scripts/lib" "$r/api/internal/identitytest" "$r/api/internal/identity/flows"
	cp "$here/fetch-denylist.sh" "$r/scripts/"
	cp "$here/lib/release-lib.sh" "$r/scripts/lib/"
	pin_go >"$r/api/internal/identitytest/pin.go"
	cp "$1" "$r/api/internal/identity/flows/realm.go"
	printf '%s' "$r"
}

# run REPO OUT [KEEP] — runs the script with the stub curl; sets RC and ERR
# (stderr).
run() {
	rm -f "$tmp/curl.log"
	local rc=0
	PATH="$tmp/bin:$PATH" "$1/scripts/fetch-denylist.sh" "${@:2}" >"$tmp/stdout" 2>"$tmp/stderr" || rc=$?
	RC=$rc ERR="$(cat "$tmp/stderr")"
}
one_sentence() { [ "$(printf '%s\n' "$ERR" | grep -c .)" = 1 ] && printf '%s' "$ERR" | grep -q '\.$'; }
empty_dir() { [ -d "$1" ] && [ -z "$(ls -A "$1")" ]; }

realm_go 15 fixture-list.txt >"$fx/realm-15.go"
realm_go 12 fixture-list.txt >"$fx/realm-12.go"
realm_go 500 fixture-list.txt >"$fx/realm-500.go"
grep -v 'PasswordPolicy' "$fx/realm-15.go" >"$fx/realm-no-length.go"
sed 's/"length(15) and /"maxLength(128) and length(15) and /' "$fx/realm-15.go" >"$fx/realm-length-not-first.go"
grep -v 'DenylistFile = ' "$fx/realm-15.go" >"$fx/realm-no-name.go"

# --- TC-1145-01: a source that does not match its pin ------------------------
serve_fixtures
printf 'not the pinned list\n' >"$served/$(key "$src_url")"
r="$(repo "$fx/realm-15.go")"
mkdir "$tmp/out01"
run "$r" "$tmp/out01"
check "TC-1145-01 a source whose sha256 differs: exit 1" "$(yes_if [ "$RC" = 1 ])" "rc=$RC $ERR"
check "TC-1145-01 one sentence on stderr, naming the pinned sha256" \
	"$({ one_sentence && grep -qF "not the pinned $src_sha" <<<"$ERR"; } && echo 0 || echo 1)" "$ERR"
check "TC-1145-01 nothing is written under OUT" "$(yes_if empty_dir "$tmp/out01")" "$(ls -lAR "$tmp/out01")"

# --- TC-1145-02: a licence that does not match its pin -----------------------
for which in seclists origin; do
	serve_fixtures
	case "$which" in
		seclists) printf 'another licence\n' >"$served/$(key "$lic_url")" ;;
		origin) printf 'another licence\n' >"$served/$(key "$origin_url")" ;;
	esac
	run "$r" "$tmp/out02-$which"
	check "TC-1145-02 a $which licence whose sha256 differs: exit 1 with one sentence" \
		"$({ [ "$RC" = 1 ] && one_sentence && grep -qF 'LICENSE has sha256' <<<"$ERR"; } && echo 0 || echo 1)" "rc=$RC $ERR"
	check "TC-1145-02 ($which) neither the list nor a licence is written (OUT not created)" "$(yes_if [ ! -e "$tmp/out02-$which" ])"
done

# --- TC-1145-03: kept downloads ---------------------------------------------
serve_fixtures
keep="$tmp/keep03"
run "$r" "$tmp/out03a" "$keep"
check "TC-1145-03 a first run with KEEP-DIR downloads three files and exits 0" \
	"$(yes_if [ "$RC" = 0 ] && [ "$(calls)" = 3 ])" "rc=$RC calls=$(calls) $ERR"
check "TC-1145-03 the downloads are kept by name, no .part left" \
	"$(yes_if [ "$(ls -1A "$keep" | tr '\n' ' ')" = "Pwdb-Public-LICENSE SecLists-LICENSE fixture-source.txt " ])" "$(ls -1A "$keep")"
touch "$tmp/curl-fails"
run "$r" "$tmp/out03b" "$keep"
check "TC-1145-03 with every download kept, a stub that fails if called is not called and the run exits 0" \
	"$(yes_if [ "$RC" = 0 ] && [ "$(calls)" = 0 ])" "rc=$RC calls=$(calls) $ERR"
check "TC-1145-03 the kept run writes the same list" \
	"$(yes_if cmp -s "$tmp/out03a/password-blacklists/fixture-list.txt" "$tmp/out03b/password-blacklists/fixture-list.txt")"
printf 'tampered\n' >>"$keep/fixture-source.txt"
before="$(sha256_of "$keep/fixture-source.txt")"
run "$r" "$tmp/out03c" "$keep"
check "TC-1145-03 a kept file that fails its check: exit 1 with one sentence, no download" \
	"$({ [ "$RC" = 1 ] && one_sentence && [ "$(calls)" = 0 ] && grep -qF 'left in place, not replaced' <<<"$ERR"; } && echo 0 || echo 1)" "rc=$RC $ERR"
check "TC-1145-03 the refused kept file is still there, byte for byte" "$(yes_if [ "$(sha256_of "$keep/fixture-source.txt")" = "$before" ])"
check "TC-1145-03 nothing is written under OUT" "$(yes_if [ ! -e "$tmp/out03c" ])"
rm -f "$tmp/curl-fails"

# --- TC-1145-04: the cut, one source for N and the name ------------------------
serve_fixtures
run "$r" "$tmp/out04"
list="$tmp/out04/password-blacklists/fixture-list.txt"
check "TC-1145-04 length(15): exit 0" "$(yes_if [ "$RC" = 0 ])" "rc=$RC $ERR"
check "TC-1145-04 length(15): the list holds exactly the source's lines of 15 bytes or more, in order, LF-terminated" \
	"$(yes_if cmp -s "$fx/want-15.txt" "$list")" "$(od -c "$list" 2>&1 | head -20)"
check "TC-1145-04 the file's name is DenylistFile's, and it is alone" \
	"$(yes_if [ "$(ls -1A "$tmp/out04/password-blacklists")" = fixture-list.txt ])" "$(ls -1A "$tmp/out04/password-blacklists")"
check "TC-1145-04 no CR in the list (od)" "$(yes_if [ -z "$(od -An -c "$list" | grep -F '\r')" ])"
check "TC-1145-04 the list and both notices are 0644" \
	"$(yes_if [ -n "$(find "$list" -perm 0644)" ] && [ "$(find "$tmp/out04/licenses" -type f -perm 0644 | grep -c .)" = 2 ])"
check "TC-1145-04 the notices are the pinned bytes" \
	"$(yes_if cmp -s "$fx/seclists-license" "$tmp/out04/licenses/SecLists-LICENSE" && cmp -s "$fx/pwdb-license" "$tmp/out04/licenses/Pwdb-Public-LICENSE")"
check "TC-1145-04 OUT holds the two directories alone" \
	"$(yes_if [ "$(ls -1A "$tmp/out04" | tr '\n' ' ')" = "licenses password-blacklists " ])" "$(ls -1A "$tmp/out04")"
r12="$(repo "$fx/realm-12.go")"
run "$r12" "$tmp/out04-12"
check "TC-1145-04 length(12): the cut moves to 12" \
	"$(yes_if [ "$RC" = 0 ] && cmp -s "$fx/want-12.txt" "$tmp/out04-12/password-blacklists/fixture-list.txt")" "rc=$RC $ERR"
# A second run replaces an earlier list rather than merging into it.
r15b="$(repo "$fx/realm-15.go")"
run "$r15b" "$tmp/out04-12"
check "TC-1145-04 a rerun at length(15) over the length(12) output replaces it" \
	"$(yes_if [ "$RC" = 0 ] && cmp -s "$fx/want-15.txt" "$tmp/out04-12/password-blacklists/fixture-list.txt")" "rc=$RC $ERR"
# The real realm.go: its anchored lines give N 15 and the shipped name.
rr="$(repo "$root/api/internal/identity/flows/realm.go")"
run "$rr" "$tmp/out04-real"
real_name="$(pin_const "$root/api/internal/identity/flows/realm.go" DenylistFile)"
check "TC-1145-04 the real realm.go cuts at 15 into $real_name" \
	"$(yes_if [ "$RC" = 0 ] && [ -n "$real_name" ] && cmp -s "$fx/want-15.txt" "$tmp/out04-real/password-blacklists/$real_name")" "rc=$RC $ERR"

# --- TC-1145-05: refusals ----------------------------------------------------
refused() { # NAME REALM WANT_TEXT — exit 1, one sentence holding WANT_TEXT, OUT not created.
	serve_fixtures
	local rx
	rx="$(repo "$2")"
	run "$rx" "$tmp/out05"
	check "TC-1145-05 $1: exit 1 with one sentence" \
		"$({ [ "$RC" = 1 ] && one_sentence && grep -qF -- "$3" <<<"$ERR"; } && echo 0 || echo 1)" "rc=$RC $ERR"
	check "TC-1145-05 $1: no output under OUT" "$(yes_if [ ! -e "$tmp/out05" ])" "$(ls -lAR "$tmp/out05" 2>&1)"
	rm -rf "$tmp/out05"
}
refused "a cut that keeps no line (length(500))" "$fx/realm-500.go" "would be an empty deny list"
refused "a realm.go without length(N)" "$fx/realm-no-length.go" "has no PasswordPolicy line starting with length(N)"
refused "a realm.go whose policy does not start with length(N)" "$fx/realm-length-not-first.go" "has no PasswordPolicy line starting with length(N)"
refused "a realm.go without DenylistFile" "$fx/realm-no-name.go" "has no DenylistFile constant"
touch "$tmp/curl-fails"
refused "a download that fails" "$fx/realm-15.go" "failed (curl exit 22)"
rm -f "$tmp/curl-fails"
check "TC-1145-05 a failed download leaves no .part behind (no KEEP-DIR: the temporary directory is gone)" \
	"$(yes_if [ -z "$(find "$tmp" -name '*.part')" ])" "$(find "$tmp" -name '*.part')"
# Usage.
rc=0; "$here/fetch-denylist.sh" >/dev/null 2>&1 || rc=$?
check "TC-1145-05 no arguments: exit 2" "$(yes_if [ "$rc" = 2 ])" "rc=$rc"
rc=0; "$here/fetch-denylist.sh" "$tmp/a" "$tmp/b" "$tmp/c" >/dev/null 2>&1 || rc=$?
check "TC-1145-05 three arguments: exit 2" "$(yes_if [ "$rc" = 2 ])" "rc=$rc"

# --- fetch_pinned on its own: kept, downloaded, refused --------------------------
serve_fixtures
w="$tmp/fp"; mkdir -p "$w"
rc=0; PATH="$tmp/bin:$PATH" fetch_pinned "$w" a.txt "$lic_url" "$lic_sha" t >/dev/null 2>"$tmp/fp.err" || rc=$?
check "fetch_pinned downloads, renames and accepts a matching file" "$(yes_if [ "$rc" = 0 ] && cmp -s "$fx/seclists-license" "$w/a.txt" && [ ! -e "$w/a.txt.part" ])" "rc=$rc $(cat "$tmp/fp.err")"
rc=0; PATH="$tmp/bin:$PATH" fetch_pinned "$w" a.txt "$lic_url" "$origin_sha" t >/dev/null 2>"$tmp/fp.err" || rc=$?
check "fetch_pinned refuses a kept file against another sha256 and leaves it" "$(yes_if [ "$rc" = 1 ] && [ -f "$w/a.txt" ])" "rc=$rc"

# --- TC-1145-07 (the repository half): no list is kept by hand ------------------
if git -C "$root" rev-parse --git-dir >/dev/null 2>&1; then
	kept="$(git -C "$root" ls-files | grep -E '(^|/)password-blacklists/' || true)"
	check "TC-1145-07 git ls-files lists no file under any password-blacklists/ path" "$(yes_if [ -z "$kept" ])" "$kept"
else
	fail "TC-1145-07 the repository's file list could not be read" "git -C $root ls-files"
fi

echo
if [ "$failures" -ne 0 ]; then echo "test-fetch-denylist: $failures failure(s)"; exit 1; fi
echo "test-fetch-denylist: all passed"
