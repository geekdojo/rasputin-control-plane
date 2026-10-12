#!/usr/bin/env bash
#
# test-pack-store-policy.sh — tests for scripts/pack-store-policy.sh
# (geekdojo/geekdojo-brain#804, TC-804-09).
#
# Run:  ./scripts/test-pack-store-policy.sh
#
# Packs the real api/internal/secretstore/storepolicy and checks every file
# arrives byte-equal at 0644 with nothing extra; then checks a source with no
# .hcl, a missing source and bad usage are each refused with a sentence and
# create nothing. No network.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
PACK="${PACK:-$here/pack-store-policy.sh}"
SRC="$here/../api/internal/secretstore/storepolicy"

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT

failures=0
ok() { printf 'ok   %s\n' "$1"; }
fail() { printf 'FAIL %s\n%s\n' "$1" "${2:-}"; failures=$((failures + 1)); }

# --- the real source: byte-equal, 0644, nothing extra --------------------------
out="$("$PACK" "$SRC" "$tmp/real/openbao-policy" 2>&1)" && rc=0 || rc=$?
if [ "$rc" = 0 ]; then ok "packing the real storepolicy/ exits 0"; else fail "packing the real storepolicy/ exits 0 (got $rc)" "$out"; fi
want="$(cd "$SRC" && ls -1 -- *.hcl)"
got="$(cd "$tmp/real/openbao-policy" && ls -1A)"
if [ -n "$want" ] && [ "$got" = "$want" ]; then ok "openbao-policy/ holds exactly storepolicy/'s .hcl files ($(echo "$want" | tr '\n' ' '))"
else fail "openbao-policy/ holds exactly storepolicy/'s .hcl files" "want: $want got: $got"; fi
for name in rasputin-api.hcl rasputin-seal-rotate.hcl; do
	if [ -f "$tmp/real/openbao-policy/$name" ]; then ok "openbao-policy/$name is packed"; else fail "openbao-policy/$name is packed"; fi
done
for f in "$SRC"/*.hcl; do
	n="$(basename "$f")"
	if cmp -s "$f" "$tmp/real/openbao-policy/$n"; then ok "$n is byte-equal"; else fail "$n is byte-equal"; fi
	# find -perm with no prefix matches the exact mode.
	if [ -n "$(find "$tmp/real/openbao-policy/$n" -perm 0644)" ]; then ok "$n is 0644"; else fail "$n is 0644"; fi
done

# --- refusals: a sentence, exit status, nothing created -------------------------
# refused NAME WANT_RC WANT_TEXT ARGS... — the pack exits WANT_RC, stderr holds
# WANT_TEXT, and $tmp/out was not created.
refused() {
	local name="$1" want_rc="$2" want_text="$3"
	shift 3
	local rc=0 out
	out="$("$PACK" "$@" 2>&1)" || rc=$?
	if [ "$rc" != "$want_rc" ]; then fail "$name: exit $rc, want $want_rc" "$out"
	elif ! grep -qF -- "$want_text" <<<"$out"; then fail "$name: output lacks '$want_text'" "$out"
	elif [ -e "$tmp/out" ]; then fail "$name: the destination was created"
	else ok "$name: exit $want_rc, '$want_text'"; fi
	rm -rf "$tmp/out"
}
mkdir -p "$tmp/empty" "$tmp/nohcl"
echo 'not a policy' > "$tmp/nohcl/README.md"
refused "an empty source" 1 "The policy source $tmp/empty holds no .hcl file, so the api tarball would ship without the store's policy text." "$tmp/empty" "$tmp/out"
refused "a source with no .hcl" 1 "The policy source $tmp/nohcl holds no .hcl file" "$tmp/nohcl" "$tmp/out"
refused "a missing source" 1 "The policy source $tmp/none holds no .hcl file" "$tmp/none" "$tmp/out"
refused "one argument" 2 "Usage: " "$SRC"
refused "an empty destination" 2 "Usage: " "$SRC" ""

echo
if [ "$failures" -ne 0 ]; then echo "test-pack-store-policy: $failures failure(s)"; exit 1; fi
echo "test-pack-store-policy: all passed"
