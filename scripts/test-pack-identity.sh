#!/usr/bin/env bash
#
# test-pack-identity.sh — tests for scripts/pack-identity.sh, the realm
# baseline it ships, and scripts/lib/release-lib.sh
# (geekdojo/geekdojo-brain#980, TC-980-01 to TC-980-18).
#
# Run:  ./scripts/test-pack-identity.sh
#
# Packs the real identity/ and pin.go and checks the four entries; checks every
# refusal exits with a sentence and creates nothing; checks the baseline's
# cluster-independent settings with jq, each assertion also failing on a
# negative fixture where the test case names one. Needs jq. No network.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
PACK="${PACK:-$here/pack-identity.sh}"
SRC="$root/identity"
PIN="$root/api/internal/identitytest/pin.go"
BASE="$SRC/realm-baseline.json"
# shellcheck source=SCRIPTDIR/lib/release-lib.sh
. "$here/lib/release-lib.sh"

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT

failures=0
ok() { printf 'ok   %s\n' "$1"; }
fail() { printf 'FAIL %s\n%s\n' "$1" "${2:-}"; failures=$((failures + 1)); }

# packs NAME ARGS... — the pack exits 0 and $tmp/out exists; removes it after.
packs() {
	local name="$1" rc=0 out
	shift
	out="$("$PACK" "$@" 2>&1)" || rc=$?
	if [ "$rc" = 0 ] && [ -d "$tmp/out" ]; then ok "$name: exit 0"; else fail "$name: exit $rc, want 0" "$out"; fi
	rm -rf "$tmp/out"
}

# refused NAME WANT_RC WANT_TEXT ARGS... — the pack exits WANT_RC, its output
# holds WANT_TEXT, and $tmp/out was not created.
refused() {
	local name="$1" want_rc="$2" want_text="$3" rc=0 out
	shift 3
	out="$("$PACK" "$@" 2>&1)" || rc=$?
	if [ "$rc" != "$want_rc" ]; then fail "$name: exit $rc, want $want_rc" "$out"
	elif ! grep -qF -- "$want_text" <<<"$out"; then fail "$name: output lacks '$want_text'" "$out"
	elif [ -e "$tmp/out" ]; then fail "$name: the destination was created"
	else ok "$name: exit $want_rc, '$want_text'"; fi
	rm -rf "$tmp/out"
}

# fixture NAME — a copy of the real identity/ at $tmp/NAME, printed.
fixture() {
	rm -rf "${tmp:?}/$1"
	cp -R "$SRC" "$tmp/$1"
	printf '%s' "$tmp/$1"
}

# holds NAME FILE JQ — jq -e JQ over FILE is true.
holds() {
	if jq -e "$3" "$2" >/dev/null 2>&1; then ok "$1"; else fail "$1" "jq: $3"; fi
}

# rejects NAME FILE JQ — jq -e JQ over the negative fixture FILE is false.
rejects() {
	if jq -e "$3" "$2" >/dev/null 2>&1; then fail "$1: the negative fixture passed" "jq: $3"; else ok "$1"; fi
}

# --- TC-980-01: the real identity/ packs to exactly the four entries ----------
out="$("$PACK" "$SRC" "$PIN" "$tmp/real/identity" 2>&1)" && rc=0 || rc=$?
if [ "$rc" = 0 ]; then ok "TC-980-01 packing the real identity/ exits 0"; else fail "TC-980-01 packing the real identity/ exits 0 (got $rc)" "$out"; fi
got="$(cd "$tmp/real/identity" && ls -1A | tr '\n' ' ')"
want="keycloak-build.conf pins.json realm-baseline.json theme "
if [ "$got" = "$want" ]; then ok "TC-980-01 identity/ holds exactly: $want"; else fail "TC-980-01 identity/ holds exactly the four entries" "got: $got"; fi
if [ -d "$tmp/real/identity/theme" ] && [ -z "$(ls -A "$tmp/real/identity/theme")" ]; then ok "TC-980-01 theme/ is an empty directory"; else fail "TC-980-01 theme/ is an empty directory"; fi
for n in realm-baseline.json keycloak-build.conf; do
	if cmp -s "$SRC/$n" "$tmp/real/identity/$n"; then ok "TC-980-01 $n is byte-equal"; else fail "TC-980-01 $n is byte-equal"; fi
	# find -perm with no prefix matches the exact mode.
	if [ -n "$(find "$tmp/real/identity/$n" -perm 0644)" ]; then ok "TC-980-01 $n is 0644"; else fail "TC-980-01 $n is 0644"; fi
done
if [ "$(sed -n 's/^sha256=//p' "$SRC/realm-baseline.lock")" = "$(sha256_of "$BASE")" ]; then ok "TC-980-01 the real lock matches the real baseline"
else fail "TC-980-01 the real lock matches the real baseline" "record the baseline's sha256 in identity/realm-baseline.lock"; fi

# --- TC-980-02: the theme slot ------------------------------------------------
mkdir -p "$tmp/theme/login/resources/css"
printf 'body{}\n' >"$tmp/theme/login/resources/css/a.css"
printf 'parent=base\n' >"$tmp/theme/login/theme.properties"
out="$("$PACK" "$SRC" "$PIN" "$tmp/out" "$tmp/theme" 2>&1)" && rc=0 || rc=$?
if [ "$rc" = 0 ] && diff -r "$tmp/theme" "$tmp/out/theme" >/dev/null; then ok "TC-980-02 a nested THEME tree is copied byte-equal into theme/"
else fail "TC-980-02 a nested THEME tree is copied byte-equal into theme/ (exit $rc)" "$out"; fi
rm -rf "$tmp/out"
printf 'x' >"$tmp/theme-file"
refused "TC-980-02 THEME naming a regular file" 1 "The theme $tmp/theme-file is not a directory" "$SRC" "$PIN" "$tmp/out" "$tmp/theme-file"
refused "TC-980-02 THEME naming a missing path" 1 "The theme $tmp/no-theme is not a directory" "$SRC" "$PIN" "$tmp/out" "$tmp/no-theme"

# --- TC-980-03: pins.json content -----------------------------------------------
cat >"$tmp/pin.go" <<'EOF'
package identitytest

const (
	KeycloakRelease = "keycloak/keycloak:1.2.3"
	KCDistSHA256    = "aaaa"

	JRERelease        = "adoptium/temurin9-binaries:9.0.1+2"
	JRELinuxX64SHA256 = "bbbb"
)
EOF
out="$("$PACK" "$SRC" "$tmp/pin.go" "$tmp/out" 2>&1)" && rc=0 || rc=$?
want='{"jre":{"linux_x64_sha256":"bbbb","release":"9.0.1+2"},"keycloak":{"release":"1.2.3","sha256":"aaaa"}}'
got="$(jq -cS . "$tmp/out/pins.json" 2>&1 || true)"
if [ "$rc" = 0 ] && [ "$got" = "$want" ]; then ok "TC-980-03 a fixture pin.go gives exactly $want"; else fail "TC-980-03 a fixture pin.go gives the exact pins.json (exit $rc)" "got: $got $out"; fi
rm -rf "$tmp/out"
# A Keycloak bump changes this together with capability rows T71 and T73.
got="$(jq -r .keycloak.release "$tmp/real/identity/pins.json")"
if [ "$got" = "26.8.2" ]; then ok "TC-980-03 the real pin.go gives keycloak.release 26.8.2"; else fail "TC-980-03 the real pin.go gives keycloak.release 26.8.2" "got: $got"; fi

# --- TC-980-04: a missing pin fails closed --------------------------------------
for c in KCDistSHA256 KeycloakRelease JRERelease JRELinuxX64SHA256; do
	grep -v "^[[:space:]]*${c}[[:space:]]" "$tmp/pin.go" >"$tmp/pin-no-$c.go"
	refused "TC-980-04 pin.go without $c" 1 "The pin file $tmp/pin-no-$c.go has no $c constant" "$SRC" "$tmp/pin-no-$c.go" "$tmp/out"
done
refused "TC-980-04 a PIN path that does not exist" 1 "The pin file $tmp/none.go does not exist" "$SRC" "$tmp/none.go" "$tmp/out"

# --- TC-980-05: the build-option allowlist ---------------------------------------
s="$(fixture bad-key)"
echo 'featurs-disabled=account' >>"$s/keycloak-build.conf"
refused "TC-980-05 an unknown key featurs-disabled" 1 "sets featurs-disabled, which is not an allowed Keycloak build option; Keycloak ignores an unknown key silently" "$s" "$PIN" "$tmp/out"
for k in db transaction-xa-enabled health-enabled metrics-enabled event-metrics-user-enabled https-client-auth vault features-disabled; do
	s="$(fixture "key-$k")"
	grep "^$k=" "$SRC/keycloak-build.conf" >"$s/keycloak-build.conf"
	packs "TC-980-05 the allowed key $k alone" "$s" "$PIN" "$tmp/out"
done

# --- TC-980-06: conf syntax ----------------------------------------------------------
s="$(fixture syntax)"
printf 'db=postgres\nvault=file\ndb postgres\n' >"$s/keycloak-build.conf"
refused "TC-980-06 a line without = at line 3" 1 "keycloak-build.conf line 3 is not blank, a # comment or key=value" "$s" "$PIN" "$tmp/out"
s="$(fixture comments)"
printf '# build options\ndb=postgres\n\n  # indented comment\n   \nvault=file\n' >"$s/keycloak-build.conf"
packs "TC-980-06 blank lines and # comments between valid lines" "$s" "$PIN" "$tmp/out"

# --- TC-980-07: missing inputs ----------------------------------------------------------
for f in realm-baseline.json keycloak-build.conf; do
	s="$(fixture "missing-$f")"
	rm "$s/$f"
	refused "TC-980-07 SRC without $f" 1 "so the api tarball would ship without the identity service's $f." "$s" "$PIN" "$tmp/out"
done

# --- TC-980-08: usage ---------------------------------------------------------------------
refused "TC-980-08 no arguments" 2 "Usage: "
refused "TC-980-08 one argument" 2 "Usage: " "$SRC"
refused "TC-980-08 two arguments" 2 "Usage: " "$SRC" "$PIN"
refused "TC-980-08 five arguments" 2 "Usage: " "$SRC" "$PIN" "$tmp/out" "$tmp/theme" extra
refused "TC-980-08 an empty SRC" 2 "Usage: " "" "$PIN" "$tmp/out"
refused "TC-980-08 an empty PIN" 2 "Usage: " "$SRC" "" "$tmp/out"
refused "TC-980-08 an empty DEST" 2 "Usage: " "$SRC" "$PIN" ""
refused "TC-980-08 an empty THEME" 2 "Usage: " "$SRC" "$PIN" "$tmp/out" ""

# --- TC-980-09: before arming --------------------------------------------------------------
old="$(sha256_of "$BASE")"
s="$(fixture pre-arm)"
printf 'armed-at=none\nsha256=%s\n' "$old" >"$s/realm-baseline.lock"
packs "TC-980-09 the unedited baseline with armed-at=none" "$s" "$PIN" "$tmp/out"
printf ' ' >>"$s/realm-baseline.json"
refused "TC-980-09 an edited baseline with armed-at=none" 1 "the baseline is not armed yet, so record the new hash in realm-baseline.lock in the same change." "$s" "$PIN" "$tmp/out"
printf 'armed-at=none\nsha256=%s\n' "$(sha256_of "$s/realm-baseline.json")" >"$s/realm-baseline.lock"
packs "TC-980-09 the edited baseline with its new hash locked" "$s" "$PIN" "$tmp/out"

# --- TC-980-10: after arming ----------------------------------------------------------------
s="$(fixture armed)"
printf 'armed-at=v0.0.0\nsha256=%s\n' "$old" >"$s/realm-baseline.lock"
packs "TC-980-10 the unedited baseline with armed-at=v0.0.0" "$s" "$PIN" "$tmp/out"
printf ' ' >>"$s/realm-baseline.json"
refused "TC-980-10 an edited baseline frozen at v0.0.0" 1 "the baseline was frozen at v0.0.0, so restore the file and change the realm through a migration (Identity 3.5), and never edit the lock." "$s" "$PIN" "$tmp/out"

# --- TC-980-11: the lock fails closed ------------------------------------------------------
s="$(fixture lock-missing)"; rm "$s/realm-baseline.lock"
refused "TC-980-11 a missing lock" 1 "The baseline lock $s/realm-baseline.lock is missing" "$s" "$PIN" "$tmp/out"
s="$(fixture lock-empty)"; : >"$s/realm-baseline.lock"
refused "TC-980-11 an empty lock" 1 "The baseline lock $s/realm-baseline.lock is empty" "$s" "$PIN" "$tmp/out"
s="$(fixture lock-no-sha)"; printf 'armed-at=none\n' >"$s/realm-baseline.lock"
refused "TC-980-11 a lock with no sha256= line" 1 "holds 0 sha256= lines, want exactly one" "$s" "$PIN" "$tmp/out"
s="$(fixture lock-bad-sha)"; printf 'armed-at=none\nsha256=%s\n' "$(printf '%s' "$old" | tr 'a-f' 'A-F')" >"$s/realm-baseline.lock"
refused "TC-980-11 a lock with a non-hex sha256" 1 "has a sha256 that is not 64 lowercase hex characters" "$s" "$PIN" "$tmp/out"
s="$(fixture lock-no-armed)"; printf 'sha256=%s\n' "$old" >"$s/realm-baseline.lock"
refused "TC-980-11 a lock with no armed-at= line" 1 "holds 0 armed-at= lines, want exactly one" "$s" "$PIN" "$tmp/out"

# --- TC-980-12: the realm settings ----------------------------------------------------------
holds "TC-980-12 realm is rasputin" "$BASE" '.realm == "rasputin"'
holds "TC-980-12 sslRequired is all" "$BASE" '.sslRequired == "all"'
holds "TC-980-12 editUsernameAllowed is false" "$BASE" '.editUsernameAllowed == false'
holds "TC-980-12 internationalizationEnabled is false" "$BASE" '.internationalizationEnabled == false'
holds "TC-980-12 defaultRole holds no role" "$BASE" \
	'.defaultRole.name as $n | ($n | type) == "string" and .defaultRole.composite == false and (.defaultRole.composites == null)
	 and ([.roles.realm[]? | select(.name == $n)] | length == 0) and ((.defaultRoles // []) | length == 0)'
holds "TC-980-12 offline_access is in no default role" "$BASE" '[.defaultRole, .defaultRoles | .. | strings | select(. == "offline_access")] | length == 0'
holds "TC-980-12 bruteForceProtected is true" "$BASE" '.bruteForceProtected == true'
holds "TC-980-12 failureFactor is 100" "$BASE" '.failureFactor == 100'
holds "TC-980-12 maxDeltaTimeSeconds (the window) is 43200" "$BASE" '.maxDeltaTimeSeconds == 43200'
holds "TC-980-12 quickLoginCheckMilliSeconds is 0 (the quick-login check off)" "$BASE" '.quickLoginCheckMilliSeconds == 0'
holds "TC-980-12 accessCodeLifespanLogin is 1800" "$BASE" '.accessCodeLifespanLogin == 1800'
holds "TC-980-12 accessCodeLifespanUserAction is 1800" "$BASE" '.accessCodeLifespanUserAction == 1800'
holds "TC-980-12 webAuthnPolicyRpId is blank" "$BASE" '.webAuthnPolicyRpId == ""'
holds "TC-980-12 webAuthnPolicyPasswordlessRpId is blank" "$BASE" '.webAuthnPolicyPasswordlessRpId == ""'
holds "TC-980-12 webAuthnPolicyUserVerificationRequirement is required" "$BASE" '.webAuthnPolicyUserVerificationRequirement == "required"'
holds "TC-980-12 webAuthnPolicyPasswordlessUserVerificationRequirement is required" "$BASE" '.webAuthnPolicyPasswordlessUserVerificationRequirement == "required"'
holds "TC-980-12 webAuthnPolicyPasswordlessResidentKey is lowercase required" "$BASE" '.webAuthnPolicyPasswordlessResidentKey == "required"'
holds "TC-980-12 eventsEnabled is true" "$BASE" '.eventsEnabled == true'
holds "TC-980-12 eventsListeners is a list without jboss-logging" "$BASE" '(.eventsListeners | type) == "array" and (any(.eventsListeners[]; . == "jboss-logging") | not)'

# --- TC-980-13: the client skeletons -------------------------------------------------------------
own="rasputin-console rasputin-account rasputin-reset-home rasputin-reset-app rasputin-admin"
for c in $own rasputin-mesh; do
	cl=".clients[] | select(.clientId == \"$c\")"
	holds "TC-980-13 $c exists once" "$BASE" "[$cl] | length == 1"
	holds "TC-980-13 $c publicClient is false" "$BASE" "$cl | .publicClient == false"
	holds "TC-980-13 $c has no redirectUris" "$BASE" "$cl | (.redirectUris // []) | length == 0"
	holds "TC-980-13 $c has no secret" "$BASE" "$cl | has(\"secret\") | not"
	holds "TC-980-13 $c has no adminUrl" "$BASE" "$cl | has(\"adminUrl\") | not"
	for f in fullScopeAllowed consentRequired frontchannelLogout directAccessGrantsEnabled implicitFlowEnabled; do
		holds "TC-980-13 $c $f is false" "$BASE" "$cl | .$f == false"
	done
	if [ "$c" = rasputin-admin ]; then sa=true std=false; else sa=false std=true; fi
	holds "TC-980-13 $c serviceAccountsEnabled is $sa" "$BASE" "$cl | .serviceAccountsEnabled == $sa"
	holds "TC-980-13 $c standardFlowEnabled is $std" "$BASE" "$cl | .standardFlowEnabled == $std"
done
for c in $own; do
	cl=".clients[] | select(.clientId == \"$c\")"
	holds "TC-980-13 $c authenticates by client-x509" "$BASE" "$cl | .clientAuthenticatorType == \"client-x509\""
	holds "TC-980-13 $c x509.subjectdn is CN=rasputin-api,O=Rasputin" "$BASE" "$cl | .attributes[\"x509.subjectdn\"] == \"CN=rasputin-api,O=Rasputin\""
	holds "TC-980-13 $c x509.allow.regex.pattern.comparison is \"false\"" "$BASE" "$cl | .attributes[\"x509.allow.regex.pattern.comparison\"] == \"false\""
done
for c in rasputin-console rasputin-account rasputin-mesh; do
	holds "TC-980-13 $c requires PKCE S256" "$BASE" ".clients[] | select(.clientId == \"$c\") | .attributes[\"pkce.code.challenge.method\"] == \"S256\""
done
holds "TC-980-13 rasputin-mesh authenticates by client-secret" "$BASE" '.clients[] | select(.clientId == "rasputin-mesh") | .clientAuthenticatorType == "client-secret"'
holds "TC-980-13 rasputin-mesh carries no secret value" "$BASE" '.clients[] | select(.clientId == "rasputin-mesh") | (has("secret") | not) and ([.attributes // {} | keys[] | select(test("secret"))] | length == 0)'
holds "TC-980-13 rasputin-mesh builds groups from rasputin_app_role" "$BASE" \
	'.clients[] | select(.clientId == "rasputin-mesh") | any(.protocolMappers[]; .config["claim.name"] == "groups" and .config["user.attribute"] == "rasputin_app_role")'
holds "TC-980-13 rasputin-console holds client roles admin, operator, viewer" "$BASE" '[.roles.client["rasputin-console"][].name] | sort == ["admin", "operator", "viewer"]'
holds "TC-980-13 rasputin-console's default scopes carry rasputin-console-roles" "$BASE" '.clients[] | select(.clientId == "rasputin-console") | .defaultClientScopes | index("rasputin-console-roles") != null'
holds "TC-980-13 client scope rasputin-console-roles exists" "$BASE" 'any(.clientScopes[]; .name == "rasputin-console-roles")'
# F-980-11: identity-authz.md §3.1 names the claim the api authorizes on rasputin_roles.
holds "TC-980-13 rasputin-console-roles emits the console roles as claim rasputin_roles" "$BASE" \
	'.clientScopes[] | select(.name == "rasputin-console-roles") | any(.protocolMappers[]; .protocolMapper == "oidc-usermodel-client-role-mapper" and .config["usermodel.clientRoleMapping.clientId"] == "rasputin-console" and .config["claim.name"] == "rasputin_roles")'
# F-980-10: a baseline that declares clientScopes stops Keycloak's import creating the
# built-in scopes (basic, profile, email) unless this realm attribute is "true"
# (RealmManager.java at 26.8.2), and the clients' references to them are dropped silently.
holds "TC-980-13 realm attribute CreateDefaultClientScopes is \"true\" (the built-in scopes are created on import)" "$BASE" '.attributes.CreateDefaultClientScopes == "true"'

# --- TC-980-14: the admin client's roles, set-equal to the eight -----------------------------------
admin_roles='([.users[] | select(.serviceAccountClientId == "rasputin-admin")]) as $sa
	| ($sa | length == 1)
	and (($sa[0].clientRoles | keys) == ["realm-management"])
	and (($sa[0].clientRoles["realm-management"] | sort) == (["manage-users", "view-users", "query-users", "query-groups", "manage-clients", "view-realm", "manage-realm", "view-events"] | sort))
	and (($sa[0].realmRoles // []) | length == 0)
	and ([.. | strings | select(. == "realm-admin")] + [paths | .[] | strings | select(. == "realm-admin")] | length == 0)'
holds "TC-980-14 rasputin-admin's service account holds exactly the eight realm-management roles, no realm role, and realm-admin is nowhere" "$BASE" "$admin_roles"
jq '(.users[] | select(.serviceAccountClientId == "rasputin-admin") | .clientRoles["realm-management"]) -= ["manage-users"]' "$BASE" >"$tmp/no-manage-users.json"
rejects "TC-980-14 a fixture missing manage-users fails" "$tmp/no-manage-users.json" "$admin_roles"
jq '(.users[] | select(.serviceAccountClientId == "rasputin-admin") | .clientRoles["realm-management"]) += ["realm-admin"]' "$BASE" >"$tmp/realm-admin.json"
rejects "TC-980-14 a fixture adding realm-admin fails" "$tmp/realm-admin.json" "$admin_roles"

# --- TC-980-15: the default clients are disabled -------------------------------------------------------
for c in account account-console admin-cli broker security-admin-console; do
	holds "TC-980-15 $c is present and disabled" "$BASE" "[.clients[] | select(.clientId == \"$c\")] | length == 1 and .[0].enabled == false"
done

# --- TC-980-16: no ids, no secret material ---------------------------------------------------------------
no_ids='[paths | select(.[-1] == "id")] | length == 0'
holds "TC-980-16 no id key at any depth" "$BASE" "$no_ids"
jq '.id = "fixed-realm-id"' "$BASE" >"$tmp/realm-id.json"
rejects "TC-980-16 a fixture with a realm id fails" "$tmp/realm-id.json" "$no_ids"
jq '.clients[0].id = "fixed-client-id"' "$BASE" >"$tmp/client-id.json"
rejects "TC-980-16 a fixture with a nested client id fails" "$tmp/client-id.json" "$no_ids"
holds "TC-980-16 no credentials, secret, privateKey, certificate, displayName or displayNameHtml key with a value" "$BASE" \
	'. as $r | [paths | select(.[-1] | IN("credentials", "secret", "privateKey", "certificate", "displayName", "displayNameHtml")) | . as $p | $r | getpath($p)
	 | select(. != null and . != "" and . != [] and . != {})] | length == 0'
holds "TC-980-16 the only user is rasputin-admin's service account" "$BASE" \
	'(.users | length == 1) and .users[0].username == "service-account-rasputin-admin" and .users[0].serviceAccountClientId == "rasputin-admin"'
holds "TC-980-16 every KeyProvider is a -generated provider" "$BASE" \
	'(.components["org.keycloak.keys.KeyProvider"] | length > 0) and all(.components["org.keycloak.keys.KeyProvider"][]; .providerId | endswith("-generated"))'

# --- TC-980-17: the flow skeletons, unbound --------------------------------------------------------------
holds "TC-980-17 each declared flow is top-level with no executions" "$BASE" \
	'(.authenticationFlows | length > 0) and all(.authenticationFlows[]; .topLevel == true and ((.authenticationExecutions // []) | length == 0))'
holds "TC-980-17 no realm flow binding names a skeleton" "$BASE" \
	'[.authenticationFlows[].alias] as $a | ([.browserFlow, .registrationFlow, .directGrantFlow, .resetCredentialsFlow, .clientAuthenticationFlow, .firstBrokerLoginFlow] - [null]) as $b
	 | ($b - $a) == $b'

# --- TC-980-18: release-lib.sh --------------------------------------------------------------------------
printf 'const (\n\tName = "v"\n\tNameX = "w"\n\t// Name = "x"\n)\n' >"$tmp/lib-a.go"
printf 'const (\n\tNameX = "w"\n\t// Name = "x"\n)\n' >"$tmp/lib-b.go"
printf 'const (\n\tOther = "y"\n)\n' >"$tmp/lib-c.go"
got="$(pin_const "$tmp/lib-a.go" Name)"
if [ "$got" = v ]; then ok "TC-980-18 pin_const prints Name's value alone"; else fail "TC-980-18 pin_const prints Name's value alone" "got: $got"; fi
got="$(pin_const "$tmp/lib-b.go" Name)"
if [ -z "$got" ]; then ok "TC-980-18 pin_const ignores NameX and a commented Name"; else fail "TC-980-18 pin_const ignores NameX and a commented Name" "got: $got"; fi
got="$(pin_const "$tmp/lib-c.go" Name)"
if [ -z "$got" ]; then ok "TC-980-18 pin_const prints nothing for a file without Name"; else fail "TC-980-18 pin_const prints nothing for a file without Name" "got: $got"; fi
printf 'abc' >"$tmp/abc"
got="$(sha256_of "$tmp/abc")"
if [ "$got" = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad ]; then ok "TC-980-18 sha256_of prints the known hex"; else fail "TC-980-18 sha256_of prints the known hex" "got: $got"; fi

echo
if [ "$failures" -ne 0 ]; then echo "test-pack-identity: $failures failure(s)"; exit 1; fi
echo "test-pack-identity: all passed"
