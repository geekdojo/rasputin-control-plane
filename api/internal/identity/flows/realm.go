package flows

import "time"

// Inputs are the facts the rules are rendered from.
type Inputs struct {
	// InstallName is setup.install_name. Nothing here renders it today: the
	// passkey relying-party name is the fixed word Rasputin (RPName).
	InstallName string
	// ClockSynced is the clock-sync fact: CONFIGURE_TOTP is enabled only
	// while it holds.
	ClockSynced bool
	// AppBindings are the app clients' variants, by client id (Identity
	// 7.3); nil until then.
	AppBindings map[string]Variant
	// FirstRun is the first-run predicate (register row C03): while it
	// holds, saving recovery codes is a default action, so every account
	// created before the claim ends sign-up on "Save your recovery codes"
	// (geekdojo/geekdojo-brain#990).
	FirstRun bool
}

// The clock bounds the realm is rendered from (D22, ratified by Bryce on
// 2026-11-02; timer-audit rows). Each bounds how long a session, a page or a
// count lasts; none decides a state change in the api.
const (
	// ssoSessionIdleLifetime ends an identity-service session after 30 idle
	// minutes.
	ssoSessionIdleLifetime = 30 * time.Minute
	// ssoSessionMaxLifetime ends one after 10 hours whatever happens.
	ssoSessionMaxLifetime = 10 * time.Hour
	// offlineSessionIdleLifetime ends an app's offline session after 30
	// days without a refresh.
	offlineSessionIdleLifetime = 720 * time.Hour
	// loginLifetime is how long one sign-in may take.
	loginLifetime = 30 * time.Minute
	// loginActionLifetime is how long one sign-in page may stay open; it
	// equals loginLifetime so one slow page (writing down recovery codes)
	// never restarts the flow.
	loginActionLifetime = 30 * time.Minute
	// authCodeLifetime is the authorization code's lifespan (stock, stated).
	authCodeLifetime = time.Minute
	// accessTokenLifetime is the access token's lifespan (stock, stated).
	accessTokenLifetime = 5 * time.Minute
	// CredentialReentryLifetime is how long after signing in a credential
	// change still runs without asking for the password again (N8): each
	// credential action's max_auth_age.
	CredentialReentryLifetime = 5 * time.Minute
	// failureCountLifetime is the window Keycloak's per-account backstop
	// counts failures over.
	failureCountLifetime = 12 * time.Hour
	// totpStep is the authenticator app's time step (stock, RFC 6238).
	totpStep = 30 * time.Second
)

// failureFactor is how many failed sign-ins within failureCountLifetime hold
// an account (the backstop; the per-source throttle is Identity 4.3's).
const failureFactor = 100

// The realm's password policy and the deny list it names
// (geekdojo/geekdojo-brain#1145). scripts/fetch-denylist.sh reads both lines
// with anchored seds, so each name stays on a line of its own and the
// policy's length(N) stays first: the list is cut to the passwords of at
// least N bytes, which the length rule does not already refuse.
const (
	// DenylistFile is the list's name in Keycloak's
	// <data>/password-blacklists/, where rasputin-os stages the copy the api
	// tarball ships (identity/password-blacklists/).
	DenylistFile = "rasputin-common-passwords.txt"
	// PasswordPolicy is the realm's password policy: 15 to 128 characters,
	// not the username, not the email, and not on the deny list, a pinned
	// third-party list of common and breached passwords.
	PasswordPolicy = "length(15) and maxLength(128) and notUsername(undefined) and notEmail(undefined) and passwordBlacklist(" + DenylistFile + ")"
	// DenylistFalsePositiveProbability is the false-positive probability of
	// the Bloom filter Keycloak checks the deny list through, its runtime
	// option spi-password-policy--password-blacklist--false-positive-probability.
	// Keycloak's default, 1.0E-4, refused about 1 in 10,000 passwords that
	// are not on the list (finding F-1145-40, geekdojo/geekdojo-brain#1145,
	// record dev-records/geekdojo/geekdojo-brain/1145/verification/flake-rca-2026-11-25.md).
	// A Bloom filter has no false negatives, so every listed password is
	// still refused; the filter grows from about 300 KB to about 670 KB.
	DenylistFalsePositiveProbability = "1e-9"
)

func seconds(d time.Duration) int { return int(d / time.Second) }

// RealmRules are the realm fields the rules own, by Keycloak's
// representation name. The WebAuthn fields are the ones prefixed
// webAuthnPolicy.
func RealmRules(in Inputs) map[string]any {
	rp := RPName(in)
	return map[string]any{
		"browserFlow": RealmDefault.Alias(),
		// The reset entry runs the reset flow; Keycloak refuses the entry
		// unless resets are allowed (Identity 4.10).
		"resetCredentialsFlow": ResetAlias,
		"resetPasswordAllowed": true,
		// Anyone on the home network may create an account; the home door
		// decides who (Identity 4.8).
		"registrationAllowed": true,

		"ssoSessionIdleTimeout":            seconds(ssoSessionIdleLifetime),
		"ssoSessionMaxLifespan":            seconds(ssoSessionMaxLifetime),
		"offlineSessionIdleTimeout":        seconds(offlineSessionIdleLifetime),
		"offlineSessionMaxLifespanEnabled": false,
		"accessCodeLifespanLogin":          seconds(loginLifetime),
		"accessCodeLifespanUserAction":     seconds(loginActionLifetime),
		"accessCodeLifespan":               seconds(authCodeLifetime),
		"accessTokenLifespan":              seconds(accessTokenLifetime),
		"rememberMe":                       false,

		"bruteForceProtected":         true,
		"failureFactor":               failureFactor,
		"maxDeltaTimeSeconds":         seconds(failureCountLifetime),
		"quickLoginCheckMilliSeconds": 0,
		"permanentLockout":            false,
		"maxSecondaryAuthFailures":    0,

		"passwordPolicy": PasswordPolicy,

		"loginWithEmailAllowed":       true,
		"duplicateEmailsAllowed":      false,
		"registrationEmailAsUsername": false,
		"verifyEmail":                 false,
		"editUsernameAllowed":         false,
		"internationalizationEnabled": false,

		"otpPolicyPeriod": seconds(totpStep),

		"webAuthnPolicyUserVerificationRequirement":             "required",
		"webAuthnPolicyPasswordlessUserVerificationRequirement": "required",
		"webAuthnPolicyPasswordlessResidentKey":                 "required",
		"webAuthnPolicyPasswordlessPasskeysEnabled":             true,
		"webAuthnPolicyExtraOrigins":                            []string{},
		"webAuthnPolicyPasswordlessExtraOrigins":                []string{},
		"webAuthnPolicyRpEntityName":                            rp,
		"webAuthnPolicyPasswordlessRpEntityName":                rp,
	}
}

// RealmIntegrityFields are the realm fields whose difference is an
// integrity difference: the binding a lost client binding falls back to.
var RealmIntegrityFields = []string{"browserFlow"}
