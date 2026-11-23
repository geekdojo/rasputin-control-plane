package flows

import (
	"maps"
	"slices"
	"strconv"
)

// The required actions the rules enable.
const (
	ActionUpdatePassword   = "UPDATE_PASSWORD"
	ActionPasskeyRegister  = "webauthn-register-passwordless"
	ActionSecurityKey      = "webauthn-register"
	ActionRecoveryCodes    = "CONFIGURE_RECOVERY_AUTHN_CODES"
	ActionConfigureTOTP    = "CONFIGURE_TOTP"
	ActionDeleteCredential = "delete_credential"
	// maxAuthAge is Keycloak's per-action re-authentication setting
	// (Constants.MAX_AUTH_AGE_KEY at 26.8.2).
	maxAuthAge = "max_auth_age"
	// warningThreshold is the recovery-codes action's other setting, which
	// Keycloak 26.8.2 requires in any config it is sent: when fewer codes
	// remain, the account console warns. It is written at its stock value,
	// 4; nothing in Rasputin reads it.
	warningThreshold      = "warning_threshold"
	stockWarningThreshold = "4"
)

// credentialActions are the actions that change a credential: each asks for
// the password again once CredentialReentryLifetime has passed (N8).
var credentialActions = []string{ActionUpdatePassword, ActionSecurityKey, ActionPasskeyRegister, ActionRecoveryCodes}

// RequiredAction is one required action as the rules want it. A nil
// DefaultAction or Config is not owned.
type RequiredAction struct {
	Alias         string            `json:"alias"`
	Enabled       bool              `json:"enabled"`
	DefaultAction *bool             `json:"defaultAction,omitempty"`
	Config        map[string]string `json:"config,omitempty"`
}

// enabledActions are the actions the rules enable for in.
func enabledActions(in Inputs) []string {
	out := []string{ActionUpdatePassword, ActionPasskeyRegister, ActionSecurityKey, ActionRecoveryCodes}
	if in.ClockSynced {
		out = append(out, ActionConfigureTOTP)
	}
	return out
}

// OwnedActions are the actions the rules may enable, each registered when
// the server does not list it.
var OwnedActions = []string{ActionUpdatePassword, ActionPasskeyRegister, ActionSecurityKey, ActionRecoveryCodes, ActionConfigureTOTP}

// RequiredActions is every action's wanted state: the owned ones, and each
// other action the server lists (listed), which is disabled, so
// delete_credential is off. Every defaultAction is false except the
// recovery codes', which Identity 4.8 owns. The result is sorted by alias.
func RequiredActions(in Inputs, listed []string) []RequiredAction {
	enabled := enabledActions(in)
	reentry := map[string]string{maxAuthAge: strconv.Itoa(seconds(CredentialReentryLifetime))}
	aliases := append(append([]string{}, OwnedActions...), listed...)
	slices.Sort(aliases)
	aliases = slices.Compact(aliases)
	out := make([]RequiredAction, 0, len(aliases))
	for _, a := range aliases {
		ra := RequiredAction{Alias: a, Enabled: slices.Contains(enabled, a)}
		if a != ActionRecoveryCodes {
			f := false
			ra.DefaultAction = &f
		}
		if slices.Contains(credentialActions, a) {
			ra.Config = maps.Clone(reentry)
		}
		if a == ActionRecoveryCodes {
			ra.Config[warningThreshold] = stockWarningThreshold
		}
		out = append(out, ra)
	}
	return out
}
