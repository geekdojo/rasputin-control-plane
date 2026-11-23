package flows

import (
	"maps"
	"slices"
)

// OwnClient is one of Rasputin's own clients as the rules want it: its
// switches and its default and optional scopes.
type OwnClient struct {
	ClientID       string          `json:"clientId"`
	Switches       map[string]bool `json:"switches"`
	DefaultScopes  []string        `json:"defaultScopes"`
	OptionalScopes []string        `json:"optionalScopes"`
}

// signInSwitches are a sign-in client's switches: the authorization code
// flow only, confidential, never consent, no full scope.
func signInSwitches() map[string]bool {
	return map[string]bool{
		"enabled": true, "standardFlowEnabled": true, "implicitFlowEnabled": false,
		"directAccessGrantsEnabled": false, "serviceAccountsEnabled": false, "publicClient": false,
		"consentRequired": false, "fullScopeAllowed": false, "bearerOnly": false,
	}
}

// OwnClients are Rasputin's own clients, as the baseline creates them, by
// client id.
func OwnClients() []OwnClient {
	admin := signInSwitches()
	admin["standardFlowEnabled"], admin["serviceAccountsEnabled"] = false, true
	return []OwnClient{
		{ClientID: "rasputin-account", Switches: signInSwitches(), DefaultScopes: []string{"basic", "profile"}, OptionalScopes: []string{}},
		{ClientID: "rasputin-admin", Switches: admin, DefaultScopes: []string{"kc-admin-api"}, OptionalScopes: []string{}},
		{ClientID: consoleClient, Switches: signInSwitches(), DefaultScopes: []string{"basic", "profile", "rasputin-console-roles"}, OptionalScopes: []string{}},
		{ClientID: "rasputin-mesh", Switches: signInSwitches(), DefaultScopes: []string{"basic", "email", "profile"}, OptionalScopes: []string{}},
		{ClientID: "rasputin-reset-app", Switches: signInSwitches(), DefaultScopes: []string{"basic"}, OptionalScopes: []string{}},
		{ClientID: "rasputin-reset-home", Switches: signInSwitches(), DefaultScopes: []string{"basic"}, OptionalScopes: []string{}},
	}
}

// ConsoleClient is the console's client, which holds the console roles.
const ConsoleClient = consoleClient

// ConsoleRoles are the console's client roles.
var ConsoleRoles = []string{consoleRoleAdmin, consoleRoleOperator, consoleRoleViewer}

// DefaultRolesName is the realm's default role, whose composites are empty:
// an account gets nothing it was not given.
const DefaultRolesName = "default-roles-rasputin"

// OwnBindings are the own sign-in clients' variants. The reset clients stay
// unbound (Identity 4.10).
var OwnBindings = map[string]Variant{
	consoleClient:      HomeConsole,
	"rasputin-mesh":    HomeMesh,
	"rasputin-account": AppAccount,
}

// Bindings are every bound client's variant: the own clients' and app's.
func Bindings(app map[string]Variant) map[string]Variant {
	out := maps.Clone(OwnBindings)
	maps.Copy(out, app)
	return out
}

// sortedKeys is m's keys, sorted.
func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}
