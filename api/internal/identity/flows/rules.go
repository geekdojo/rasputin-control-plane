package flows

import "slices"

// Rules is everything the definition renders from Inputs alone. Converge
// folds it into its desired state's hash, so the hash changes exactly when
// a rule does.
type Rules struct {
	Flows          map[string][]Node  `json:"flows"`
	Realm          map[string]any     `json:"realm"`
	EnabledActions []string           `json:"enabledActions"`
	Clients        []OwnClient        `json:"clients"`
	Bindings       map[string]Variant `json:"bindings"`
	ConsoleRoles   []string           `json:"consoleRoles"`
	AdminOnly      map[string]bool    `json:"adminOnly"`
	Reentry        int                `json:"reentrySeconds"`
	Username       string             `json:"usernamePattern"`
}

// Render is the rules for in.
func Render(in Inputs) Rules {
	r := Rules{
		Flows:          map[string][]Node{},
		Realm:          RealmRules(in),
		EnabledActions: enabledActions(in),
		Clients:        OwnClients(),
		Bindings:       Bindings(in.AppBindings),
		ConsoleRoles:   slices.Clone(ConsoleRoles),
		AdminOnly:      AdminOnlyAttributes,
		Reentry:        seconds(CredentialReentryLifetime),
		Username:       UsernamePattern,
	}
	for _, v := range Variants {
		r.Flows[v.Alias()] = Flow(v)
	}
	r.Flows[ResetAlias] = ResetFlow()
	return r
}
