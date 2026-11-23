package flows

import (
	"slices"
	"strings"
)

// SameSteps reports whether observed, a flow's executions as read and
// flattened, equals want: the same executions, in the same places, with the
// same requirements and configs.
func SameSteps(want, observed []Step) bool {
	if len(want) != len(observed) {
		return false
	}
	for i := range want {
		w, o := want[i], observed[i]
		if w.Level != o.Level || w.Index != o.Index || w.Provider != o.Provider || w.Alias != o.Alias ||
			w.Requirement != o.Requirement || w.ConfigAlias != o.ConfigAlias || !sameConfig(w.Config, o.Config) {
			return false
		}
	}
	return true
}

func sameConfig(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// clientSwitches are the client switches whose difference is an integrity
// difference.
var clientSwitches = []string{
	"enabled", "standardFlowEnabled", "implicitFlowEnabled", "directAccessGrantsEnabled",
	"serviceAccountsEnabled", "publicClient", "consentRequired", "fullScopeAllowed", "bearerOnly",
}

// ClientSwitches are the owned switch names, in a fixed order.
func ClientSwitches() []string { return slices.Clone(clientSwitches) }

// IsIntegrity reports whether a drifted field, by the name converge gives
// it, is an integrity difference: the flows, the bindings (each client's and
// the realm default), the required actions, the roles, the scopes, the
// client switches, the default roles and the profile attributes the
// conditions read. Lifetimes, the password policy, brute force and WebAuthn
// are not: they keep converge's drift behaviour.
func IsIntegrity(field string) bool {
	for _, p := range []string{"flow.", "action.", "role.", "defaultRoles.", "profile.attribute.", "profile.claim."} {
		if strings.HasPrefix(field, p) {
			return true
		}
	}
	if slices.Contains(RealmIntegrityFields, strings.TrimPrefix(field, "realm.")) && strings.HasPrefix(field, "realm.") {
		return true
	}
	if rest, ok := strings.CutPrefix(field, "client."); ok {
		i := strings.LastIndex(rest, ".")
		if i < 0 {
			return false
		}
		last := rest[i+1:]
		if strings.Contains(rest, ".scope.") {
			return true
		}
		return last == "binding" || slices.Contains(clientSwitches, last)
	}
	return false
}
