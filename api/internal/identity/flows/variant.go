// Package flows is the one Go definition of Rasputin's sign-in rules
// (geekdojo/geekdojo-brain#987, Identity 4.5; identity-authz.md §5.1): the
// seven sign-in flows, the realm's session, password, brute-force and passkey
// rules, the required actions, the owned parts of the user profile, and the
// own clients' switches, scopes, roles and flow bindings.
//
// It is pure: no I/O and no clock. The converge package applies what it
// renders and compares the realm with it.
package flows

// Door is the sign-in door a client belongs to.
type Door string

// The two doors.
const (
	DoorHome Door = "home"
	DoorApp  Door = "app"
)

// Variant is one of the seven sign-in flows.
type Variant int

// The seven variants. The baseline's frozen aliases name them
// (identity/realm-baseline.json, authenticationFlows).
const (
	HomeConsole Variant = iota
	HomeMesh
	AppAccount
	AppClients
	Administering
	AdminsFirst
	NetworkDevices
)

// Variants are all seven, in order.
var Variants = []Variant{HomeConsole, HomeMesh, AppAccount, AppClients, Administering, AdminsFirst, NetworkDevices}

// RealmDefault is the variant the realm's browser flow binding names: a
// client whose own binding is lost signs in by it.
const RealmDefault = AppClients

// Alias is the variant's top-level flow alias, as the baseline froze it.
func (v Variant) Alias() string {
	switch v {
	case HomeConsole:
		return "rasputin-signin-home-console"
	case HomeMesh:
		return "rasputin-signin-home-mesh"
	case AppAccount:
		return "rasputin-signin-app-account"
	case AppClients:
		return "rasputin-signin-app-clients"
	case Administering:
		return "rasputin-signin-administering"
	case AdminsFirst:
		return "rasputin-signin-admins-first"
	case NetworkDevices:
		return "rasputin-signin-network-devices"
	}
	return ""
}

// Door is the door the variant's clients sign in at.
func (v Variant) Door() Door {
	if v == HomeConsole || v == HomeMesh {
		return DoorHome
	}
	return DoorApp
}

// Stricter reports whether the realm default would weaken the variant: an
// administrators-first app would admit user, an administering server would
// drop its always-run second step, and a network device would gate on app
// access instead of network grants.
func (v Variant) Stricter() bool {
	return v == Administering || v == AdminsFirst || v == NetworkDevices
}

// VariantByAlias is the variant whose top-level alias is alias.
func VariantByAlias(alias string) (Variant, bool) {
	for _, v := range Variants {
		if v.Alias() == alias {
			return v, true
		}
	}
	return 0, false
}
