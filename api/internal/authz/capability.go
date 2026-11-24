package authz

// Capability is one thing a console principal may do (identity-authz.md
// §3.2). An unknown capability is held by nobody.
type Capability string

// The capabilities, in the order Set.List reports them.
const (
	// View reads routes and streams classed view. It never reaches Accounts.
	View Capability = "view"
	// Apps covers catalog tiles whose effective tier is routine or elevated,
	// their sign-in settings and their secrets.
	Apps Capability = "apps"
	// AppsHost is a custom compose, created or edited, and a host-trusting
	// tile installed or upgraded with its privilege consent. A custom compose
	// is not validated (ADR-0006 Decision 12), so only administrators hold it.
	AppsHost Capability = "apps.host"
	// Updates applies OS and control-plane updates.
	Updates Capability = "updates"
	// Secrets writes or replaces a secret. Nothing reveals one (S21).
	Secrets Capability = "secrets"
	// Nodes manages nodes.
	Nodes Capability = "nodes"
	// Firewall manages the firewall.
	Firewall Capability = "firewall"
	// Mesh manages the private network.
	Mesh Capability = "mesh"
	// BMC drives the boards' management controllers, serial-over-LAN
	// included.
	BMC Capability = "bmc"
	// IAM manages accounts and roles, and reads everyone's audit records.
	IAM Capability = "iam"
	// System changes cluster-wide settings.
	System Capability = "system"
	// Self is the account's own profile, credentials, devices, sessions and
	// audit records. Every account holds it, with a role or without one.
	Self Capability = "self"
	// Repair is held by break-glass repair sessions only
	// (geekdojo/geekdojo-brain#321). No role or grant yields it.
	Repair Capability = "repair"
)

// Capabilities returns every capability, in Set.List's order.
func Capabilities() []Capability {
	return []Capability{View, Apps, AppsHost, Updates, Secrets, Nodes, Firewall, Mesh, BMC, IAM, System, Self, Repair}
}

// ParseCapability returns the capability s names exactly, and false when it
// names none.
func ParseCapability(s string) (Capability, bool) {
	for _, c := range Capabilities() {
		if string(c) == s {
			return c, true
		}
	}
	return "", false
}

// Role is a console role, as the rasputin_roles claim carries it.
type Role string

// The console roles (the rasputin-console client's roles).
const (
	// Admin holds every capability but Repair.
	Admin Role = "admin"
	// Operator holds View, Apps, Updates, Secrets and Self.
	Operator Role = "operator"
	// Viewer ("Sees the cluster, changes nothing") holds View and Self.
	Viewer Role = "viewer"
)

// RoleNames returns the console roles' names: the one source the identity
// service's baseline and sign-in rules read them from.
func RoleNames() []string { return []string{string(Admin), string(Operator), string(Viewer)} }

// Privileged reports whether role is a privileged console role (C3):
// administrator or operator. The match is exact.
func Privileged(role string) bool { return role == string(Admin) || role == string(Operator) }

// known reports whether role names a console role exactly.
func known(role string) bool { return rank(role) > 0 }

// rank orders the console roles by privilege: none or unknown 0, viewer 1,
// operator 2, admin 3.
func rank(role string) int {
	switch Role(role) {
	case Viewer:
		return 1
	case Operator:
		return 2
	case Admin:
		return 3
	}
	return 0
}

// bundle is role's capabilities, nothing for an unknown role.
func bundle(role string) []Capability {
	switch Role(role) {
	case Admin:
		return []Capability{View, Apps, AppsHost, Updates, Secrets, Nodes, Firewall, Mesh, BMC, IAM, System, Self}
	case Operator:
		return []Capability{View, Apps, Updates, Secrets, Self}
	case Viewer:
		return []Capability{View, Self}
	}
	return nil
}

// Grant is an agent grant's scopes: the seam an agent grant narrows a
// principal through. No grant exists today.
type Grant struct{ Scopes []string }

// Subject is the principal For maps: the account's subject, its console
// roles, and an optional grant.
type Subject struct {
	Sub   string
	Roles []string
	Grant *Grant
}

// Set is an immutable set of capabilities. The zero value holds nothing.
type Set struct{ bits uint32 }

// bit is c's position in Capabilities, and false for an unknown capability.
func bit(c Capability) (uint32, bool) {
	for i, k := range Capabilities() {
		if k == c {
			return 1 << i, true
		}
	}
	return 0, false
}

func (s Set) with(c Capability) Set {
	b, _ := bit(c)
	return Set{bits: s.bits | b}
}

// Has reports whether s holds c. An unknown capability is never held.
func (s Set) Has(c Capability) bool {
	b, ok := bit(c)
	return ok && s.bits&b != 0
}

// List returns s's capabilities in Capabilities' order. It is never nil.
func (s Set) List() []string {
	out := []string{}
	for _, c := range Capabilities() {
		if s.Has(c) {
			out = append(out, string(c))
		}
	}
	return out
}

// For is the one capability function. It returns nothing for an empty Sub.
// Otherwise it returns Self plus every known role's bundle (an exact,
// case-sensitive match; an unknown role counts as none). When Grant is set,
// the result is intersected with the grant's scopes, an unknown scope
// counting as none, so a grant only narrows. No role or grant yields Repair.
func For(s Subject) Set {
	if s.Sub == "" {
		return Set{}
	}
	set := Set{}.with(Self)
	for _, r := range s.Roles {
		for _, c := range bundle(r) {
			set = set.with(c)
		}
	}
	if s.Grant != nil {
		var g Set
		for _, scope := range s.Grant.Scopes {
			if c, ok := ParseCapability(scope); ok {
				g = g.with(c)
			}
		}
		set = Set{bits: set.bits & g.bits}
	}
	return set
}
