package authz

import "slices"

// The app access levels (rasputin_app_role) and the network grants
// (rasputin_network) the guard decides (geekdojo/geekdojo-brain#994).
const (
	AppRoleUser  = "user"
	AppRoleAdmin = "admin"

	NetworkJoin      = "join"
	NetworkGearRead  = "gear-read"
	NetworkGearAdmin = "gear-admin"
)

// NetworkGrants are every network grant, in no meaningful order.
func NetworkGrants() []string { return []string{NetworkJoin, NetworkGearRead, NetworkGearAdmin} }

// Levels are the privileged levels an account holds (C3): its privileged
// console role (admin or operator, "" for none), app administrator, and
// gear administrator.
type Levels struct {
	Console   string
	App, Gear bool
}

// Empty reports whether l holds no privileged level.
func (l Levels) Empty() bool { return l.Console == "" && !l.App && !l.Gear }

// PrivilegedLevels is the one definition of privilege (F-994-06): the
// privileged levels f holds. The guard, the account requests, the
// credential removals and the second-step markers all decide on it.
func PrivilegedLevels(f AccountFacts) Levels {
	var l Levels
	if h := highest(f.Roles); h >= rank(string(Operator)) {
		l.Console = string(Operator)
		if h == rank(string(Admin)) {
			l.Console = string(Admin)
		}
	}
	l.App = f.AppRole == AppRoleAdmin
	l.Gear = slices.Contains(f.Network, NetworkGearAdmin)
	return l
}

// HoldsPrivilege reports whether f holds any privileged level.
func HoldsPrivilege(f AccountFacts) bool { return !PrivilegedLevels(f).Empty() }

// RaisesPrivilege reports whether ch, applied to the account f describes,
// adds a privileged level f lacks or raises its console role to a
// privileged rank above the one it holds.
func RaisesPrivilege(f AccountFacts, ch RoleChange) bool {
	have := PrivilegedLevels(f)
	switch ch.Op {
	case OpSetRole:
		return Privileged(ch.Role) && rank(ch.Role) > highest(f.Roles)
	case OpSetAppAccess:
		return ch.AppRole == AppRoleAdmin && !have.App
	case OpSetNetwork:
		return slices.Contains(ch.Network, NetworkGearAdmin) && !have.Gear
	}
	return false
}
