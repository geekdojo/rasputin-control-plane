package authz

// Class is a route's or Job kind's class (identity-authz.md §3.2): view,
// control under one capability, or self. The zero value is no class and is
// refused.
type Class int

// The route classes.
const (
	// ClassView needs View.
	ClassView Class = iota + 1
	// ClassControl needs the requirement's capability.
	ClassControl
	// ClassSelf needs Self. Checking that the target is the caller is the
	// route's or kind's own (geekdojo/geekdojo-brain#1001, #1002).
	ClassSelf
)

// Requirement is what a route or Job kind needs: its class and, for
// control, its capability.
type Requirement struct {
	Class      Class
	Capability Capability
}

// NeedView is a view requirement.
func NeedView() Requirement { return Requirement{Class: ClassView} }

// NeedControl is a control requirement under c.
func NeedControl(c Capability) Requirement { return Requirement{Class: ClassControl, Capability: c} }

// NeedSelf is a self requirement.
func NeedSelf() Requirement { return Requirement{Class: ClassSelf} }

// AccountsRead is what reading Accounts needs: control under IAM, so a
// viewer, who holds View, never sees Accounts.
func AccountsRead() Requirement { return NeedControl(IAM) }

// Permits reports whether s meets r. It refuses what it cannot evaluate:
// the zero Requirement, an out-of-range class, and control with an empty or
// unknown capability, or with View or Self, which are classes of their own
// rather than control capabilities.
func (s Set) Permits(r Requirement) bool {
	switch r.Class {
	case ClassView:
		return s.Has(View)
	case ClassSelf:
		return s.Has(Self)
	case ClassControl:
		return r.Capability != View && r.Capability != Self && s.Has(r.Capability)
	}
	return false
}
