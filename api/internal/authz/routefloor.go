package authz

// PermitsKindRoute is the floor of a route that submits jobs of kind
// (geekdojo/geekdojo-brain#1002): the least that any person who passes kind's
// rule must hold. It is decided by Permits alone, with no spec and no target,
// so the router can refuse a person who can never run kind before the
// handler reads the body or writes anything. The runner still decides the
// job itself, on its spec and its target (KindPolicy.Authorize).
//
// It returns nil or a *KindRefusal with the kind table's code and sentence:
// unknown_kind for a kind the table does not hold, system_only and
// not_submittable for kinds no person submits, and not_permitted otherwise.
func (s Set) PermitsKindRoute(kind string) error {
	r, ok := kindTable[kind]
	if !ok {
		return refuseKind(CodeUnknownKind)
	}
	return s.permitsRule(r)
}

// permitsRule is r's floor for s.
func (s Set) permitsRule(r rule) error {
	switch r.shape {
	case control, others:
		return allowIf(s.Permits(NeedControl(r.cap)), CodeNotPermitted)
	case appTier:
		// The least an app job needs: apps, for a routine or elevated tile.
		// apps.host is the runner's to ask for, from the app's facts.
		return allowIf(s.Permits(NeedControl(Apps)), CodeNotPermitted)
	case self, selfOrOthers:
		return allowIf(s.Permits(NeedSelf()), CodeNotPermitted)
	case repairOnly:
		return allowIf(s.Permits(NeedControl(Repair)), CodeNotPermitted)
	case repairOr:
		return allowIf(s.Permits(NeedControl(Repair)) || s.Permits(NeedControl(r.cap)), CodeNotPermitted)
	case bridge:
		// A bridge grant never holds a console session.
		return refuseKind(CodeNotPermitted)
	case sysOnly:
		return refuseKind(CodeSystemOnly)
	case move:
		// A repair session re-runs the move (geekdojo/geekdojo-brain#321);
		// the runner's moveRule decides C9's state. Everyone else, as the
		// system's job.
		return allowIf(s.Permits(NeedControl(Repair)), CodeSystemOnly)
	case never:
		return refuseKind(CodeNotSubmittable)
	}
	// A shape this switch does not know is refused (ERR-CLOSED).
	return refuseKind(CodeNotPermitted)
}
