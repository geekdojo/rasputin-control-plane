package accounts

import "context"

// Result is what one target of a hook made of its revocation.
type Result string

// The results a target can have. Each is an outcome, never an error
// (app-sso.md §7.2 item 5).
const (
	Delivered   Result = "delivered"
	Refused     Result = "refused"
	Unreachable Result = "unreachable"
	Offline     Result = "offline"
)

// TargetResult is one target's result. Target names the device, app or
// network component, never the person.
type TargetResult struct {
	Target string `json:"target"`
	Result Result `json:"result"`
}

// Outcome is a hook step's recorded outcome: one result per target, or a
// hook that is not built yet.
type Outcome struct {
	Outcome string         `json:"outcome"`
	What    string         `json:"what,omitempty"`
	Targets []TargetResult `json:"targets,omitempty"`
}

// Hook ends a person's access on one kind of thing outside the identity
// service: their private-network device (Identity 8.2), the apps' own
// sessions (Identity 7.5), the network (Identity 9.5).
//
// A target the hook can't reach, one that refuses, or a node that is
// offline is a result in the Outcome. Revoke returns an error only when it
// can't decide what to do at all, such as its own store being unreadable;
// that error fails the step.
type Hook interface {
	Revoke(ctx context.Context, sub string, kind RevokeKind) (Outcome, error)
}

// NoHook is a hook that is not built yet. What names it.
type NoHook struct{ What string }

// Revoke records that the hook is not built.
func (h NoHook) Revoke(context.Context, string, RevokeKind) (Outcome, error) {
	return Outcome{Outcome: "not_built", What: h.What}, nil
}
