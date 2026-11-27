package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
)

// A signed-in person adds a sign-in method to their own account
// (geekdojo/geekdojo-brain#1150, Identity 4.16): each is one of Keycloak's
// application-initiated actions, run in a fresh sign-in at the home door
// (prompt=login) that carries a single kc_action. The api issues the
// action under the sign-in's state, and the doors forward a kc_action only
// when this sign-in issued it (Issued), once.

// Method is a sign-in method a person may add to their own account.
type Method string

// The four methods, and nothing else: no credential removal and no
// password change.
const (
	MethodPasskey          Method = "passkey"
	MethodSecurityKey      Method = "security_key"
	MethodAuthenticatorApp Method = "authenticator_app"
	MethodRecoveryCodes    Method = "recovery_codes"
)

// methodSpec is a method's action kind (the fresh sign-in's
// ?action=<kind>) and the Keycloak required action it runs.
type methodSpec struct {
	kind     string
	kcAction string
}

// methods is the closed set: each method, its kind and its action.
var methods = map[Method]methodSpec{
	MethodPasskey:          {kind: "add_passkey", kcAction: flows.ActionPasskeyRegister},
	MethodSecurityKey:      {kind: "add_security_key", kcAction: flows.ActionSecurityKey},
	MethodAuthenticatorApp: {kind: "add_authenticator_app", kcAction: flows.ActionConfigureTOTP},
	MethodRecoveryCodes:    {kind: "add_recovery_codes", kcAction: flows.ActionRecoveryCodes},
}

// methodKind reports whether kind is a method's action kind.
func methodKind(kind string) bool {
	for _, m := range methods {
		if m.kind == kind {
			return true
		}
	}
	return false
}

var (
	// ErrUnknownMethod is ParseMethod's refusal of anything but the four
	// methods' exact names.
	ErrUnknownMethod = errors.New("auth: no such sign-in method")
	// ErrClockNotSet is PrepareMethod's refusal of an authenticator app while
	// the api's clock-sync fact does not hold: its codes depend on the clock.
	ErrClockNotSet = errors.New("auth: the clock is not set, so an authenticator app cannot be added")
)

// ParseMethod is the method named s, matched exactly and case-sensitively,
// or ErrUnknownMethod.
func ParseMethod(s string) (Method, error) {
	if _, ok := methods[Method(s)]; !ok {
		return "", ErrUnknownMethod
	}
	return Method(s), nil
}

// ClockFact is the api's clock-sync fact (the composition root's
// clockSyncFact): an authenticator app is offered only while it holds.
type ClockFact interface {
	Synced(ctx context.Context) bool
}

// The launcher's sentence key for a method the person cancelled.
const signinMethodCancelled = launcherPath + "?signin=method-cancelled"

// PrepareMethod holds the fresh sign-in that adds m to the account r is
// signed in as, under the browser's pending cookie (replacing any record
// there), and returns where the browser goes to start it:
// GET /api/auth/signin?action=<kind>. The person comes only from r's
// principal. It refuses with ErrNoAction without a signed-in person or with
// the pending cookie twice, ErrClockNotSet for an authenticator app while
// the clock fact does not hold, and an error when no random values could be
// read.
func (s *SignIn) PrepareMethod(w http.ResponseWriter, r *http.Request, m Method) (string, error) {
	spec, ok := methods[m]
	if !ok {
		return "", ErrUnknownMethod
	}
	if p, ok := PrincipalFrom(r.Context()); !ok || p.Sub == "" {
		return "", ErrNoAction
	}
	if m == MethodAuthenticatorApp && !s.d.Clock.Synced(r.Context()) {
		return "", ErrClockNotSet
	}
	return s.prepare(w, r, spec.kind, &pendingAction{kind: spec.kind, method: m, kcAction: spec.kcAction})
}

// Issued answers the doors whether this sign-in issued the kc_action in a:
// only for rasputin-console, only under the state of a begun, unexpired
// sign-in that carries exactly that action, and only once. CONFIGURE_TOTP
// is forwarded only while the clock fact holds, read afresh. Anything else
// is false. It never returns an error.
func (s *SignIn) Issued(ctx context.Context, a policy.ActionRequest) (bool, error) {
	if a.Client != s.d.ClientID || a.State == "" || a.Action == "" {
		return false, nil
	}
	if a.Action == flows.ActionConfigureTOTP && !s.d.Clock.Synced(ctx) {
		return false, nil
	}
	return s.pending.forward(a.State, a.Action), nil
}

// methodReturn is a method's return once the same person signed in again:
// it mints no session, and kc_action_status picks the sentence. The status
// grants nothing: the facts are re-read by the observer, which Complete
// tells of every verified return.
func (s *SignIn) methodReturn(ctx context.Context, rec *pendingSignin, p Principal, q map[string][]string) CallbackResult {
	outcome, level, loc := "error", slog.LevelWarn, signinActionFailed
	if st := q["kc_action_status"]; len(st) == 1 {
		switch st[0] {
		case "success":
			outcome, level, loc = "success", slog.LevelInfo, launcherPath
		case "cancelled":
			outcome, level, loc = "cancelled", slog.LevelInfo, signinMethodCancelled
		}
	}
	s.log.LogAttrs(ctx, level, "A person came back from adding a sign-in method.",
		slog.String("event", "signin.method_returned"), slog.String("method", string(rec.action.method)),
		slog.String("outcome", outcome), slog.String("sub", p.Sub))
	return CallbackResult{Status: http.StatusSeeOther, Location: loc}
}
