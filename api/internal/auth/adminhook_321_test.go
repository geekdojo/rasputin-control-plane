package auth

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// TC-321-17 (auth's half): the admin sign-in hook runs exactly when the
// callback mints a session holding admin, before the cookie is written, and
// never for a session without it or for a refused sign-in. Its other half,
// that the hook's break-glass service then ends the repair session and
// retires the code, is breakglass's TestAdminSignedIn_TC321_17; main wires one
// to the other (breakglass_wiring.go), and CI TC-321-33 runs both together.
func TestAdminSignInHook_TC321_17(t *testing.T) {
	r := newSigninRig(t)
	calls := 0
	r.f.svc.SetAdminSignInHook(func(context.Context) { calls++ })

	if w := r.signIn(t, func(c map[string]any) { c["rasputin_roles"] = []string{"operator"} }); sessionFrom(w) == nil {
		t.Fatalf("operator sign-in: %d %s", w.Code, w.Body.String())
	}
	if calls != 0 {
		t.Fatalf("the hook ran %d times for an operator's sign-in, want 0", calls)
	}
	if w := r.signIn(t, nil); sessionFrom(w) == nil || w.Code != http.StatusSeeOther {
		t.Fatalf("admin sign-in: %d %s", w.Code, w.Body.String())
	}
	if calls != 1 {
		t.Fatalf("the hook ran %d times for an admin's sign-in, want 1", calls)
	}
	// A refused sign-in mints nothing, so the hook does not run.
	if w := r.signIn(t, func(c map[string]any) { c["exp"] = r.f.clock.Now().Add(-time.Hour).Unix() }); sessionFrom(w) != nil {
		t.Fatal("an expired ID token minted a session")
	}
	if calls != 1 {
		t.Fatalf("the hook ran for a refused sign-in (%d calls)", calls)
	}
	r.f.svc.SetAdminSignInHook(nil)
	if w := r.signIn(t, nil); sessionFrom(w) == nil {
		t.Fatal("admin sign-in with no hook")
	}
}

// SessionLifetime is the console session's bound, exported for the repair
// session (register row C72).
func TestSessionLifetimeIsTheConsoleBound(t *testing.T) {
	if got := SessionLifetime; got != 7*24*time.Hour {
		t.Fatalf("SessionLifetime = %v, want the console session's seven days", got)
	}
}
