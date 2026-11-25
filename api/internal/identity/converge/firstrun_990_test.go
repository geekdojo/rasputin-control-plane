package converge

import (
	"slices"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
)

// recoveryDefault is the fake realm's recovery-codes defaultAction.
func (r *rig) recoveryDefault(t *testing.T) bool {
	t.Helper()
	i := slices.IndexFunc(r.kc.rulesState.actions, func(a requiredAction) bool { return a.Alias == flows.ActionRecoveryCodes })
	if i < 0 {
		t.Fatal("no recovery-codes action")
	}
	return r.kc.rulesState.actions[i].DefaultAction
}

// TC-990-23: the recovery-codes action is a default action while first run
// holds, and the claim, which ends it, changes the desired hash, so
// ConvergeCond is due with a new rearm key and the next run clears it.
// That run changes only defaultAction, and the fake replaces the action's
// config with the PUT body's as Keycloak 26.8.2 does (register row T253), so
// the run passes only if the action PUT carries the config (F-990-12).
func TestFirstRun_TC990_23_DefaultActionFollowsTheClaim(t *testing.T) {
	r := newRig(t)
	r.inputs.FirstRun = true
	if _, err := r.c.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !r.recoveryDefault(t) {
		t.Error("during first run the recovery codes are not a default action")
	}
	cond := ConvergeCond(r.c, laggingNone{})
	_, _, before, err := cond(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if before != "" {
		t.Fatalf("converged, but the key is %q", before)
	}
	r.inputs.FirstRun = false // the claim committed
	due, _, key, err := cond(t.Context())
	if err != nil || !due || key == "" || key == before {
		t.Errorf("after the claim: due %v key %q (before %q), %v", due, key, before, err)
	}
	if _, err := r.c.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if r.recoveryDefault(t) {
		t.Error("after the claim the recovery codes are still a default action")
	}
	for _, a := range r.kc.rulesState.actions {
		if a.Alias == flows.ActionRecoveryCodes && (a.Config["max_auth_age"] != "300" || a.Config["warning_threshold"] != "4") {
			t.Errorf("the defaultAction write lost the recovery codes' config: %v", a.Config)
		}
	}
}
