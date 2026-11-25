package main

import (
	"errors"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/breakglass"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/move"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// TC-1004-23: under keycloak the wiring registers identity.move as a
// System kind, adds its trigger's entry at the K03 interval and fills the
// state holder, and the accounts register accounts.grant_waiting. Outside
// keycloak none of these is built, the holder stays empty, and a repair
// submission of the move is refused as a check that failed. A nil
// collaborator under keycloak is an error.
func TestIdentityMoveWiring_TC1004_23(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rasputin.db")
	ad, _ := accountsFixture(t, dbPath)
	acct, err := wireAccounts(t.Context(), ad)
	if err != nil {
		t.Fatal(err)
	}
	r := &registered{kinds: map[string]jobs.Workflow{}}
	acct.register(r)
	if _, ok := r.kinds[accounts.KindGrantWaiting]; !ok {
		t.Error("accounts.grant_waiting is not registered under keycloak")
	}
	st, err := identityStateWiring(identityDeps(t, identityModeKeycloak, &identityCounts{}))
	if err != nil {
		t.Fatal(err)
	}
	cd := convergeDeps(t, identityModeKeycloak, &st)
	conv, err := identityConvergeWiring(cd)
	if err != nil {
		t.Fatal(err)
	}
	deps := func(mode string, holder *moveStateHolder) identityMoveDeps {
		return identityMoveDeps{mode: mode, dbPath: dbPath, session: cd.session, oldUsers: ad.moved, acct: acct,
			designations: ad.designations, monitor: st.monitor, converger: conv.converger, ledger: cd.ledger,
			holder: holder, now: time.Now, log: slog.New(slog.DiscardHandler)}
	}
	repairSubmit := func(h *moveStateHolder) error {
		kp, err := authz.NewKindPolicy(noAppFacts{}, authz.WithMoveState(h))
		if err != nil {
			t.Fatal(err)
		}
		return kp.Authorize(t.Context(), move.Kind, []byte(`{"repair":true,"stateToken":"x"}`), breakglass.Session{}.Submitter())
	}

	for _, mode := range []string{identityModeOff, identityModeMock} {
		h := &moveStateHolder{}
		w, err := identityMoveWiring(t.Context(), deps(mode, h))
		reg := &registered{kinds: map[string]jobs.Workflow{}}
		w.register(reg)
		if err != nil || len(reg.kinds) != 0 || w.entry != nil || h.p.Load() != nil {
			t.Errorf("mode %s: %v, kinds %v, entry %v", mode, err, reg.kinds, w.entry)
		}
		if err := repairSubmit(h); !errors.Is(err, authz.ErrCheckFailed) {
			t.Errorf("mode %s: a repair submission %v, want ErrCheckFailed", mode, err)
		}
		w.close()
	}

	h := &moveStateHolder{}
	w, err := identityMoveWiring(t.Context(), deps(identityModeKeycloak, h))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.close)
	reg := &registered{kinds: map[string]jobs.Workflow{}}
	w.register(reg)
	if wf, ok := reg.kinds[move.Kind]; !ok || !wf.System || len(wf.Steps) != 3 {
		t.Errorf("identity.move registered %v, System %v", ok, wf.System)
	}
	if w.entry == nil || w.entry.Kind != move.Kind || w.entry.Interval != storeAuditCheckEvery || w.entry.Due == nil {
		t.Errorf("entry %+v", w.entry)
	}
	if h.p.Load() == nil {
		t.Error("the holder is empty under keycloak")
	}

	d := deps(identityModeKeycloak, &moveStateHolder{})
	d.converger = nil
	if _, err := identityMoveWiring(t.Context(), d); err == nil {
		t.Error("a nil converger was accepted under keycloak")
	}
}
