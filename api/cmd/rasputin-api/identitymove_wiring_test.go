package main

import (
	"crypto/rand"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
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
	svc, err := auth.NewService(ad.moved, auth.Config{RPID: "ci.local", RPOrigins: []string{"https://ci.local"}})
	if err != nil {
		t.Fatal(err)
	}
	deps := func(mode string, holder *moveStateHolder) identityMoveDeps {
		return identityMoveDeps{mode: mode, dbPath: dbPath, session: cd.session, oldUsers: ad.moved, acct: acct,
			designations: ad.designations, monitor: st.monitor, converger: conv.converger, ledger: cd.ledger,
			holder: holder, auth: svc, runner: ad.runner, signInOrigin: "https://sso-ci.local",
			newCorrelationID: func() string { return "id" }, rand: rand.Reader, now: time.Now, log: slog.New(slog.DiscardHandler)}
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

// TC-1005-24 (the wiring half): under keycloak with the doors on the
// wiring registers accounts.set_first_password and installs the bridge
// (its routes answer); outside keycloak, or with the doors off, it does
// neither and the routes answer 404. A nil bridge collaborator under
// keycloak is an error.
func TestIdentityMoveWiring_TC1005_24_Bridge(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rasputin.db")
	ad, _ := accountsFixture(t, dbPath)
	acct, err := wireAccounts(t.Context(), ad)
	if err != nil {
		t.Fatal(err)
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
	build := func(mode, origin string) (identityMove, *auth.Service, error) {
		svc, err := auth.NewService(ad.moved, auth.Config{RPID: "ci.local", RPOrigins: []string{"https://ci.local"}})
		if err != nil {
			t.Fatal(err)
		}
		w, err := identityMoveWiring(t.Context(), identityMoveDeps{mode: mode, dbPath: dbPath, session: cd.session, oldUsers: ad.moved,
			acct: acct, designations: ad.designations, monitor: st.monitor, converger: conv.converger, ledger: cd.ledger,
			holder: &moveStateHolder{}, auth: svc, runner: ad.runner, signInOrigin: origin,
			newCorrelationID: func() string { return "id" }, rand: rand.Reader, now: time.Now, log: slog.New(slog.DiscardHandler)})
		t.Cleanup(w.close)
		return w, svc, err
	}
	bridgeStatus := func(svc *auth.Service) int {
		mux := http.NewServeMux()
		svc.RegisterRoutes(mux)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/auth/bridge", nil))
		return w.Code
	}
	for _, c := range []struct {
		mode, origin string
		installed    bool
	}{
		{identityModeKeycloak, "https://sso-ci.local", true},
		{identityModeKeycloak, "", false},
		{identityModeOff, "https://sso-ci.local", false},
		{identityModeMock, "https://sso-ci.local", false},
	} {
		w, svc, err := build(c.mode, c.origin)
		if err != nil {
			t.Fatalf("%s %q: %v", c.mode, c.origin, err)
		}
		reg := &registered{kinds: map[string]jobs.Workflow{}}
		w.register(reg)
		_, has := reg.kinds[accounts.FirstPasswordKind]
		code := bridgeStatus(svc)
		if has != c.installed || (code != http.StatusNotFound) != c.installed {
			t.Errorf("%s %q: set_first_password registered %v, GET /api/auth/bridge %d; want installed %v", c.mode, c.origin, has, code, c.installed)
		}
	}
	for name, edit := range map[string]func(*identityMoveDeps){
		"auth":             func(d *identityMoveDeps) { d.auth = nil },
		"runner":           func(d *identityMoveDeps) { d.runner = nil },
		"newCorrelationID": func(d *identityMoveDeps) { d.newCorrelationID = nil },
		"rand":             func(d *identityMoveDeps) { d.rand = nil },
		"checker":          func(d *identityMoveDeps) { d.acct.checker = nil },
	} {
		d := identityMoveDeps{mode: identityModeKeycloak, dbPath: dbPath, session: cd.session, oldUsers: ad.moved, acct: acct,
			designations: ad.designations, monitor: st.monitor, converger: conv.converger, ledger: cd.ledger, holder: &moveStateHolder{},
			auth: &auth.Service{}, runner: ad.runner, signInOrigin: "https://sso-ci.local", newCorrelationID: func() string { return "id" },
			rand: rand.Reader, now: time.Now, log: slog.New(slog.DiscardHandler)}
		edit(&d)
		if _, err := identityMoveWiring(t.Context(), d); err == nil {
			t.Errorf("a nil %s was accepted under keycloak", name)
		}
	}
}
