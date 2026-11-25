package main

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/converge"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitystate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// refusedIdentity is the identity service refusing rasputin-admin's login
// with invalid_client, as a deleted or broken admin client does.
type refusedIdentity struct{ n atomic.Int64 }

func (r *refusedIdentity) ClientCredentials(context.Context, string, string, *secret.Value) (secret.Value, error) {
	r.n.Add(1)
	return secret.Value{}, &idclient.Error{Op: "token", Status: 401, Kind: idclient.ErrDenied, OAuthError: "invalid_client"}
}

func (r *refusedIdentity) Admin(context.Context, secret.Value, string, string, any, any) (idclient.Response, error) {
	r.n.Add(1)
	return idclient.Response{}, errors.New("no token was ever issued")
}

func openSetupStore(t *testing.T) *setup.Store {
	t.Helper()
	st, err := setup.OpenStore(t.Context(), filepath.Join(t.TempDir(), "setup.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func convergeDeps(t *testing.T, mode string, mon *identityState) identityConvergeDeps {
	t.Helper()
	ident := &countedIdentity{}
	sess, err := idclient.NewSession(idclient.SessionConfig{Login: ident, Admin: ident, Realm: identityRealm,
		ClientID: identityAdminClient, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	return identityConvergeDeps{
		mode: mode, session: sess, monitor: mon.monitor, ledger: openJobStore(t), settings: openSetupStore(t),
		createArmed: func(string, []byte) error { return nil },
		stat:        func(string) (fs.FileInfo, error) { return nil, fs.ErrNotExist },
		firstRun:    func(context.Context) (bool, error) { return true, nil },
		now:         time.Now, log: slog.New(slog.DiscardHandler),
	}
}

// TC-981-18: under keycloak the wiring builds the converger, the runner, the
// armer, three registered workflows and three triggers' entries at the K03
// interval, and the features func; the drift alert joins the identity
// alerts composition. Other modes build none of these, and a nil
// collaborator under keycloak is an error.
func TestIdentityConvergeWiring(t *testing.T) {
	st, err := identityStateWiring(identityDeps(t, identityModeKeycloak, &identityCounts{}))
	if err != nil {
		t.Fatal(err)
	}
	w, err := identityConvergeWiring(convergeDeps(t, identityModeKeycloak, &st))
	if err != nil {
		t.Fatal(err)
	}
	if w.converger == nil {
		t.Fatal("no converger under keycloak")
	}
	reg := &fakeRegistry{}
	w.register(reg)
	var kinds []string
	system := map[string]bool{}
	for _, wf := range reg.wfs {
		kinds = append(kinds, wf.Kind)
		system[wf.Kind] = wf.System
	}
	if want := []string{converge.ConvergeKind, converge.MigrateKind, converge.ArmKind}; !slices.Equal(kinds, want) {
		t.Fatalf("registered %v, want %v", kinds, want)
	}
	if system[converge.ConvergeKind] || !system[converge.MigrateKind] || !system[converge.ArmKind] {
		t.Errorf("System = %v, want only migrate and arm", system)
	}
	entries := w.entries()
	if len(entries) != 3 {
		t.Fatalf("entries = %+v", entries)
	}
	for i, e := range entries {
		if e.Kind != kinds[i] || e.Interval != storeAuditCheckEvery || e.Due == nil {
			t.Errorf("entry %d = %+v", i, e)
		}
		// The identity service is unreachable in these deps: not due.
		if due, _ := e.Due(t.Context()); due {
			t.Errorf("%s due with the identity service unreachable", e.Kind)
		}
	}
	if f := identityFeatures(identityModeKeycloak, convergeDeps(t, identityModeKeycloak, &st).session, slog.New(slog.DiscardHandler)); f == nil {
		t.Error("no features func under keycloak")
	}

	// The drift alert in the identity alerts composition.
	if a := w.alerts(t.Context(), time.Now()); len(a) != 0 {
		t.Errorf("alerts with no drift = %+v", a)
	}
	hook := &alertsHook{}
	drift := func(context.Context, time.Time) []proto.Alert { return []proto.Alert{{ID: converge.DriftAlertID}} }
	st.wireAlerts(hook, nil, w.alerts, drift)
	var ids []string
	for _, a := range hook.fn(t.Context(), time.Now()) {
		ids = append(ids, a.ID)
	}
	if len(ids) != 2 || ids[1] != converge.DriftAlertID {
		t.Errorf("identity alerts = %v, want the state's then the drift alert", ids)
	}

	for _, mode := range []string{identityModeOff, identityModeMock} {
		off, err := identityConvergeWiring(identityConvergeDeps{mode: mode})
		reg := &fakeRegistry{}
		off.register(reg)
		if err != nil || off.converger != nil || off.entries() != nil || len(reg.wfs) != 0 || off.alerts(t.Context(), time.Now()) != nil {
			t.Errorf("%s: %+v, %v; want nothing", mode, off, err)
		}
		if identityFeatures(mode, nil, nil) != nil {
			t.Errorf("%s: a features func", mode)
		}
	}
	for name, mut := range map[string]func(*identityConvergeDeps){
		"session": func(d *identityConvergeDeps) { d.session = nil }, "monitor": func(d *identityConvergeDeps) { d.monitor = nil },
		"ledger": func(d *identityConvergeDeps) { d.ledger = nil }, "settings": func(d *identityConvergeDeps) { d.settings = nil },
		"createArmed": func(d *identityConvergeDeps) { d.createArmed = nil }, "stat": func(d *identityConvergeDeps) { d.stat = nil },
		"now": func(d *identityConvergeDeps) { d.now = nil }, "log": func(d *identityConvergeDeps) { d.log = nil },
	} {
		d := convergeDeps(t, identityModeKeycloak, &st)
		mut(&d)
		if _, err := identityConvergeWiring(d); err == nil {
			t.Errorf("a nil %s under keycloak was accepted", name)
		}
	}
	d := identityDeps(t, identityModeKeycloak, &identityCounts{})
	d.features = nil
	if _, err := identityStateWiring(d); err == nil {
		t.Error("identity state: a nil features func under keycloak was accepted")
	}
}

// TC-981-09: with the features check unable to finish (serverinfo
// unreadable) and the identity service refusing rasputin-admin's login with
// invalid_client, the wired identity.recover_admin entry is due: the
// features states never block the recovery that repairs them.
func TestIdentityAdminTrigger_NotBlockedByTheFeaturesCheck(t *testing.T) {
	d := identityDeps(t, identityModeKeycloak, &identityCounts{})
	d.run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		return []byte("ActiveState=active\nSubState=running\nInvocationID=0123456789abcdef0123456789abcdef\n\n" +
			"ActiveState=active\nSubState=running\nInvocationID=fedcba9876543210fedcba9876543210\n"), nil
	}
	d.client = countedHealth{c: &identityCounts{}}
	d.features = func(context.Context, string) (bool, error) {
		return false, &idclient.Error{Op: "admin", Path: "/admin/serverinfo", Kind: idclient.ErrDenied, OAuthError: "invalid_client"}
	}
	st, err := identityStateWiring(d)
	if err != nil {
		t.Fatal(err)
	}
	var nr *identitystate.NotReadyError
	if err := st.monitor.Ready(t.Context()); !errors.As(err, &nr) || nr.State != identitystate.FeaturesUnchecked {
		t.Fatalf("monitor Ready = %v, want NotReadyError{features-unchecked}", err)
	}
	ident := &refusedIdentity{}
	sess, err := idclient.NewSession(idclient.SessionConfig{Login: ident, Admin: ident, Realm: identityRealm,
		ClientID: identityAdminClient, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	holder := &atomic.Pointer[restoredFunc]{}
	f := restoredFunc(func(context.Context, string) error { return nil })
	holder.Store(&f)
	entry, _, err := identityAdminTrigger(identityModeKeycloak, st.monitor, sess, openJobStore(t), holder, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if due, reason := entry.Due(t.Context()); !due {
		t.Errorf("identity.recover_admin Due = false %q, want due", reason)
	}
	if ident.n.Load() == 0 {
		t.Error("the trigger never probed the admin login")
	}
}

// TC-990-23 (wiring part): converge's inputs carry C03's predicate, and its
// read error fails the inputs, so converge writes nothing.
func TestIdentityConvergeInputs_TC990_23_FirstRun(t *testing.T) {
	d := convergeDeps(t, identityModeKeycloak, &identityState{})
	synced := func(context.Context) bool { return false }
	in, err := d.inputs(synced)(t.Context())
	if err != nil || !in.FirstRun {
		t.Errorf("first run: %+v, %v", in.FirstRun, err)
	}
	d.firstRun = func(context.Context) (bool, error) { return false, nil }
	if in, err := d.inputs(synced)(t.Context()); err != nil || in.FirstRun {
		t.Errorf("after the claim: %v, %v", in.FirstRun, err)
	}
	d.firstRun = func(context.Context) (bool, error) { return false, errors.New("unreadable") }
	if _, err := d.inputs(synced)(t.Context()); err == nil {
		t.Error("a first-run read error did not fail the inputs")
	}
	d.firstRun = nil
	if _, err := identityConvergeWiring(d); err == nil {
		t.Error("no first-run predicate was accepted under keycloak")
	}
}
