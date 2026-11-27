package main

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/markers"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// recordingGated records the gate wireControlGate installs.
type recordingGated struct {
	gate auth.ControlGate
	log  *slog.Logger
	n    int
}

func (r *recordingGated) SetControlGate(g auth.ControlGate, log *slog.Logger) {
	r.gate, r.log, r.n = g, log, r.n+1
}

// TC-987-35: under keycloak the auth service gets the converger's gate, the
// converger is the drain's admin and pass sink and the marker writer a user
// sink; in every other mode no gate is installed and control is never
// locked.
func TestSignInRulesWiring(t *testing.T) {
	st, err := identityStateWiring(identityDeps(t, identityModeKeycloak, &identityCounts{}))
	if err != nil {
		t.Fatal(err)
	}
	w, err := identityConvergeWiring(convergeDeps(t, identityModeKeycloak, &st))
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingGated{}
	wireControlGate(rec, w)
	if rec.n != 1 || rec.gate == nil || rec.log == nil {
		t.Fatalf("keycloak: gate installed %d times", rec.n)
	}
	// The installed gate is the converger's: both answer alike.
	if (rec.gate(t.Context()) == nil) != (w.converger.ControlGate(t.Context()) == nil) {
		t.Error("the installed gate is not the converger's")
	}
	sinks := w.eventSinks()
	if len(sinks.admin) != 1 || sinks.admin[0] != any(w.converger) || len(sinks.pass) != 1 || sinks.pass[0] != any(w.converger) {
		t.Errorf("sinks = %+v, want the converger as admin and pass sink", sinks)
	}
	table, err := doors.New("ci")
	if err != nil {
		t.Fatal(err)
	}
	idw := identityWiring{mode: identityModeKeycloak, session: convergeDeps(t, identityModeKeycloak, &st).session, dirty: newIdentityDirty()}
	mw := markerWriter(t.Context(), idw, table, nil, &sync.Mutex{}, slog.New(slog.DiscardHandler))
	if mw == nil {
		t.Fatal("no marker writer under keycloak")
	}
	if markerWriter(t.Context(), identityWiring{mode: identityModeOff}, table, nil, &sync.Mutex{}, slog.New(slog.DiscardHandler)) != nil {
		t.Error("a marker writer outside keycloak")
	}
	deps, th := eventsDeps(t.Context(), idw, &memMarks{m: map[string]string{}}, table, nil, sinks, mw, slog.New(slog.DiscardHandler))
	var writer, throttle bool
	for _, s := range deps.UserSinks {
		switch s.(type) {
		case *markers.Writer:
			writer = true
		case *policy.Throttle:
			throttle = true
		}
	}
	if !writer || !throttle || th == nil || len(deps.AdminSinks) != 1 || deps.AdminSinks[0] != any(w.converger) {
		t.Errorf("drain deps: marker writer %v, throttle %v, admin sinks %v", writer, throttle, deps.AdminSinks)
	}
	if len(deps.PassSinks) != 2 {
		t.Errorf("pass sinks %v, want the converger and the throttle", deps.PassSinks)
	}
	// geekdojo/geekdojo-brain#994 (F-994-01): a user sink the accounts add
	// reaches the drain beside the throttle and the marker writer.
	extra := &countingUserSink{}
	sinks.user = []events.UserSink{extra}
	deps, _ = eventsDeps(t.Context(), idw, &memMarks{m: map[string]string{}}, table, nil, sinks, mw, slog.New(slog.DiscardHandler))
	if len(deps.UserSinks) != 3 || deps.UserSinks[0] != any(extra) {
		t.Errorf("user sinks %v, want the added sink, the throttle and the marker writer", deps.UserSinks)
	}

	// Every other mode: nothing installed, and a real auth service's control
	// POST is never locked.
	store, err := auth.OpenStore(t.Context(), filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	svc, err := auth.NewService(store, auth.Config{RPDisplayName: "R", RPID: "localhost", RPOrigins: []string{"http://localhost"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{identityModeOff, identityModeMock} {
		off, _ := identityConvergeWiring(identityConvergeDeps{mode: mode})
		rec := &recordingGated{}
		wireControlGate(rec, off)
		wireControlGate(svc, off)
		if rec.n != 0 || svc.HasControlGate() {
			t.Errorf("%s: a gate was installed", mode)
		}
		if s := off.eventSinks(); s.admin != nil || s.pass != nil {
			t.Errorf("%s: sinks %+v", mode, s)
		}
	}
}

// The marker writer's doors: the door table's clients, and none without a
// table.
func TestDoorOf(t *testing.T) {
	table, err := doors.New("ci")
	if err != nil {
		t.Fatal(err)
	}
	of := doorOf(table, nil)
	if d, ok := of("rasputin-console"); !ok || d != flows.DoorHome {
		t.Error("the console is not the home door's")
	}
	if d, ok := of("rasputin-account"); !ok || d != flows.DoorApp {
		t.Error("the account client is not the app door's")
	}
	if _, ok := of("immich"); ok {
		t.Error("an unregistered client has a door")
	}
	if _, ok := doorOf(doors.Table{}, doors.ErrNoClusterID)("rasputin-console"); ok {
		t.Error("with no table a client has a door")
	}
}

// TC-987-27: the clock-sync reader and the identity policy: absent is not
// synced, present (empty or not) is synced, a stat failure is not synced
// with one WARN per outage, cleared on recovery; no timesyncd is not synced
// for the identity, while the TLS gate still trusts the clock.
func TestClockSyncFact(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "synchronized")
	withClockPaths(t, dir, marker)
	log, rec := logkittest.New()
	fact := &clockSyncFact{read: readClockSync, log: log}
	ctx := context.Background()
	if fact.Synced(ctx) {
		t.Error("absent: synced")
	}
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if !fact.Synced(ctx) {
		t.Error("present and empty: not synced")
	}
	if err := os.WriteFile(marker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !fact.Synced(ctx) {
		t.Error("present and non-empty: not synced")
	}
	perm := errors.New("stat: permission denied")
	fail := &clockSyncFact{read: func() (bool, bool, error) { return true, false, perm }, log: log}
	if fail.Synced(ctx) {
		t.Error("a stat failure read as synced")
	}
	if fail.Synced(ctx) {
		t.Error("a second stat failure read as synced")
	}
	warn := "The clock-sync signal could not be read, so the authenticator app is not offered."
	if n := len(rec.Matching(slog.LevelWarn, warn)); n != 1 {
		t.Errorf("%d WARNs for one outage, want 1", n)
	}
	fail.read = readClockSync
	fail.Synced(ctx)
	fail.read = func() (bool, bool, error) { return true, false, perm }
	fail.Synced(ctx)
	if n := len(rec.Matching(slog.LevelWarn, warn)); n != 2 {
		t.Errorf("%d WARNs over two outages, want 2", n)
	}
	// The real reader on a marker it cannot stat.
	if os.Geteuid() != 0 {
		if err := os.Chmod(dir, 0o000); err != nil {
			t.Fatal(err)
		}
		_, synced, err := readClockSync()
		_ = os.Chmod(dir, 0o755)
		if synced || err == nil || errors.Is(err, fs.ErrNotExist) {
			t.Errorf("unreadable marker: synced %v, err %v", synced, err)
		}
	}
	withClockPaths(t, filepath.Join(dir, "none"), filepath.Join(dir, "none", "synchronized"))
	if fact.Synced(ctx) {
		t.Error("no timesyncd: synced for the identity")
	}
	if !waitForTrustworthyClock(ctx, 0) {
		t.Error("no timesyncd: the TLS gate does not trust the clock")
	}
}

// F-987-18: under keycloak the mounted door's policy gets the converger as
// its Bindings; in every other mode it gets nil, which the policy answers by
// pausing every client outside the door table.
func TestDoorPolicy_BindingsAreTheConverger(t *testing.T) {
	st, err := identityStateWiring(identityDeps(t, identityModeKeycloak, &identityCounts{}))
	if err != nil {
		t.Fatal(err)
	}
	w, err := identityConvergeWiring(convergeDeps(t, identityModeKeycloak, &st))
	if err != nil {
		t.Fatal(err)
	}
	if b := doorPolicyDeps(doorMountDeps{bindings: w.doorBindings()}).Bindings; b == nil || b != any(w.converger) {
		t.Errorf("keycloak: the door policy's Bindings = %v, want the converger", b)
	}
	for _, mode := range []string{identityModeOff, identityModeMock} {
		off, _ := identityConvergeWiring(identityConvergeDeps{mode: mode})
		if b := doorPolicyDeps(doorMountDeps{bindings: off.doorBindings()}).Bindings; b != nil {
			t.Errorf("%s: the door policy's Bindings = %v, want nil", mode, b)
		}
	}
}

// countingUserSink is a user sink that takes nothing.
type countingUserSink struct{}

func (*countingUserSink) UserEvent(context.Context, events.UserEvent) {}
