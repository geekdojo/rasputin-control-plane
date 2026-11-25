package main

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// issuedFake is a door policy's issued-action set, told apart by identity.
type issuedFake struct{ name string }

func (*issuedFake) Issued(context.Context, policy.ActionRequest) (bool, error) { return false, nil }

// TC-1150-14: the composition root wires the console sign-in as the doors'
// issued actions and the one clock fact, and fails closed without them.
func TestWiring_TC1150_14(t *testing.T) {
	t.Run("(a) doorPolicyDeps passes the given actions", func(t *testing.T) {
		fake := &issuedFake{name: "launcher"}
		got := doorPolicyDeps(doorMountDeps{actions: fake}).Actions
		if got != policy.Actions(fake) {
			t.Errorf("Actions = %#v, want the given fake", got)
		}
		if _, stand := got.(policy.NoActionsIssued); stand {
			t.Error("Actions is still NoActionsIssued")
		}
	})
	t.Run("(b) no sign-in built is a nil interface", func(t *testing.T) {
		if a := (consoleSignIn{}).doorActions(); a != nil {
			t.Errorf("doorActions() = %#v, want a nil interface", a)
		}
	})
	t.Run("(c) mountDoors without actions builds no doors", func(t *testing.T) {
		f := newMountFixture(t)
		f.deps.actions = nil
		if h, a := mountDoors(context.Background(), f.deps); h != nil || a != nil {
			t.Fatal("built doors with no issued actions")
		}
		got := f.rec.Matching(slog.LevelError, "sign-in doors not served")
		if len(got) != 1 {
			t.Fatalf("%d ERROR records, want 1:\n%s", len(got), f.rec.Text())
		}
		if v, _ := logkittest.Attr(got[0], "configfault"); v != "true" {
			t.Errorf("configfault = %q", v)
		}
	})
	t.Run("(d) consoleSignInWiring refuses a nil clock", func(t *testing.T) {
		table, err := doors.New("ci")
		if err != nil {
			t.Fatal(err)
		}
		_, sessions := consoleAuth(t)
		_, err = consoleSignInWiring(t.Context(), consoleSignInDeps{mode: identityModeKeycloak, doorsOn: true, table: table, host: "ci.local",
			client: idclient.Disabled{Kind: idclient.ErrDisabled}, session: &recordingAdmin{}, ready: readyNow{},
			sessions: sessions, identity: sessionsEnder(), firstRun: notFirstRun{}, claimer: noClaimer{}, observer: noObserver{},
			now: time.Now, log: slog.New(slog.DiscardHandler)})
		if err == nil {
			t.Error("a nil clock under keycloak with the doors on was accepted")
		}
	})
	t.Run("(e) identityConvergeWiring refuses a nil clock", func(t *testing.T) {
		st, err := identityStateWiring(identityDeps(t, identityModeKeycloak, &identityCounts{}))
		if err != nil {
			t.Fatal(err)
		}
		d := convergeDeps(t, identityModeKeycloak, &st)
		d.clock = nil
		if _, err := identityConvergeWiring(d); err == nil {
			t.Error("a nil clock under keycloak was accepted")
		}
	})
}
