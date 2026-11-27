package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/breakglass"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/pwpolicy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

type nopAlerts struct{}

func (nopAlerts) RaiseBreakGlassIssued(context.Context, string) error   { return nil }
func (nopAlerts) RaiseBreakGlassRedeemed(context.Context, string) error { return nil }
func (nopAlerts) RaiseBreakGlassReset(context.Context, string, string) error {
	return nil
}

type nopJobs struct{}

func (nopJobs) GetJob(context.Context, string) (*jobs.Job, error) { return nil, nil }

type hashStore struct{ id string }

func (h hashStore) CurrentHashID(context.Context) (string, error) { return h.id, nil }

// The subcommand is matched by its exact name only.
func TestIsRepairCode(t *testing.T) {
	for _, c := range []struct {
		args []string
		want bool
	}{
		{[]string{"rasputin-api", "repair-code"}, true}, {[]string{"rasputin-api"}, false},
		{[]string{"rasputin-api", "repair"}, false}, {[]string{"rasputin-api", "--repair-code"}, false},
	} {
		if got := isRepairCode(c.args); got != c.want {
			t.Errorf("%v: %v", c.args, got)
		}
	}
}

// nopRun is a systemctl that lists no unit.
func nopRun(context.Context, string, ...string) ([]byte, error) { return nil, nil }

// Off keycloak there is no identity.restart, and the break-glass service
// reports no sign-in service, with RESTART never enabled. TC-321-74 and
// TC-321-76: the ways follow the BMC-host marker file and, without it, the
// serial gettys systemctl lists as active, read with TC-321-72's argv; a
// nil run is refused.
func TestWireBreakglass_IdentityOff(t *testing.T) {
	if r, err := identityRestartWiring(nil, nil, nil, nil); r != nil || err != nil {
		t.Fatalf("identityRestartWiring off keycloak = %v, %v", r, err)
	}
	log, rec := logkittest.New()
	dir := t.TempDir()
	var calls []string
	listed := "serial-getty@ttyAMA10.service loaded active running Serial Getty on ttyAMA10\n"
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return []byte(listed), nil
	}
	deps := breakglassDeps{alerts: nopAlerts{}, jobs: nopJobs{}, host: "ci.local",
		primaryIP: func() net.IP { return net.IPv4(192, 0, 2, 1) }, dataDir: dir, log: log, run: run}
	w, err := wireBreakglass(context.Background(), deps)
	if err != nil {
		t.Fatal(err)
	}
	st := w.svc.State(context.Background(), breakglass.Session{})
	if st.Actions[0].Enabled || st.Sentence != "Sign-in isn't installed on this control plane." {
		t.Errorf("state %+v", st)
	}
	if n := len(w.svc.Ways(context.Background()).Ways); n != 3 {
		t.Errorf("%d ways without the marker and with a getty active, want 3", n)
	}
	want := []string{"systemctl list-units --type=service --state=active --plain --no-legend serial-getty@*.service"}
	if !slices.Equal(calls, want) {
		t.Errorf("run calls %q, want %q", calls, want)
	}
	listed = ""
	if n := len(w.svc.Ways(context.Background()).Ways); n != 2 {
		t.Errorf("%d ways without the marker and with no getty active, want 2", n)
	}
	listed, calls = "serial-getty@ttyAMA10.service loaded active running Serial Getty on ttyAMA10\n", nil
	if err := os.WriteFile(filepath.Join(dir, "bmc-host"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if n := len(w.svc.Ways(context.Background()).Ways); n != 2 {
		t.Errorf("%d ways with the marker, want 2", n)
	}
	if len(calls) != 0 {
		t.Errorf("run called with the marker present: %q", calls)
	}
	noRun := deps
	noRun.run = nil
	if _, err := wireBreakglass(context.Background(), noRun); err == nil {
		t.Error("a nil run wired")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if w.socket.Start(ctx) {
		t.Error("the socket was served with no identity CA")
	}
	if len(rec.Records()) == 0 {
		t.Error("the socket's refusal was not logged")
	}
	if _, err := wireBreakglass(context.Background(), breakglassDeps{}); err == nil {
		t.Error("an empty breakglassDeps wired")
	}
	// A dev run with no cluster id: no console origin, so break-glass is off
	// at INFO and the api still starts.
	off, err := wireBreakglass(context.Background(), breakglassDeps{alerts: nopAlerts{}, jobs: nopJobs{},
		primaryIP: func() net.IP { return nil }, dataDir: dir, log: log, run: nopRun})
	if err != nil || off.svc != nil || off.socket != nil {
		t.Errorf("no cluster id: %+v, %v; want off", off, err)
	}
	if len(rec.Matching(slog.LevelInfo, "break-glass off: no cluster id")) != 1 {
		t.Error("break-glass off was not logged at INFO")
	}
}

// TC-321-23 (the file): the warning shows with no console password and an
// authorized_keys that is absent, empty or holds only comment and invalid
// lines; it doesn't with a password or with one valid key line.
func TestLastResortAlerts_TC321_23(t *testing.T) {
	const valid = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK2AcGjrl5kW bryce@laptop"
	dir := t.TempDir()
	now := time.Now()
	for name, c := range map[string]struct {
		body *string
		hash string
		want int
	}{
		"absent":                     {nil, "", 1},
		"empty":                      {ptr(""), "", 1},
		"comments and invalid lines": {ptr("# a comment\nnot a key\nssh-rsa\n\n"), "", 1},
		"one valid key line":         {ptr("# keys\n" + valid + "\n"), "", 0},
		"a console password":         {nil, "hash-1", 0},
	} {
		path := filepath.Join(dir, name)
		if c.body != nil {
			if err := os.WriteFile(path, []byte(*c.body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if got := lastResortAlerts(hashStore{c.hash}, path)(context.Background(), now); len(got) != c.want {
			t.Errorf("%s: %d alerts, want %d", name, len(got), c.want)
		}
	}
	if _, err := authorizedKeyLines(dir)(); err == nil {
		t.Error("reading a directory as authorized_keys gave no error")
	}
}

// downAdmins is an administrators read that fails.
type downAdmins struct{}

func (downAdmins) Administrators(context.Context) ([]accounts.Account, error) {
	return nil, errors.New("identity down")
}
func (downAdmins) List(context.Context) ([]accounts.Designation, error) { return nil, nil }
func (downAdmins) Read(context.Context, string) (accounts.Person, error) {
	return accounts.Person{}, errors.New("identity down")
}
func (downAdmins) Check(secret.Value, string, string) (pwpolicy.Refusal, error) {
	return pwpolicy.Refusal{}, nil
}
func (downAdmins) SubmitFor(context.Context, authz.Submitter, string, any, func(string) error) (*jobs.Job, error) {
	return nil, errors.New("not here")
}

// TC-321-52: under keycloak the service gets the reset and the move's state
// (the reset listed, the move read); off keycloak, or given nil pointers,
// neither is wired and the reset is never listed. The lost-accounts alert
// over an empty holder raises nothing.
func TestWireBreakglass_TC321_52_ResetAndMove(t *testing.T) {
	resets, err := accounts.NewRepairResets(accounts.RepairResetsDeps{Admins: downAdmins{}, Designations: downAdmins{},
		Users: downAdmins{}, Checker: downAdmins{}, Runner: downAdmins{}, Held: accounts.NewHeld(), Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	holder := &moveStateHolder{}
	wire := func(mode string, r *accounts.RepairResets, m *moveStateHolder) (breakglass.StateView, *logkittest.Recorder) {
		t.Helper()
		log, rec := logkittest.New()
		w, err := wireBreakglass(context.Background(), breakglassDeps{alerts: nopAlerts{}, jobs: nopJobs{}, host: "ci.local",
			primaryIP: func() net.IP { return nil }, dataDir: t.TempDir(), log: log, resets: r, move: m, mode: mode, run: nopRun})
		if err != nil {
			t.Fatal(err)
		}
		return w.svc.State(context.Background(), breakglass.Session{}), rec
	}
	listed := func(st breakglass.StateView, id string) *breakglass.Action {
		for i := range st.Actions {
			if st.Actions[i].ID == id {
				return &st.Actions[i]
			}
		}
		return nil
	}
	st, rec := wire(identityModeKeycloak, resets, holder)
	if a := listed(st, "reset"); a == nil || a.Enabled || a.Reason == "" {
		t.Errorf("keycloak: reset %+v, want it listed and disabled by the failed read", a)
	}
	if listed(st, "move") != nil || len(rec.Matching(slog.LevelWarn, "")) == 0 {
		t.Errorf("keycloak: the move was listed, or its unwired read not logged:\n%s", rec.Text())
	}
	for name, c := range map[string]struct {
		mode string
		r    *accounts.RepairResets
		m    *moveStateHolder
	}{
		"off keycloak": {identityModeOff, resets, holder},
		"nil pointers": {identityModeKeycloak, nil, nil},
	} {
		st, rec := wire(c.mode, c.r, c.m)
		if listed(st, "reset") != nil || listed(st, "move") != nil || len(rec.Matching(slog.LevelWarn, "")) != 0 {
			t.Errorf("%s: actions %+v", name, st.Actions)
		}
	}
	if got := lostAccountsAlerts(holder)(context.Background(), time.Now()); len(got) != 0 {
		t.Errorf("an empty holder raised %+v", got)
	}
}
