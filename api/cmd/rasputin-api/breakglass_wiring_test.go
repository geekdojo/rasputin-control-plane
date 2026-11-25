package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/breakglass"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

type nopAlerts struct{}

func (nopAlerts) RaiseBreakGlassIssued(context.Context, string) error   { return nil }
func (nopAlerts) RaiseBreakGlassRedeemed(context.Context, string) error { return nil }

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

// Off keycloak there is no identity.restart, and the break-glass service
// reports no sign-in service, with RESTART never enabled; the ways follow
// the BMC-host marker file.
func TestWireBreakglass_IdentityOff(t *testing.T) {
	if r, err := identityRestartWiring(nil, nil, nil, nil); r != nil || err != nil {
		t.Fatalf("identityRestartWiring off keycloak = %v, %v", r, err)
	}
	log, rec := logkittest.New()
	dir := t.TempDir()
	w, err := wireBreakglass(context.Background(), breakglassDeps{alerts: nopAlerts{}, jobs: nopJobs{}, host: "ci.local",
		primaryIP: func() net.IP { return net.IPv4(192, 0, 2, 1) }, dataDir: dir, log: log})
	if err != nil {
		t.Fatal(err)
	}
	st := w.svc.State(context.Background(), breakglass.Session{})
	if st.Actions[0].Enabled || st.Sentence != "Sign-in isn't installed on this control plane." {
		t.Errorf("state %+v", st)
	}
	if n := len(w.svc.Ways().Ways); n != 3 {
		t.Errorf("%d ways without the marker", n)
	}
	if err := os.WriteFile(filepath.Join(dir, "bmc-host"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if n := len(w.svc.Ways().Ways); n != 2 {
		t.Errorf("%d ways with the marker", n)
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
		primaryIP: func() net.IP { return nil }, dataDir: dir, log: log})
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
