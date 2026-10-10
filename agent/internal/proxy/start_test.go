//go:build unix

package proxy

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// stubWithin bounds every wait on the stub caddy below. Each wait is on a
// checkable fact (a file appearing, a process being gone), never a sleep.
const stubWithin = 10 * time.Second

// subscribeRecorder stands in for the agent's subscribe hook: it counts the
// calls and keeps each registration so a test can run it against a bus.
type subscribeRecorder struct {
	mu  sync.Mutex
	fns []func(*nats.Conn) error
}

func (s *subscribeRecorder) subscribe(fn func(*nats.Conn) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fns = append(s.fns, fn)
}

func (s *subscribeRecorder) registered() []func(*nats.Conn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]func(*nats.Conn) error(nil), s.fns...)
}

const notStartedMsg = "node-local app proxy not started"

// stubCaddy writes a shell script that stands in for the caddy binary: when
// run it writes its pid to marker and then sleeps until it is killed. exec keeps
// the pid, so the pid in the marker is the process RunCaddy supervises.
func stubCaddy(t *testing.T, dir string) (bin, marker string) {
	t.Helper()
	bin = filepath.Join(dir, "caddy-stub")
	marker = filepath.Join(dir, "caddy-stub.started")
	script := "#!/bin/sh\necho $$ > '" + marker + ".tmp' && mv '" + marker + ".tmp' '" + marker + "'\nexec sleep 86400\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, marker
}

// startTestConfig is a NodeProxyConfig whose state and admin socket live under
// dir, a directory this test's uid owns (PrepareAdminDir accepts it).
func startTestConfig(dir, caddyBin string, logger *slog.Logger, subs *subscribeRecorder) NodeProxyConfig {
	return NodeProxyConfig{
		NodeID:      "node-831",
		StateDir:    filepath.Join(dir, "state"),
		AdminSocket: filepath.Join(dir, "caddy", "admin.sock"),
		CaddyBin:    caddyBin,
		TailnetIP:   func() string { return "" },
		LANIP:       func() string { return "127.0.0.1" },
		Subscribe:   subs.subscribe,
		Logger:      logger,
	}
}

// waitStubPID waits for the stub's marker file and returns the pid it holds.
func waitStubPID(t *testing.T, marker string) int {
	t.Helper()
	waitFor(t, stubWithin, "the stub caddy writing its start marker "+marker, func() bool {
		_, err := os.Stat(marker)
		return err == nil
	})
	b, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("stub caddy marker %s holds %q, not a pid", marker, b)
	}
	return pid
}

// waitProcessGone waits until pid no longer exists (reaped by RunCaddy).
func waitProcessGone(t *testing.T, pid int) {
	t.Helper()
	waitFor(t, stubWithin, "stub caddy pid "+strconv.Itoa(pid)+" exiting after its context was cancelled", func() bool {
		return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
	})
}

// TC-831-02: on a controlplane StartNodeProxy starts no Caddy, registers no
// app.leaf handler, returns nil, and says why once at INFO.
func TestStartNodeProxy_ControlplaneStartsNothing(t *testing.T) {
	dir := t.TempDir()
	bin, marker := stubCaddy(t, dir)
	logger, logs := logkittest.New()
	subs := &subscribeRecorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := StartNodeProxy(ctx, proto.RoleControlPlane, startTestConfig(dir, bin, logger, subs))

	if r != nil {
		t.Errorf("StartNodeProxy on a controlplane returned a reconciler, want nil")
	}
	if n := len(subs.registered()); n != 0 {
		t.Errorf("Subscribe called %d times on a controlplane, want 0 (no app.leaf subscription)", n)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stub caddy start marker %s: err %v, want it absent (caddy must not start)", marker, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "caddy")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("caddy admin dir was created on a controlplane (err %v), want nothing prepared", err)
	}

	recs := logs.Records()
	if len(recs) != 1 {
		t.Fatalf("got %d log records, want exactly 1: %v", len(recs), recs)
	}
	rec := recs[0]
	if rec.Level != slog.LevelInfo || !strings.Contains(rec.Message, notStartedMsg) {
		t.Errorf("record = %s %q, want INFO %q", rec.Level, rec.Message, notStartedMsg)
	}
	if role, ok := logkittest.Attr(rec, "role"); !ok || role != string(proto.RoleControlPlane) {
		t.Errorf("record role = %q (present %v), want %q", role, ok, proto.RoleControlPlane)
	}
	if reason, ok := logkittest.Attr(rec, "reason"); !ok || reason == "" {
		t.Errorf("record reason = %q (present %v), want a non-empty reason", reason, ok)
	}
}

// TC-831-03: on compute StartNodeProxy starts Caddy, registers the app.leaf
// handler once, returns the reconciler, and logs neither a skip nor a WARN.
func TestStartNodeProxy_ComputeStartsCaddy(t *testing.T) {
	dir := t.TempDir()
	bin, marker := stubCaddy(t, dir)
	logger, logs := logkittest.New()
	subs := &subscribeRecorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := StartNodeProxy(ctx, proto.RoleCompute, startTestConfig(dir, bin, logger, subs))

	if r == nil {
		t.Fatal("StartNodeProxy on compute returned nil, want a reconciler")
	}
	if n := len(subs.registered()); n != 1 {
		t.Errorf("Subscribe called %d times on compute, want 1 (the app.leaf subscription)", n)
	}
	pid := waitStubPID(t, marker)

	if text := logs.Text(); strings.Contains(text, notStartedMsg) {
		t.Errorf("compute logged %q, want no such record:\n%s", notStartedMsg, text)
	}
	if recs := logs.AtLevel(slog.LevelWarn); len(recs) != 0 {
		t.Errorf("compute with a caddy binary logged %d WARN records, want none: %v", len(recs), recs)
	}

	cancel()
	waitProcessGone(t, pid)
}

// TC-831-10: on compute with no caddy binary, StartNodeProxy still subscribes
// (leaves are still delivered) and returns the reconciler, starts no Caddy, and
// logs one WARN carrying node_id.
func TestStartNodeProxy_ComputeWithoutCaddy(t *testing.T) {
	dir := t.TempDir()
	logger, logs := logkittest.New()
	subs := &subscribeRecorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := startTestConfig(dir, "", logger, subs)

	r := StartNodeProxy(ctx, proto.RoleCompute, cfg)

	if r == nil {
		t.Fatal("StartNodeProxy on compute without caddy returned nil, want a reconciler")
	}
	fns := subs.registered()
	if len(fns) != 1 {
		t.Fatalf("Subscribe called %d times, want 1 (leaves are still delivered)", len(fns))
	}
	// No Caddy: RunCaddy's first act is preparing the admin directory, so its
	// absence shows the supervisor never ran.
	if _, err := os.Stat(filepath.Dir(cfg.AdminSocket)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("caddy admin dir exists (err %v), want no caddy supervisor started", err)
	}

	warns := logs.AtLevel(slog.LevelWarn)
	if len(warns) != 1 {
		t.Fatalf("got %d WARN records, want exactly 1: %v", len(warns), warns)
	}
	if !strings.Contains(warns[0].Message, "node-local proxy disabled") {
		t.Errorf("WARN message = %q, want it to say the node-local proxy is disabled", warns[0].Message)
	}
	if id, ok := logkittest.Attr(warns[0], "node_id"); !ok || id != cfg.NodeID {
		t.Errorf("WARN node_id = %q (present %v), want %q", id, ok, cfg.NodeID)
	}

	// The registration it handed to Subscribe delivers a leaf into the store
	// under <StateDir>/proxy, Caddy or not.
	nc := startNATS(t)
	if err := fns[0](nc); err != nil {
		t.Fatalf("subscribed registration: %v", err)
	}
	if ack := requestLeaf(t, nc, cfg.NodeID, proto.AppLeafCmd{
		AppID: "app-1", Name: "app", CertPEM: []byte("CERT"), KeyPEM: []byte("KEY"), TailnetFQDN: "app.example.internal", UpstreamPort: 8080,
	}); !ack.OK {
		t.Fatalf("leaf delivery ack not OK: %+v", ack)
	}
	store := NewLeafStore(filepath.Join(cfg.StateDir, "proxy"))
	if b, err := os.ReadFile(store.CertPath("app-1")); err != nil || string(b) != "CERT" {
		t.Errorf("delivered leaf at %s = %q (err %v), want CERT", store.CertPath("app-1"), b, err)
	}
}

// F-831-08: when the bus connection refuses the app.leaf subscription, the
// registration StartNodeProxy hands to Subscribe returns the failure wrapped
// with what it was doing, so the agent's subscribe hook can report it.
func TestStartNodeProxy_RegistrationErrorIsWrapped(t *testing.T) {
	dir := t.TempDir()
	logger, _ := logkittest.New()
	subs := &subscribeRecorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if r := StartNodeProxy(ctx, proto.RoleCompute, startTestConfig(dir, "", logger, subs)); r == nil {
		t.Fatal("StartNodeProxy on compute returned nil, want a reconciler")
	}
	fns := subs.registered()
	if len(fns) != 1 {
		t.Fatalf("Subscribe called %d times, want 1", len(fns))
	}

	nc := startNATS(t)
	nc.Close()
	err := fns[0](nc)
	if err == nil {
		t.Fatal("registration on a closed connection succeeded, want an error")
	}
	if !strings.HasPrefix(err.Error(), "register proxy handlers: ") {
		t.Errorf("registration error = %q, want it prefixed %q", err, "register proxy handlers: ")
	}
	if !errors.Is(err, nats.ErrConnectionClosed) {
		t.Errorf("registration error = %v, want it to wrap nats.ErrConnectionClosed", err)
	}
}
