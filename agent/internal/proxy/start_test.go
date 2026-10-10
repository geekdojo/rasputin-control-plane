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

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// stubWithin bounds every wait on the stub caddy below. Each wait is on a
// checkable fact (a file appearing, a process being gone), never a sleep.
const stubWithin = 10 * time.Second

// captureHandler is a slog.Handler that keeps every record it is given.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

func (h *captureHandler) all() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]slog.Record(nil), h.records...)
}

// withMessage returns the captured records whose message contains substr.
func (h *captureHandler) withMessage(substr string) []slog.Record {
	var out []slog.Record
	for _, r := range h.all() {
		if strings.Contains(r.Message, substr) {
			out = append(out, r)
		}
	}
	return out
}

// atLevel returns the captured records at level.
func (h *captureHandler) atLevel(level slog.Level) []slog.Record {
	var out []slog.Record
	for _, r := range h.all() {
		if r.Level == level {
			out = append(out, r)
		}
	}
	return out
}

// attr returns the string value of record r's attribute key, and whether it is
// present.
func attr(r slog.Record, key string) (string, bool) {
	var val string
	var found bool
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			val, found = a.Value.String(), true
			return false
		}
		return true
	})
	return val, found
}

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
func startTestConfig(dir, caddyBin string, logs *captureHandler, subs *subscribeRecorder) NodeProxyConfig {
	return NodeProxyConfig{
		NodeID:      "node-831",
		StateDir:    filepath.Join(dir, "state"),
		AdminSocket: filepath.Join(dir, "caddy", "admin.sock"),
		CaddyBin:    caddyBin,
		TailnetIP:   func() string { return "" },
		LANIP:       func() string { return "127.0.0.1" },
		Subscribe:   subs.subscribe,
		Logger:      slog.New(logs),
	}
}

// waitStubPID waits for the stub's marker file and returns the pid it holds.
func waitStubPID(t *testing.T, marker string) int {
	t.Helper()
	deadline := time.Now().Add(stubWithin)
	for {
		if b, err := os.ReadFile(marker); err == nil {
			pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
			if err != nil {
				t.Fatalf("stub caddy marker %s holds %q, not a pid", marker, b)
			}
			return pid
		}
		if time.Now().After(deadline) {
			t.Fatalf("never happened within %s: the stub caddy writing its start marker %s", stubWithin, marker)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitProcessGone waits until pid no longer exists (reaped by RunCaddy).
func waitProcessGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(stubWithin)
	for {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("never happened within %s: stub caddy pid %d exiting after its context was cancelled", stubWithin, pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TC-831-02: on a controlplane StartNodeProxy starts no Caddy, registers no
// app.leaf handler, returns nil, and says why once at INFO.
func TestStartNodeProxy_ControlplaneStartsNothing(t *testing.T) {
	dir := t.TempDir()
	bin, marker := stubCaddy(t, dir)
	logs, subs := &captureHandler{}, &subscribeRecorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := StartNodeProxy(ctx, proto.RoleControlPlane, startTestConfig(dir, bin, logs, subs))

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

	recs := logs.all()
	if len(recs) != 1 {
		t.Fatalf("got %d log records, want exactly 1: %v", len(recs), recs)
	}
	rec := recs[0]
	if rec.Level != slog.LevelInfo || !strings.Contains(rec.Message, notStartedMsg) {
		t.Errorf("record = %s %q, want INFO %q", rec.Level, rec.Message, notStartedMsg)
	}
	if role, ok := attr(rec, "role"); !ok || role != string(proto.RoleControlPlane) {
		t.Errorf("record role = %q (present %v), want %q", role, ok, proto.RoleControlPlane)
	}
	if reason, ok := attr(rec, "reason"); !ok || reason == "" {
		t.Errorf("record reason = %q (present %v), want a non-empty reason", reason, ok)
	}
}

// TC-831-03: on compute StartNodeProxy starts Caddy, registers the app.leaf
// handler once, returns the reconciler, and logs neither a skip nor a WARN.
func TestStartNodeProxy_ComputeStartsCaddy(t *testing.T) {
	dir := t.TempDir()
	bin, marker := stubCaddy(t, dir)
	logs, subs := &captureHandler{}, &subscribeRecorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := StartNodeProxy(ctx, proto.RoleCompute, startTestConfig(dir, bin, logs, subs))

	if r == nil {
		t.Fatal("StartNodeProxy on compute returned nil, want a reconciler")
	}
	if n := len(subs.registered()); n != 1 {
		t.Errorf("Subscribe called %d times on compute, want 1 (the app.leaf subscription)", n)
	}
	pid := waitStubPID(t, marker)

	if recs := logs.withMessage(notStartedMsg); len(recs) != 0 {
		t.Errorf("compute logged %d %q records, want none", len(recs), notStartedMsg)
	}
	if recs := logs.atLevel(slog.LevelWarn); len(recs) != 0 {
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
	logs, subs := &captureHandler{}, &subscribeRecorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := startTestConfig(dir, "", logs, subs)

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

	warns := logs.atLevel(slog.LevelWarn)
	if len(warns) != 1 {
		t.Fatalf("got %d WARN records, want exactly 1: %v", len(warns), warns)
	}
	if !strings.Contains(warns[0].Message, "node-local proxy disabled") {
		t.Errorf("WARN message = %q, want it to say the node-local proxy is disabled", warns[0].Message)
	}
	if id, ok := attr(warns[0], "node_id"); !ok || id != cfg.NodeID {
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
