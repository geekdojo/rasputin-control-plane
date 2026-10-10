//go:build linux

package proxy

// Functional test for geekdojo/geekdojo-brain#831: rasputin-api and the
// node-local Caddy both want :443, and whichever starts second loses. It runs
// StartNodeProxy, the function the agent's main calls, against a REAL Caddy as
// root, and stands in for the api with net.Listen("tcp", ":443") — the address
// rasputin-api.service gives the api and the call ListenAndServeTLS makes.
//
// The same steps run for both roles in both start orders:
//
//   - proxy first: start the proxy; if it returned a reconciler, wait until its
//     LAN listener is up; then the api stand-in binds :443;
//   - api first: the stand-in holds :443; start the proxy; if it returned a
//     reconciler, wait until Caddy's admin socket answers and push the config.
//
// On compute the proxy runs, and both orders reproduce the bench symptoms: the
// stand-in's bind fails with EADDRINUSE, or Caddy refuses the config with a 400
// "address already in use". On a controlplane the proxy must not run, so the
// stand-in binds and serves in both orders and no Caddy exists. Were the proxy
// started on a controlplane, the controlplane rows would fail with exactly the
// compute symptoms.
//
// It needs root and a caddy binary (requireFunctional): CI's "caddy admin
// socket" job runs it with RASPUTIN_CADDY_FUNCTIONAL=required. Every wait is on
// a checkable fact with a hard deadline that names what never happened.

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/host"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

const apiAddr = ":443"

func TestAPIAndProxy443_BothStartOrders(t *testing.T) {
	caddyBin := requireFunctional(t)
	lanIP := host.PrimaryLANIP()
	if lanIP == "" {
		t.Fatal("host.PrimaryLANIP returned no address; the proxy's lan server would not be rendered and the race could not happen")
	}

	base, err := os.MkdirTemp("", "c831")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	// Caddy's autosave and data dirs follow XDG; keep them out of the checkout.
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "xdg-config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(base, "xdg-data"))

	for _, tc := range []struct {
		name      string
		role      proto.NodeRole
		proxyRuns bool
		apiFirst  bool
	}{
		{"TC-831-04 compute proxy first", proto.RoleCompute, true, false},
		{"TC-831-05 compute api first", proto.RoleCompute, true, true},
		{"TC-831-06 controlplane proxy first", proto.RoleControlPlane, false, false},
		{"TC-831-07 controlplane api first", proto.RoleControlPlane, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := os.MkdirTemp(base, "run")
			if err != nil {
				t.Fatal(err)
			}
			h := &raceHarness{t: t, caddyBin: caddyBin, lanIP: lanIP, dir: dir, role: tc.role}
			if tc.apiFirst {
				h.apiFirst(tc.proxyRuns)
			} else {
				h.proxyFirst(tc.proxyRuns)
			}
		})
	}
}

type raceHarness struct {
	t        *testing.T
	caddyBin string
	lanIP    string
	dir      string
	role     proto.NodeRole
	logs     *logkittest.Recorder
	subs     *subscribeRecorder
}

// startProxy calls StartNodeProxy as main does, with the admin socket and state
// under the harness dir. Cleanup cancels its context and waits until its Caddy
// is gone, so the next subtest starts with :443 free.
func (h *raceHarness) startProxy() (*Reconciler, string) {
	t := h.t
	logger, logs := logkittest.New()
	h.logs, h.subs = logs, &subscribeRecorder{}
	sock := filepath.Join(h.dir, "caddy", "admin.sock")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		waitFor(t, convergeWithin, "every caddy this subtest started exiting after its context was cancelled", func() bool {
			return len(caddyPIDs(h.caddyBin)) == 0
		})
	})
	r := StartNodeProxy(ctx, h.role, NodeProxyConfig{
		NodeID:      "node-831",
		StateDir:    filepath.Join(h.dir, "state"),
		AdminSocket: sock,
		CaddyBin:    h.caddyBin,
		TailnetIP:   func() string { return "" },
		LANIP:       host.PrimaryLANIP,
		Subscribe:   h.subs.subscribe,
		Logger:      logger,
	})
	return r, sock
}

// proxyFirst starts the proxy, lets it take the port if it runs, then binds
// the api stand-in.
func (h *raceHarness) proxyFirst(proxyRuns bool) {
	t := h.t
	r, _ := h.startProxy()
	if r != nil {
		lan := net.JoinHostPort(h.lanIP, "443")
		waitFor(t, convergeWithin, "the proxy's lan server listening on "+lan, func() bool {
			c, err := net.DialTimeout("tcp", lan, time.Second)
			if err != nil {
				return false
			}
			_ = c.Close()
			return true
		})
	}

	if proxyRuns {
		if r == nil {
			t.Fatalf("StartNodeProxy on %s returned nil, want a reconciler", h.role)
		}
		ln, err := net.Listen("tcp", apiAddr)
		if err == nil {
			_ = ln.Close()
			t.Fatalf("api stand-in bound %s with the proxy up on %s:443, want EADDRINUSE", apiAddr, h.lanIP)
		}
		if !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatalf("api stand-in bind %s: %v, want EADDRINUSE", apiAddr, err)
		}
		return
	}

	h.assertProxyNotStarted(r)
	ln, err := net.Listen("tcp", apiAddr)
	if err != nil {
		t.Fatalf("api stand-in bind %s after the proxy started first: %v", apiAddr, err)
	}
	defer ln.Close()
	assertServes(t, ln)
}

// apiFirst binds the api stand-in, starts the proxy, and pushes the proxy's
// config if it runs.
func (h *raceHarness) apiFirst(proxyRuns bool) {
	t := h.t
	ln, err := net.Listen("tcp", apiAddr)
	if err != nil {
		t.Fatalf("api stand-in bind %s before the proxy: %v", apiAddr, err)
	}
	defer ln.Close()

	r, sock := h.startProxy()
	var reconcileErr error
	if r != nil {
		waitAdminAnswers(t, h.caddyBin, sock)
		reconcileErr = r.Reconcile()
	}

	if proxyRuns {
		if r == nil {
			t.Fatalf("StartNodeProxy on %s returned nil, want a reconciler", h.role)
		}
		if reconcileErr == nil {
			t.Fatalf("Reconcile with the api stand-in holding %s succeeded, want caddy's 400 address already in use", apiAddr)
		}
		if msg := reconcileErr.Error(); !strings.Contains(msg, "(400)") || !strings.Contains(msg, "address already in use") {
			t.Fatalf("Reconcile error = %v, want caddy's 400 containing address already in use", reconcileErr)
		}
		return
	}

	if reconcileErr != nil {
		t.Errorf("Reconcile with the api stand-in holding %s: %v", apiAddr, reconcileErr)
	}
	h.assertProxyNotStarted(r)
	assertServes(t, ln)
}

// assertProxyNotStarted checks the role that runs no proxy: nil returned, no
// Caddy child, no app.leaf subscription, the one INFO record saying why, and
// no "address already in use" anywhere in what it logged.
func (h *raceHarness) assertProxyNotStarted(r *Reconciler) {
	t := h.t
	t.Helper()
	if r != nil {
		t.Errorf("StartNodeProxy on %s returned a reconciler, want nil", h.role)
	}
	if pids := caddyPIDs(h.caddyBin); len(pids) != 0 {
		t.Errorf("caddy processes %v exist on %s, want none", pids, h.role)
	}
	if n := len(h.subs.registered()); n != 0 {
		t.Errorf("Subscribe called %d times on %s, want 0", n, h.role)
	}
	recs := h.logs.Matching(slog.LevelInfo, notStartedMsg)
	if len(recs) != 1 {
		t.Errorf("got %d INFO %q records, want 1:\n%s", len(recs), notStartedMsg, h.logs.Text())
	} else if role, _ := logkittest.Attr(recs[0], "role"); role != string(h.role) {
		t.Errorf("%q record role = %q, want %q", notStartedMsg, role, h.role)
	}
	if text := h.logs.Text(); strings.Contains(text, "address already in use") {
		t.Errorf("logged address already in use:\n%s", text)
	}
}

// assertServes completes one TCP connection to the api stand-in. The deadlines
// bound single I/O calls.
func assertServes(t *testing.T, ln net.Listener) {
	t.Helper()
	tcp := ln.(*net.TCPListener)
	if err := tcp.SetDeadline(time.Now().Add(convergeWithin)); err != nil {
		t.Fatal(err)
	}
	accepted := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
		accepted <- err
	}()
	c, err := net.DialTimeout("tcp", "127.0.0.1:443", convergeWithin)
	if err != nil {
		t.Fatalf("connect to the api stand-in on 127.0.0.1:443: %v", err)
	}
	_ = c.Close()
	if err := <-accepted; err != nil {
		t.Fatalf("api stand-in never accepted the connection: %v", err)
	}
}
