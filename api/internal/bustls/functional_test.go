package bustls_test

// THE FUNCTIONAL TEST for bus TLS (geekdojo/geekdojo-brain#448): the real
// embedded bus (bus.Start, with auth callout enforced), the real inventory
// service and the real bustls service, wired the way cmd/rasputin-api wires
// them — and the REAL rasputin-agent binary, built from this workspace and run
// as a subprocess, doing the TLS handshake and the pin check itself.
//
// Why a subprocess: the agent's client lives in agent/internal and cannot be
// imported from the api module, and the parts most likely to be wrong are in
// agent main — where the pin is resolved, where a delivered one is saved, and
// what the registration reports. A copy of the client wired by this test would
// prove the copy.
//
// Every wait is for a checkable fact with a deadline — a registration that
// says busTls, a log line naming the refusal — never a sleep.
//
// What it does NOT prove: anything about the OS or firewall images (firstboot,
// apply-seed, the seed scrub), mDNS resolution of <cluster>.local, or real
// clocks on real hardware. That is the bench plan in the PR.
//
// Run alone: scripts/test-bus-tls.sh.

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

const factDeadline = 45 * time.Second

// --- the agent binary --------------------------------------------------------

var (
	agentBinOnce sync.Once
	agentBin     string
	agentBinErr  error
)

func buildAgent(t *testing.T) string {
	t.Helper()
	agentBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "bustls-agent-")
		if err != nil {
			agentBinErr = err
			return
		}
		agentBin = filepath.Join(dir, "rasputin-agent")
		// The go on PATH, with this process's environment (GOTOOLCHAIN, GOWORK,
		// GOFLAGS) — the same toolchain `go test` was run with.
		goBin, err := exec.LookPath("go")
		if err != nil {
			agentBinErr = fmt.Errorf("the agent binary is built with the go command, and none is on PATH: %w", err)
			return
		}
		cmd := exec.Command(goBin, "build", "-o", agentBin, "github.com/geekdojo/rasputin-control-plane/agent/cmd/rasputin-agent") // G204: fixed arguments, the test's own toolchain
		out, err := cmd.CombinedOutput()
		if err != nil {
			agentBinErr = fmt.Errorf("go build rasputin-agent: %v\n%s", err, out)
		}
	})
	if agentBinErr != nil {
		t.Fatal(agentBinErr)
	}
	return agentBin
}

// agentProc is one running agent, with its log lines captured.
type agentProc struct {
	id       string
	stateDir string
	cmd      *exec.Cmd

	mu    sync.Mutex
	lines []string
	done  chan struct{}
}

type agentOpts struct {
	id    string
	role  proto.NodeRole
	url   string
	token string
	pin   string // RASPUTIN_BUS_PIN; "" leaves it unset
	// stateDir reuses a previous agent's state (a restart); "" is fresh.
	stateDir string
}

func startAgent(t *testing.T, o agentOpts) *agentProc {
	t.Helper()
	bin := buildAgent(t)
	if o.stateDir == "" {
		o.stateDir = t.TempDir()
	}
	if o.role == "" {
		o.role = proto.RoleCompute
	}
	a := &agentProc{id: o.id, stateDir: o.stateDir, done: make(chan struct{})}
	cmd := exec.Command(bin) // G204: the binary this test just built
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + o.stateDir,
		"RASPUTIN_NODE_ID=" + o.id,
		"RASPUTIN_NODE_ROLE=" + string(o.role),
		"RASPUTIN_NATS_URL=" + o.url,
		"RASPUTIN_AGENT_STATE_DIR=" + o.stateDir,
		// Mock every backend: this test is about the bus, and an autodetect
		// that found a real docker or tailscale on the runner would make it
		// about the runner.
		"RASPUTIN_DOCKER_BACKEND=mock",
		"RASPUTIN_UPDATE_BACKEND=mock",
		"RASPUTIN_STORAGE_BACKEND=mock",
		"RASPUTIN_TAILSCALE_BACKEND=mock",
		"RASPUTIN_RESOLVED_DROPIN_DIR=" + filepath.Join(o.stateDir, "resolved"),
		"RASPUTIN_CP_MDNS_NAME=bustls-functional-" + o.id,
	}
	if o.token != "" {
		env = append(env, "RASPUTIN_CP_JOIN_TOKEN="+o.token)
	}
	if o.pin != "" {
		env = append(env, "RASPUTIN_BUS_PIN="+o.pin)
	}
	cmd.Env = env
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatalf("start agent %s: %v", o.id, err)
	}
	a.cmd = cmd
	go func() {
		defer close(a.done)
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			a.mu.Lock()
			a.lines = append(a.lines, sc.Text())
			a.mu.Unlock()
		}
	}()
	t.Cleanup(func() { a.stop(t) })
	return a
}

func (a *agentProc) stop(t *testing.T) {
	if a.cmd.ProcessState != nil {
		return
	}
	_ = a.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-a.done:
	case <-time.After(10 * time.Second):
		_ = a.cmd.Process.Kill()
		<-a.done
	}
	_ = a.cmd.Wait()
	if t.Failed() {
		a.mu.Lock()
		t.Logf("--- agent %s log ---\n%s", a.id, strings.Join(a.lines, "\n"))
		a.mu.Unlock()
	}
}

// waitLog waits for a log line containing every one of subs.
func (a *agentProc) waitLog(t *testing.T, what string, subs ...string) string {
	t.Helper()
	end := time.Now().Add(factDeadline)
	for time.Now().Before(end) {
		a.mu.Lock()
		for _, l := range a.lines {
			all := true
			for _, s := range subs {
				all = all && strings.Contains(l, s)
			}
			if all {
				a.mu.Unlock()
				return l
			}
		}
		a.mu.Unlock()
		select {
		case <-a.done:
			t.Fatalf("agent %s exited before %s", a.id, what)
		case <-time.After(50 * time.Millisecond):
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	t.Fatalf("agent %s: no log line for %s within %s (wanted %q)\n%s", a.id, what, factDeadline, subs, strings.Join(a.lines, "\n"))
	return ""
}

// --- the controlplane --------------------------------------------------------

type cp struct {
	dataDir  string
	port     int
	srv      *bus.Server
	inv      *inventory.Store
	svc      *bustls.Service
	key      *bustls.Key
	restarts atomic.Int32

	regMu sync.Mutex
	regs  []proto.NodeRegisteredEvt

	// tokens is the bus join-token store, so a scenario can mint a real
	// node-bound token (unbound tokens do not exist).
	tokens *busauth.Store

	stopFn func()
}

// stop shuts this controlplane instance down (idempotent).
func (c *cp) stop() { c.stopFn() }

type cpOpts struct {
	dataDir string // reuse (a restart); "" is fresh
	port    int    // reuse (a restart); 0 lets the server pick
	mode    bustls.Mode
	// cert overrides the certificate wrapped around the bus key.
	cert *tls.Certificate
}

func startCP(t *testing.T, o cpOpts) *cp {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	if o.dataDir == "" {
		o.dataDir = t.TempDir()
	}
	if o.port == 0 {
		o.port = -1 // the server picks; read back below
	}
	c := &cp{dataDir: o.dataDir}
	dbPath := filepath.Join(o.dataDir, "rasputin.db")

	key, _, err := bustls.EnsureKey(filepath.Join(o.dataDir, "bus"))
	if err != nil {
		t.Fatal(err)
	}
	c.key = key
	serverTLS, err := key.ServerTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if o.cert != nil {
		serverTLS = bustls.ServerTLSConfigFor(*o.cert)
	}
	issuer, err := busauth.EnsureIssuer(filepath.Join(o.dataDir, "bus"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := bus.Start(ctx, bus.Config{
		Host: "127.0.0.1", Port: o.port, StoreDir: filepath.Join(o.dataDir, "nats"),
		AuthEnforce: true, IssuerPublicKey: issuer.PublicKey(), APIUser: "rasputin-api", APIPass: "functional-test",
		TLS: serverTLS, AllowNonTLS: o.mode.AllowsPlaintext(),
	})
	if err != nil {
		t.Fatalf("bus.Start: %v", err)
	}
	c.srv = srv
	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(srv.ClientURL(), "tls://"), "nats://"))
	if err != nil {
		t.Fatalf("server URL %q: %v", srv.ClientURL(), err)
	}
	if _, err := fmt.Sscan(portStr, &c.port); err != nil {
		t.Fatal(err)
	}
	tokens, err := busauth.OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	c.tokens = tokens
	responder := busauth.NewResponder(srv.Conn(), issuer, tokens)
	if err := responder.Start(); err != nil {
		t.Fatal(err)
	}
	settings, err := setup.OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	invStore, err := inventory.OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	c.inv = invStore
	invSvc := inventory.NewService(invStore, srv.Conn())
	c.svc = bustls.NewService(bustls.Config{
		Key:       key,
		Settings:  settings,
		StartMode: o.mode,
		Nodes: func(ctx context.Context) ([]*proto.Node, error) {
			nodes, err := invStore.List(ctx)
			if err == nil {
				invStore.Presence(ctx, nodes)
			}
			return nodes, err
		},
		Plaintext: srv.PlaintextClients,
		NC:        srv.Conn(),
		Restart:   func() { c.restarts.Add(1) },
	})
	invSvc.SetOnRegistered(c.svc.OnRegistered)
	if err := invSvc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	// Every registration THIS controlplane instance receives, so a fact can
	// be asked of this process and not of rows an earlier one left behind.
	if _, err := srv.Conn().Subscribe(proto.NodeRegisteredSubject("*"), func(m *nats.Msg) {
		var ev proto.NodeRegisteredEvt
		if json.Unmarshal(m.Data, &ev) == nil {
			c.regMu.Lock()
			c.regs = append(c.regs, ev)
			c.regMu.Unlock()
		}
	}); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			c.svc.Wait()
			invSvc.Stop()
			responder.Stop()
			srv.Stop()
			cancel()
			_ = invStore.Close()
			_ = settings.Close()
			_ = tokens.Close()
		})
	}
	c.stopFn = stop
	t.Cleanup(stop)
	return c
}

func (c *cp) url() string { return fmt.Sprintf("nats://127.0.0.1:%d", c.port) }

// waitRegistered waits for THIS instance to receive a registration from id
// whose busTls is want.
func (c *cp) waitRegistered(t *testing.T, id string, want bool) {
	t.Helper()
	end := time.Now().Add(factDeadline)
	for time.Now().Before(end) {
		c.regMu.Lock()
		for _, ev := range c.regs {
			if ev.NodeID == id {
				if v, ok := ev.Metadata[proto.MetadataBusTLS].(bool); ok && v == want {
					c.regMu.Unlock()
					return
				}
			}
		}
		c.regMu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
	c.regMu.Lock()
	defer c.regMu.Unlock()
	t.Fatalf("no registration from %s with busTls=%t within %s; got %+v", id, want, factDeadline, c.regs)
}

func (c *cp) registeredAtAll(id string) bool {
	c.regMu.Lock()
	defer c.regMu.Unlock()
	for _, ev := range c.regs {
		if ev.NodeID == id {
			return true
		}
	}
	return false
}

func otherPin(t *testing.T) string {
	t.Helper()
	k, _, err := bustls.EnsureKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return k.Pin()
}

func skipShort(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("functional: builds and runs the agent binary")
	}
}

// --- the scenarios -----------------------------------------------------------

// During migration (offer): the right pin connects over TLS and says so; a
// wrong pin is refused by the agent and never registers; no pin still connects,
// in plaintext, and the server lists it as the thing holding require back.
func TestFunctional_OfferMode(t *testing.T) {
	skipShort(t)
	c := startCP(t, cpOpts{mode: bustls.ModeOffer})

	startAgent(t, agentOpts{id: "n-good", url: c.url(), pin: c.key.Pin()})
	c.waitRegistered(t, "n-good", true)

	bad := startAgent(t, agentOpts{id: "n-bad", url: c.url(), pin: otherPin(t)})
	bad.waitLog(t, "the pin mismatch refusal", "does not match RASPUTIN_BUS_PIN")

	startAgent(t, agentOpts{id: "n-plain", url: c.url()})
	c.waitRegistered(t, "n-plain", false)

	if c.registeredAtAll("n-bad") {
		t.Fatal("a node with the wrong pin registered")
	}
	st, err := c.svc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Ready {
		t.Fatalf("ready with a plaintext node: %+v", st)
	}
	var plainListed bool
	for _, pc := range st.PlaintextConnections {
		plainListed = plainListed || strings.Contains(pc.Name, "n-plain")
		if strings.Contains(pc.Name, "n-good") {
			t.Errorf("the TLS agent is listed as plaintext: %+v", pc)
		}
	}
	if !plainListed {
		t.Errorf("the plaintext agent is not in PlaintextConnections: %+v", st.PlaintextConnections)
	}
}

// The whole migration, end to end: two nodes enrolled before the pin existed —
// the controlplane's own tokenless loopback agent and a compute node — get it
// delivered over the plaintext bus, save it, come back over TLS and say so;
// the readiness fact turns true; require is accepted and asks for the restart;
// the restarted controlplane refuses plaintext; both agents, restarted with no
// pin in their environment, come back over TLS from the pin they saved; and a
// node that never got one is refused.
func TestFunctional_MigrateThenRequire(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	c := startCP(t, cpOpts{mode: bustls.ModeOffer})
	pin := c.key.Pin()

	cpAgent := startAgent(t, agentOpts{id: "cp1", role: proto.RoleControlPlane, url: c.url()})
	// A real token bound to n1, as Add-node mints it. On loopback the callout
	// trusts the connection before it reads the token, so this is realism,
	// not the thing under test.
	n1Token, _, err := c.tokens.MintBound(ctx, "n1", "n1")
	if err != nil {
		t.Fatal(err)
	}
	n1 := startAgent(t, agentOpts{id: "n1", url: c.url(), token: n1Token})
	c.waitRegistered(t, "cp1", false)
	c.waitRegistered(t, "n1", false)

	if _, err := c.svc.SetMode(ctx, bustls.ModeRequire); err == nil {
		t.Fatal("require accepted while both nodes are on plaintext")
	}
	if _, err := c.svc.SetMode(ctx, bustls.ModeMigrate); err != nil {
		t.Fatal(err)
	}
	c.waitRegistered(t, "cp1", true)
	c.waitRegistered(t, "n1", true)
	for _, a := range []*agentProc{cpAgent, n1} {
		saved, err := os.ReadFile(filepath.Join(a.stateDir, "bus", "pin"))
		if err != nil || strings.TrimSpace(string(saved)) != pin {
			t.Fatalf("%s saved pin = (%q, %v), want %s", a.id, saved, err, pin)
		}
	}

	// The plaintext connections the delivery replaced are gone: the fact.
	var st bustls.Status
	end := time.Now().Add(factDeadline)
	for {
		var err error
		st, err = c.svc.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if st.Ready || time.Now().After(end) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !st.Ready {
		t.Fatalf("not ready after every node moved to TLS: %v", st.Blockers)
	}
	if _, err := c.svc.SetMode(ctx, bustls.ModeRequire); err != nil {
		t.Fatalf("require refused once ready: %v", err)
	}
	if got := c.restarts.Load(); got != 1 {
		t.Fatalf("restart requested %d times, want 1", got)
	}

	// The restart: agents down, controlplane down, controlplane up in require
	// on the same data dir and port, agents up with NO pin in their env.
	cpAgent.stop(t)
	n1.stop(t)
	c.stop()
	c2 := startCP(t, cpOpts{dataDir: c.dataDir, port: c.port, mode: bustls.ModeRequire})
	if c2.key.Pin() != pin {
		t.Fatalf("the restarted controlplane has pin %s, want %s", c2.key.Pin(), pin)
	}
	startAgent(t, agentOpts{id: "cp1", role: proto.RoleControlPlane, url: c2.url(), stateDir: cpAgent.stateDir})
	startAgent(t, agentOpts{id: "n1", url: c2.url(), token: n1Token, stateDir: n1.stateDir})
	c2.waitRegistered(t, "cp1", true)
	c2.waitRegistered(t, "n1", true)

	stray := startAgent(t, agentOpts{id: "n-unmigrated", url: c2.url()})
	stray.waitLog(t, "the TLS-required refusal of an unpinned node", "NATS connect", "tls")
	if c2.registeredAtAll("n-unmigrated") {
		t.Fatal("an unpinned node registered on a TLS-required bus")
	}
	plain, err := c2.srv.PlaintextClients()
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != 0 {
		t.Fatalf("plaintext connections on a TLS-required bus: %+v", plain)
	}
}

// A node's clock does not decide whether it joins: the bus certificate is not
// yet valid, or long expired, and the pinned agent connects anyway.
func TestFunctional_ClockIndependence(t *testing.T) {
	skipShort(t)
	dataDir := t.TempDir()
	key, _, err := bustls.EnsureKey(filepath.Join(dataDir, "bus"))
	if err != nil {
		t.Fatal(err)
	}
	for name, span := range map[string][2]time.Time{
		"not-yet-valid": {time.Now().AddDate(30, 0, 0), time.Now().AddDate(31, 0, 0)},
		"expired":       {time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(1991, 1, 1, 0, 0, 0, 0, time.UTC)},
	} {
		t.Run(name, func(t *testing.T) {
			cert, err := bustls.SelfSignedCert(key.Signer(), span[0], span[1])
			if err != nil {
				t.Fatal(err)
			}
			c := startCP(t, cpOpts{dataDir: dataDir, mode: bustls.ModeRequire, cert: &cert})
			id := "n-" + name
			startAgent(t, agentOpts{id: id, url: c.url(), pin: key.Pin()})
			c.waitRegistered(t, id, true)
			c.stop()
		})
	}
}
