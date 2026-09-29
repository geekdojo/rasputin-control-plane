package bustls_test

// THE FUNCTIONAL TEST for the TLS-only bus (geekdojo/geekdojo-brain#448,
// #517): the real embedded bus (bus.Start, TLS required, with the auth callout
// enforced), the real inventory service and join-token store, wired the way
// cmd/rasputin-api wires them — and the REAL rasputin-agent binary, built from
// this workspace and run as subprocesses, doing the TLS handshake and the pin
// check itself.
//
// Why a subprocess: the agent's client lives in agent/internal and cannot be
// imported from the api module, and the parts most likely to be wrong are in
// agent main — where the pin is resolved, where a missing one ends the
// process, and what the registration reports. A copy of the client wired by
// this test would prove the copy.
//
// Every wait is for a fact, signalled when it changes, under a hard deadline:
// a registration, a log line, a process exit. Nothing here sleeps to let
// something happen.
//
// functional_api_test.go runs the REAL rasputin-api binary too, for what only
// a process shows: a stale mode setting and RASPUTIN_BUS_TLS changing nothing,
// and a bus key or certificate that will not load.
//
// What it does NOT prove: the OS or firewall images (firstboot, apply-seed,
// the seed scrub), mDNS resolution of <cluster>.local, or real clocks on real
// hardware. That is the bench plan in the PR.
//
// Run alone: scripts/test-bus-tls.sh.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls/bustlstest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/cutover"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

const factDeadline = 45 * time.Second

// signal is a broadcast "something changed": waiters grab the current channel,
// re-check their condition, and block on it; a change closes it and installs a
// fresh one.
type signal struct {
	mu sync.Mutex
	ch chan struct{}
}

func (s *signal) wait() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ch == nil {
		s.ch = make(chan struct{})
	}
	return s.ch
}

func (s *signal) fire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ch != nil {
		close(s.ch)
	}
	s.ch = make(chan struct{})
}

// waitFact blocks until cond() holds, re-checking only when changed fires, and
// fails the test at the deadline.
func waitFact(t *testing.T, what string, changed *signal, cond func() bool, describe func() string) {
	t.Helper()
	deadline := time.NewTimer(factDeadline)
	defer deadline.Stop()
	for {
		ch := changed.wait()
		if cond() {
			return
		}
		select {
		case <-ch:
		case <-deadline.C:
			t.Fatalf("no %s within %s\n%s", what, factDeadline, describe())
		}
	}
}

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

	mu      sync.Mutex
	lines   []string
	changed signal
	done    chan struct{} // closed once the process has exited and been reaped
	exitErr error
}

type agentOpts struct {
	id    string
	role  proto.NodeRole
	url   string
	token string
	// tokenFile is RASPUTIN_CP_JOIN_TOKEN_FILE: how the controlplane's own
	// agent reads the token its api mints (cp.agentTokenFile).
	tokenFile string
	pin       string // RASPUTIN_BUS_PIN; "" leaves it unset
	// pinFile is RASPUTIN_BUS_PIN_FILE: where the controlplane's own agent
	// reads the pin its api writes (cp.agentPinFile). Read by the
	// controlplane role only, and last.
	pinFile string
	// stateDir reuses a previous agent's state (a restart); "" is fresh.
	stateDir string
	// bin runs another agent binary (the compatibility tests' floor agent);
	// "" builds this workspace's.
	bin string
}

func startAgent(t *testing.T, o agentOpts) *agentProc {
	t.Helper()
	bin := o.bin
	if bin == "" {
		bin = buildAgent(t)
	}
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
	if o.tokenFile != "" {
		env = append(env, "RASPUTIN_CP_JOIN_TOKEN_FILE="+o.tokenFile)
	}
	if o.pin != "" {
		env = append(env, "RASPUTIN_BUS_PIN="+o.pin)
	}
	if o.pinFile != "" {
		env = append(env, "RASPUTIN_BUS_PIN_FILE="+o.pinFile)
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
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			a.mu.Lock()
			a.lines = append(a.lines, sc.Text())
			a.mu.Unlock()
			a.changed.fire()
		}
		a.exitErr = cmd.Wait()
		close(a.done)
		a.changed.fire()
	}()
	t.Cleanup(func() { a.stop(t) })
	return a
}

func (a *agentProc) exited() bool {
	select {
	case <-a.done:
		return true
	default:
		return false
	}
}

func (a *agentProc) stop(t *testing.T) {
	if !a.exited() {
		_ = a.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-a.done:
		case <-time.After(10 * time.Second): // bounds the one wait for exit
			_ = a.cmd.Process.Kill()
			<-a.done
		}
	}
	if t.Failed() {
		t.Logf("--- agent %s log ---\n%s", a.id, a.log())
	}
}

// waitExit waits for the process to end on its own and returns its exit code.
func (a *agentProc) waitExit(t *testing.T) int {
	t.Helper()
	waitFact(t, "agent "+a.id+" to exit", &a.changed, a.exited, a.log)
	var ee *exec.ExitError
	if errors.As(a.exitErr, &ee) {
		return ee.ExitCode()
	}
	if a.exitErr != nil {
		t.Fatalf("agent %s: %v", a.id, a.exitErr)
	}
	return 0
}

func (a *agentProc) log() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return strings.Join(a.lines, "\n")
}

func (a *agentProc) lineCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.lines)
}

// waitLog waits for a log line containing every one of subs.
func (a *agentProc) waitLog(t *testing.T, what string, subs ...string) {
	t.Helper()
	a.waitLogSince(t, 0, what, subs...)
}

// waitLogSince is waitLog over the lines after the first `since`.
func (a *agentProc) waitLogSince(t *testing.T, since int, what string, subs ...string) {
	t.Helper()
	waitFact(t, what+" in agent "+a.id+"'s log", &a.changed, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		for _, l := range a.lines[since:] {
			all := true
			for _, s := range subs {
				all = all && strings.Contains(l, s)
			}
			if all {
				return true
			}
		}
		return false
	}, a.log)
}

// --- a listener nobody should reach -----------------------------------------

// stub is a TCP listener standing where the bus would be, for an agent that
// must never dial.
func stub(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// assertNeverDialed proves nothing connected to l: the test dials l itself,
// and the first connection l accepts must be that sentinel — any connection
// the agent had made would be queued ahead of it.
func assertNeverDialed(t *testing.T, l net.Listener) {
	t.Helper()
	sentinel, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sentinel.Close() }()
	got, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = got.Close() }()
	if got.RemoteAddr().String() != sentinel.LocalAddr().String() {
		t.Fatalf("the listener's first connection came from %s, not the sentinel: the agent dialed", got.RemoteAddr())
	}
}

// --- the controlplane --------------------------------------------------------

type cp struct {
	dataDir  string
	port     int
	selfNode string
	srv      *bus.Server
	key      *bustls.Key
	tokens   *busauth.Store
	// inv is the node store the api records registrations into, so a test
	// can read back what was PERSISTED on the node row and not only what
	// crossed the bus.
	inv *inventory.Store

	regMu   sync.Mutex
	regs    []proto.NodeRegisteredEvt
	changed signal

	// recorded names every node whose registration has been written to the
	// node row, as reported by inventory's own post-write hook.
	recordedMu sync.Mutex
	recorded   map[string]struct{}

	stopFn func()
}

func (c *cp) stop() { c.stopFn() }

type cpOpts struct {
	dataDir string // reuse (a restart); "" is fresh
	port    int    // reuse (a restart); 0 lets the server pick
	// selfNode is RASPUTIN_SELF_NODE_ID: the controlplane's own node id, for
	// which the controlplane mints its agent's bus token at start
	// (agentTokenFile), as the api does.
	selfNode string
	// cert overrides the certificate wrapped around the bus key.
	cert *tls.Certificate
	// noPinFile skips writing the controlplane agent's pin file, which the
	// api writes on every start; a test that wants the moment before it sets
	// this.
	noPinFile bool
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
	c := &cp{dataDir: o.dataDir, selfNode: o.selfNode, recorded: map[string]struct{}{}}
	dbPath := filepath.Join(o.dataDir, "rasputin.db")
	busDir := filepath.Join(o.dataDir, "bus")

	key, _, err := bustls.EnsureKey(busDir)
	if err != nil {
		t.Fatal(err)
	}
	c.key = key
	// The PERSISTED certificate, as the api serves it (geekdojo-brain#508):
	// same bytes across restarts, carrying the fixed DNS SAN.
	busCert, _, err := bustls.EnsureCert(busDir, key)
	if len(busCert.Certificate) == 0 {
		t.Fatal(err)
	}
	serverTLS := bustls.ServerTLSConfigFor(busCert)
	if o.cert != nil {
		serverTLS = bustls.ServerTLSConfigFor(*o.cert)
	}
	if !o.noPinFile {
		if _, err := bustls.WriteAgentPinFile(busDir, key); err != nil {
			t.Fatal(err)
		}
	}
	issuer, err := busauth.EnsureIssuer(busDir)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := bus.Start(ctx, bus.Config{
		Host: "127.0.0.1", Port: o.port, StoreDir: filepath.Join(o.dataDir, "nats"),
		AuthEnforce: true, IssuerPublicKey: issuer.PublicKey(), APIUser: "rasputin-api", APIPass: "functional-test",
		TLS: serverTLS,
	})
	if err != nil {
		t.Fatalf("bus.Start: %v", err)
	}
	c.srv = srv
	url, listening := srv.ClientURL()
	if !listening {
		t.Fatal("a TLS bus reports no listener")
	}
	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(url, "tls://"))
	if err != nil {
		t.Fatalf("server URL %q: %v", url, err)
	}
	if _, err := fmt.Sscan(portStr, &c.port); err != nil {
		t.Fatal(err)
	}
	tokens, err := busauth.OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	c.tokens = tokens
	// The api's one node list, opened and loaded before the responder admits
	// anyone — as cmd/rasputin-api does. Without it nothing is admitted.
	invStore, err := inventory.OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	c.inv = invStore
	if o.selfNode != "" {
		if _, err := tokens.EnsureAgentToken(ctx, c.agentTokenFile(), o.selfNode); err != nil {
			t.Fatalf("EnsureAgentToken: %v", err)
		}
	}
	if err := tokens.SetNodeRegistry(ctx, invStore.Registry()); err != nil {
		t.Fatalf("SetNodeRegistry: %v", err)
	}
	invStore.Registry().OnNodeExcluded(func(nodeID string) { _ = tokens.DisconnectNode(nodeID) })
	tokens.TrackSessions(srv)
	responder := busauth.NewResponder(srv.Conn(), issuer, tokens)
	if err := responder.Start(); err != nil {
		t.Fatal(err)
	}
	invSvc := inventory.NewService(invStore, srv.Conn())
	// OnRegistered fires AFTER the node row is written, so a test that needs
	// the RECORDED row (not only the event that crossed the bus) has a fact to
	// wait on instead of a poll.
	invSvc.SetOnRegistered(func(ctx context.Context, n *proto.Node) {
		c.recordedMu.Lock()
		c.recorded[n.ID] = struct{}{}
		c.recordedMu.Unlock()
		c.changed.fire()
	})
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
			c.changed.fire()
		}
	}); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	c.stopFn = func() {
		once.Do(func() {
			invSvc.Stop()
			responder.Stop()
			srv.Stop()
			cancel()
			_ = invStore.Close()
			_ = tokens.Close()
		})
	}
	t.Cleanup(c.stop)
	return c
}

func (c *cp) url() string  { return fmt.Sprintf("nats://127.0.0.1:%d", c.port) }
func (c *cp) addr() string { return fmt.Sprintf("127.0.0.1:%d", c.port) }

// agentTokenFile is where this controlplane mints its own agent's bus token.
func (c *cp) agentTokenFile() string {
	return filepath.Join(c.dataDir, "bus", proto.BusAgentTokenFileName)
}

// agentPinFile is where this controlplane writes its own agent's bus pin.
func (c *cp) agentPinFile() string {
	return filepath.Join(c.dataDir, "bus", proto.BusAgentPinFileName)
}

// mint returns a fresh join token bound to id, as Add-node or a matched set
// provisions one. Every agent needs one: loopback earns none
// (geekdojo-brain#140).
func (c *cp) mint(t *testing.T, id string) string {
	t.Helper()
	tok, _, err := c.tokens.MintBound(context.Background(), id, id, "compute")
	if err != nil {
		t.Fatalf("MintBound(%s): %v", id, err)
	}
	return tok
}

func (c *cp) describeRegs() string {
	c.regMu.Lock()
	defer c.regMu.Unlock()
	return fmt.Sprintf("registrations: %+v", c.regs)
}

// waitRegistered waits for THIS instance to receive a registration from id.
func (c *cp) waitRegistered(t *testing.T, id string) proto.NodeRegisteredEvt {
	t.Helper()
	var got proto.NodeRegisteredEvt
	waitFact(t, "registration from "+id, &c.changed, func() bool {
		c.regMu.Lock()
		defer c.regMu.Unlock()
		for _, ev := range c.regs {
			if ev.NodeID == id {
				got = ev
				return true
			}
		}
		return false
	}, c.describeRegs)
	return got
}

// waitRecorded blocks until id's registration has been written to the node
// row, which is the fact inventory's post-write hook reports.
func (c *cp) waitRecorded(t *testing.T, id string) {
	t.Helper()
	waitFact(t, "the node row for "+id, &c.changed, func() bool {
		c.recordedMu.Lock()
		defer c.recordedMu.Unlock()
		_, ok := c.recorded[id]
		return ok
	}, c.describeRegs)
}

// lastRegistration is the most recent registration this controlplane received
// from id.
func (c *cp) lastRegistration(id string) (proto.NodeRegisteredEvt, bool) {
	c.regMu.Lock()
	defer c.regMu.Unlock()
	for i := len(c.regs) - 1; i >= 0; i-- {
		if c.regs[i].NodeID == id {
			return c.regs[i], true
		}
	}
	return proto.NodeRegisteredEvt{}, false
}

func (c *cp) registeredAtAll(id string) bool {
	_, ok := c.lastRegistration(id)
	return ok
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

// assertNoLadderMetadata fails when a registration still carries a key the
// plaintext ladder used.
func assertNoLadderMetadata(t *testing.T, ev proto.NodeRegisteredEvt) {
	t.Helper()
	for _, gone := range []string{"busTls", "httpsPinned"} {
		if v, ok := ev.Metadata[gone]; ok {
			t.Errorf("%s registered with %s=%v; the key is gone", ev.NodeID, gone, v)
		}
	}
}

// --- the scenarios -----------------------------------------------------------

// TC-517-25: a controlplane that never had a seed — nothing put
// RASPUTIN_BUS_PIN in its agent's environment — joins its own TLS-only bus
// from the pin file the api writes beside the token (geekdojo/geekdojo-brain
// #510). The bus refuses plaintext from its first listen.
func TestFunctional_ControlplaneAgentPinFile(t *testing.T) {
	skipShort(t)
	c := startCP(t, cpOpts{selfNode: "cp1"})
	bustlstest.AssertPlaintextRefused(t, c.addr())

	got, err := os.ReadFile(c.agentPinFile())
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != c.key.Pin() {
		t.Fatalf("pin file = %q, want %q", got, c.key.Pin())
	}

	// No `pin:` — this agent was never seeded one. It must find the file.
	a := startAgent(t, agentOpts{
		id: "cp1", role: proto.RoleControlPlane, url: c.url(),
		tokenFile: c.agentTokenFile(), pinFile: c.agentPinFile(),
	})
	a.waitLog(t, "the pin taken from the controlplane's own file", "bus pin", "source=controlplane", "pin_file="+c.agentPinFile())
	ev := c.waitRegistered(t, "cp1")
	assertNoLadderMetadata(t, ev)
}

// TC-517-26: a compute node seeded with the pin joins over TLS.
func TestFunctional_ComputeJoinsOnItsSeededPin(t *testing.T) {
	skipShort(t)
	c := startCP(t, cpOpts{})
	a := startAgent(t, agentOpts{id: "n1", url: c.url(), token: c.mint(t, "n1"), pin: c.key.Pin()})
	a.waitLog(t, "the seeded pin", "bus pin", "source=env")
	assertNoLadderMetadata(t, c.waitRegistered(t, "n1"))
}

// TC-517-27: a node migrated in place holds its pin only in the file an older
// agent saved when the pin was delivered. It still joins, and nothing touches
// the file.
func TestFunctional_SavedPinFileOnlyNodeJoins(t *testing.T) {
	skipShort(t)
	c := startCP(t, cpOpts{})
	stateDir := t.TempDir()
	pinFile := filepath.Join(stateDir, "bus", "pin")
	if err := os.MkdirAll(filepath.Dir(pinFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinFile, []byte(c.key.Pin()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(pinFile)
	if err != nil {
		t.Fatal(err)
	}
	beforeBytes, _ := os.ReadFile(pinFile)

	a := startAgent(t, agentOpts{id: "n-migrated", url: c.url(), token: c.mint(t, "n-migrated"), stateDir: stateDir})
	a.waitLog(t, "the saved pin", "bus pin", "source=file", "pin_file="+pinFile)
	c.waitRegistered(t, "n-migrated")

	after, err := os.Stat(pinFile)
	if err != nil {
		t.Fatal(err)
	}
	afterBytes, _ := os.ReadFile(pinFile)
	if !bytes.Equal(beforeBytes, afterBytes) || !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("the saved pin file changed: %q (%s) → %q (%s)", beforeBytes, before.ModTime(), afterBytes, after.ModTime())
	}
}

// TC-517-28: nothing on a node accepts a pin over the bus any more. A request
// on the node's bus.pin lane gets no responder, while the same node answers
// diag.ping on the same lane.
func TestFunctional_BusPinVerbHasNoResponder(t *testing.T) {
	skipShort(t)
	c := startCP(t, cpOpts{})
	startAgent(t, agentOpts{id: "n1", url: c.url(), token: c.mint(t, "n1"), pin: c.key.Pin()})
	// The agent subscribes on a new connection before it registers, and both
	// go out on that one connection, so its lane is live by now.
	c.waitRegistered(t, "n1")
	nc := c.srv.Conn()
	if _, err := nc.Request(proto.NodeCmdSubject("n1", "diag.ping"), []byte("{}"), 10*time.Second); err != nil {
		t.Fatalf("diag.ping on n1's lane: %v (the control: the lane must be live)", err)
	}
	_, err := nc.Request(proto.NodeCmdSubject("n1", "bus.pin"), []byte(`{"pin":"`+otherPin(t)+`"}`), 10*time.Second)
	if !errors.Is(err, nats.ErrNoResponders) {
		t.Fatalf("bus.pin request = %v, want nats.ErrNoResponders", err)
	}
}

// TC-517-10: a node with no pin anywhere does not dial. It exits non-zero with
// one FATAL entry naming the node, every source it read, and the fix — and
// nothing ever connects to where the bus would be.
func TestFunctional_AgentExitsWithNoPin(t *testing.T) {
	skipShort(t)
	l := stub(t)
	stateDir := t.TempDir()
	a := startAgent(t, agentOpts{id: "n-nopin", url: "nats://" + l.Addr().String(), token: "tok-never-sent", stateDir: stateDir})
	if code := a.waitExit(t); code == 0 {
		t.Fatal("an agent with no pin exited 0")
	}
	a.waitLog(t, "the FATAL entry", "level=FATAL", "refusing to dial the bus", "node_id=n-nopin",
		"pin_file="+filepath.Join(stateDir, "bus", "pin"), "cp_pin_file=", "fix=")
	assertNeverDialed(t, l)
}

// TC-517-11: a saved pin file that is empty or malformed, or a malformed
// seeded pin, gives the same FATAL exit, and the token is never sent.
func TestFunctional_AgentExitsOnAnUnusablePin(t *testing.T) {
	skipShort(t)
	for name, tc := range map[string]struct {
		file     *string // saved pin file content; nil for none
		envPin   string
		wantText string
	}{
		"empty saved pin file":     {file: ptr(""), wantText: "pin_file_fault="},
		"malformed saved pin file": {file: ptr("sha256/short\n"), wantText: "pin_file_fault="},
		"malformed seeded pin":     {envPin: "sha256/nope", wantText: "env_pin_fault="},
	} {
		t.Run(name, func(t *testing.T) {
			l := stub(t)
			stateDir := t.TempDir()
			if tc.file != nil {
				p := filepath.Join(stateDir, "bus", "pin")
				if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(*tc.file), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			a := startAgent(t, agentOpts{id: "n-bad", url: "nats://" + l.Addr().String(), token: "tok-never-sent", pin: tc.envPin, stateDir: stateDir})
			if code := a.waitExit(t); code == 0 {
				t.Fatal("an agent with an unusable pin exited 0")
			}
			a.waitLog(t, "the FATAL entry", "level=FATAL", "refusing to dial the bus", "node_id=n-bad", tc.wantText)
			assertNeverDialed(t, l)
		})
	}
}

func ptr(s string) *string { return &s }

// TC-517-34: a controlplane agent that starts before its api has written the
// pin file exits, and once the file is there the unit's restart joins it with
// no manual step. The harness plays the unit: it starts the agent again.
func TestFunctional_ControlplaneAgentStartsBeforeItsPinFile(t *testing.T) {
	skipShort(t)
	c := startCP(t, cpOpts{selfNode: "cp1", noPinFile: true})
	stateDir := t.TempDir()
	opts := agentOpts{id: "cp1", role: proto.RoleControlPlane, url: c.url(), tokenFile: c.agentTokenFile(), pinFile: c.agentPinFile(), stateDir: stateDir}
	first := startAgent(t, opts)
	if code := first.waitExit(t); code == 0 {
		t.Fatal("the controlplane agent exited 0 with no pin file")
	}
	first.waitLog(t, "the FATAL entry", "level=FATAL", "refusing to dial the bus")
	if c.registeredAtAll("cp1") {
		t.Fatal("the controlplane agent registered with no pin")
	}

	if _, err := bustls.WriteAgentPinFile(filepath.Join(c.dataDir, "bus"), c.key); err != nil { // the api's start
		t.Fatal(err)
	}
	startAgent(t, opts) // the unit's restart
	c.waitRegistered(t, "cp1")
}

// TC-517-33: an identity restore that changes the bus key under a running
// controlplane agent (a controlplane that generated its own key K2, then had
// K1 restored). The api restarts with K1 and rewrites agent.pin; the running
// agent, pinned to K2, refuses K1 — it logs the refusal, never registers, and
// keeps running. Restarted, it reads the rewritten file and joins on K1. The
// fix (re-reading the file on every dial) is geekdojo/geekdojo-brain#669.
func TestFunctional_RestoreOntoAnotherKey(t *testing.T) {
	skipShort(t)
	c := startCP(t, cpOpts{selfNode: "cp1"})
	stateDir := t.TempDir()
	opts := agentOpts{id: "cp1", role: proto.RoleControlPlane, url: c.url(), tokenFile: c.agentTokenFile(), pinFile: c.agentPinFile(), stateDir: stateDir}
	a := startAgent(t, opts)
	a.waitLog(t, "the pin source", "bus pin", "source=controlplane", "pin_file="+c.agentPinFile())
	c.waitRegistered(t, "cp1")
	k2 := c.key.Pin()

	// The restore: another key, K1, into bus.key; the certificate re-minted
	// around it on the next start.
	c.stop()
	k1Dir := t.TempDir()
	k1, _, err := bustls.EnsureKey(k1Dir)
	if err != nil {
		t.Fatal(err)
	}
	k1Bytes, err := os.ReadFile(filepath.Join(k1Dir, bustls.KeyFileName))
	if err != nil {
		t.Fatal(err)
	}
	busDir := filepath.Join(c.dataDir, "bus")
	if err := os.WriteFile(filepath.Join(busDir, bustls.KeyFileName), k1Bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	since := a.lineCount()
	c2 := startCP(t, cpOpts{dataDir: c.dataDir, port: c.port, selfNode: "cp1"})
	if c2.key.Pin() != k1.Pin() || k1.Pin() == k2 {
		t.Fatalf("the restarted controlplane serves %s, want the restored %s", c2.key.Pin(), k1.Pin())
	}
	if got, _ := os.ReadFile(c2.agentPinFile()); strings.TrimSpace(string(got)) != k1.Pin() {
		t.Fatalf("agent.pin = %q after the restart, want %q", got, k1.Pin())
	}

	a.waitLogSince(t, since, "the refusal of the restored key", "refused the bus server's key", "pin="+strconv.Quote(k2), "does not match RASPUTIN_BUS_PIN")
	if a.exited() {
		t.Fatal("the agent exited on a key mismatch; it must keep re-dialing")
	}
	if c2.registeredAtAll("cp1") {
		t.Fatal("the agent pinned to the old key registered on the restored one")
	}

	a.stop(t)
	b := startAgent(t, opts) // what a reboot or `systemctl restart rasputin-agent` does
	b.waitLog(t, "the rewritten pin", "bus pin", "pin="+strconv.Quote(k1.Pin()), "source=controlplane")
	c2.waitRegistered(t, "cp1")
}

// TC-517-05 (functional): a node's clock does not decide whether it joins: the
// bus certificate is not yet valid, or long expired, and the pinned agent
// connects anyway.
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
			c := startCP(t, cpOpts{dataDir: dataDir, cert: &cert})
			id := "n-" + name
			startAgent(t, agentOpts{id: id, url: c.url(), token: c.mint(t, id), pin: key.Pin()})
			c.waitRegistered(t, id)
			c.stop()
		})
	}
}

// The controlplane's own agent on the bus once loopback earns no trust
// (geekdojo-brain#140), with the REAL agent binary:
//
//  1. the agent starts BEFORE its api has minted the token file: its connect
//     attempts fail for want of a token, and it joins on its own once the
//     file appears — no restart, no timer, just its ordinary retry reading
//     the file again;
//  2. an impostor agent on the same box, holding the pin but no token,
//     claiming an enrolled node's id over 127.0.0.1, is refused and never
//     registers — nor does one claiming the controlplane's own id;
//  3. the token file is deleted and the controlplane restarts: it re-mints,
//     the old token stops authenticating, and the SAME agent process rejoins
//     with the new token.
func TestFunctional_ControlplaneAgentToken(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	c := startCP(t, cpOpts{})
	tokenFile := c.agentTokenFile()

	// 1. No file yet (startCP minted nothing: no self node id).
	cpAgent := startAgent(t, agentOpts{id: "cp1", role: proto.RoleControlPlane, url: c.url(), tokenFile: tokenFile, pinFile: c.agentPinFile()})
	cpAgent.waitLog(t, "a connect attempt with no token file", "no join token for this connection attempt", "does not exist yet")
	if c.registeredAtAll("cp1") {
		t.Fatal("the controlplane agent registered with no token")
	}
	if _, err := c.tokens.EnsureAgentToken(ctx, tokenFile, "cp1"); err != nil { // the api's start
		t.Fatal(err)
	}
	c.waitRegistered(t, "cp1")

	// 2. Impostors over loopback, pinned, no token.
	c.mint(t, "n-victim") // enrolled, not running
	for _, id := range []string{"n-victim", "cp1"} {
		imp := startAgent(t, agentOpts{id: id, url: c.url(), pin: c.key.Pin()})
		imp.waitLog(t, "the refusal of a tokenless agent claiming "+id, "NATS connect", "Authorization Violation")
		imp.stop(t)
	}
	if c.registeredAtAll("n-victim") {
		t.Fatal("a tokenless agent registered as n-victim")
	}

	// 3. The file is lost; the controlplane restarts and re-mints.
	old, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	c.stop()
	if err := os.Remove(tokenFile); err != nil {
		t.Fatal(err)
	}
	since := cpAgent.lineCount()
	c2 := startCP(t, cpOpts{dataDir: c.dataDir, port: c.port, selfNode: "cp1"})
	cur, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatalf("the restarted controlplane did not re-mint the token file: %v", err)
	}
	if string(cur) == string(old) {
		t.Fatal("the restarted controlplane wrote the old token back")
	}
	c2.waitRegistered(t, "cp1")
	cpAgent.waitLogSince(t, since, "the same agent process back on the bus", "reconnected", fmt.Sprint(c2.port))
	if cpAgent.exited() {
		t.Fatal("the controlplane agent process ended")
	}
	if ok, err := c2.tokens.Validate(ctx, strings.TrimSpace(string(old)), "cp1"); err != nil || ok {
		t.Fatalf("the replaced token still validates: (%v, %v)", ok, err)
	}
}

// The bus serves the PERSISTED certificate, and a client that verifies it the
// way Alloy will — the file's exact bytes as its only root, plus a server name
// — completes the handshake (geekdojo/geekdojo-brain#508, #467).
//
// This is what a Rasputin node does NOT do: a node checks the pin and ignores
// the chain, the name and the dates. The SAN exists for everything else.
func TestFunctional_BusServesThePersistedCertificate(t *testing.T) {
	skipShort(t)
	c := startCP(t, cpOpts{})

	certPath := filepath.Join(c.dataDir, "bus", bustls.CertFileName)
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("the api did not persist a bus certificate: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		t.Fatalf("%s is not loadable as a trust root", certPath)
	}

	// NATS always sends its INFO line in the clear and the client upgrades
	// after it, so the handshake is driven by hand here.
	raw, err := net.DialTimeout("tcp", c.addr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second)) // bounds this one exchange
	if line, rerr := bufio.NewReader(raw).ReadString('\n'); rerr != nil || !strings.HasPrefix(line, "INFO ") {
		t.Fatalf("first line from the bus = (%q, %v), want INFO", line, rerr)
	}

	// From here it is exactly a collector's tls_config: ca_pem = the file's
	// bytes, server_name = the SAN. No pin, and no InsecureSkipVerify.
	conn := tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: bustls.BusDNSName,
	})
	if err := conn.Handshake(); err != nil {
		t.Fatalf("a name-verifying client could not handshake with the bus: %v", err)
	}

	served := conn.ConnectionState().PeerCertificates
	if len(served) != 1 {
		t.Fatalf("the bus served %d certificates, want 1", len(served))
	}
	if !bytes.Equal(served[0].Raw, mustParsePEM(t, pemBytes).Raw) {
		t.Fatal("the certificate on the wire is not the one in bus/bus.crt")
	}
	if got := served[0].DNSNames; len(got) != 1 || got[0] != bustls.BusDNSName {
		t.Fatalf("the served certificate's DNSNames = %v, want [%q]", got, bustls.BusDNSName)
	}
	pin, err := proto.BusPinForPublicKey(served[0].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if pin != c.key.Pin() {
		t.Fatalf("the served certificate wraps %q, and nodes pin %q", pin, c.key.Pin())
	}

	// A node with the pin and no notion of names joins the same bus.
	startAgent(t, agentOpts{id: "n-pinned", url: c.url(), token: c.mint(t, "n-pinned"), pin: c.key.Pin()})
	c.waitRegistered(t, "n-pinned")

	// The api restarting does not change the bytes.
	c.stop()
	c2 := startCP(t, cpOpts{dataDir: c.dataDir, port: c.port})
	after, err := os.ReadFile(filepath.Join(c2.dataDir, "bus", bustls.CertFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, pemBytes) {
		t.Fatal("the persisted certificate changed across a restart")
	}
}

func mustParsePEM(t *testing.T, b []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatal("no PEM block")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// THE FUNCTIONAL CHECK for the §7 4.0 token-source emitter
// (geekdojo/geekdojo-brain#536): the REAL rasputin-agent binary, over the REAL
// bus to the REAL inventory service, reports where it read its join token, and
// the api records it on the node row, where the cutover reads it.
func TestFunctional_CutoverFactsReportedAndRecorded(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	c := startCP(t, cpOpts{})

	// A node whose token is in a file — the canonical source (§7 4.1).
	fileTok := c.mint(t, "n-file")
	tokenFile := filepath.Join(t.TempDir(), "join.token")
	if err := os.WriteFile(tokenFile, []byte(fileTok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	startAgent(t, agentOpts{id: "n-file", url: c.url(), tokenFile: tokenFile, pin: c.key.Pin()})
	// A node still carrying the seeded variable.
	startAgent(t, agentOpts{id: "n-env", url: c.url(), token: c.mint(t, "n-env"), pin: c.key.Pin()})

	c.waitRegistered(t, "n-file")
	c.waitRegistered(t, "n-env")
	c.waitRecorded(t, "n-file")
	c.waitRecorded(t, "n-env")

	for _, tc := range []struct {
		id   string
		want string
	}{
		{"n-file", proto.TokenSourceFile},
		{"n-env", proto.TokenSourceEnv},
	} {
		ev, ok := c.lastRegistration(tc.id)
		if !ok {
			t.Fatalf("no registration from %s\n%s", tc.id, c.describeRegs())
		}
		if src, reported := proto.TokenSourceOf(ev.Metadata); !reported || src != tc.want {
			t.Errorf("%s reported %s = (%q, %v), want %q", tc.id, proto.MetadataTokenSource, src, reported, tc.want)
		}
		assertNoLadderMetadata(t, ev)
		n, err := c.inv.Get(ctx, tc.id)
		if err != nil || n == nil {
			t.Fatalf("inventory Get(%s) = (%v, %v)", tc.id, n, err)
		}
		if src, reported := proto.TokenSourceOf(n.Metadata); !reported || src != tc.want {
			t.Errorf("node row %s: %s = (%q, %v), want (%q, true)", tc.id, proto.MetadataTokenSource, src, reported, tc.want)
		}
	}

	nodes, err := c.inv.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st := cutover.TokenOnFile(nodes)
	if st.Satisfied {
		t.Fatalf("the token-on-file cutover read as satisfied while n-env is on the variable: %+v", st)
	}
	var named bool
	for _, b := range st.Blockers {
		named = named || strings.Contains(b, "n-env")
		if strings.Contains(b, "n-file") {
			t.Errorf("blocker names the migrated node: %q", b)
		}
	}
	if !named {
		t.Errorf("blockers = %v, want one naming n-env", st.Blockers)
	}
}
