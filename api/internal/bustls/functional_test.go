package bustls_test

// THE FUNCTIONAL TEST for bus TLS (geekdojo/geekdojo-brain#448): the real
// embedded bus (bus.Start, with the auth callout enforced), the real inventory
// service, job store and runner, the real bustls service and its real commit
// check (updater.SelfBuildCommitted), wired the way cmd/rasputin-api wires
// them — and the REAL rasputin-agent binary, built from this workspace and run
// as subprocesses, doing the TLS handshake, the pin check, the pin delivery
// and the commit report itself.
//
// Why a subprocess: the agent's client lives in agent/internal and cannot be
// imported from the api module, and the parts most likely to be wrong are in
// agent main — where the pin is resolved, where a delivered one is saved, and
// what the registration reports. A copy of the client wired by this test would
// prove the copy.
//
// Every wait is for a fact, signalled when it changes, under a hard deadline:
// a registration that says busTls, a log line naming a refusal, the switch to
// TLS-only completing. Nothing here sleeps to let something happen.
//
// TestFunctional_RealAPIProcess (functional_api_test.go) runs the REAL
// rasputin-api binary too, for what only a process shows: the same PID and an
// HTTP server that never stops answering while the bus switches.
//
// What it does NOT prove: the OS or firewall images (firstboot, apply-seed,
// the seed scrub), mDNS resolution of <cluster>.local, a real RAUC slot commit
// (the controlplane agent runs the mock updater backend, whose commit model is
// unit-tested beside the RAUC one), or real clocks on real hardware. That is
// the bench plan in the PR.
//
// Run alone: scripts/test-bus-tls.sh.

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
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
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/api/internal/updater"
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
	done    chan struct{}
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
		// about the runner. The mock updater is also what answers the
		// controlplane's commit question.
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
		defer a.changed.fire()
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			a.mu.Lock()
			a.lines = append(a.lines, sc.Text())
			a.mu.Unlock()
			a.changed.fire()
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
	case <-time.After(10 * time.Second): // bounds the one wait for exit
		_ = a.cmd.Process.Kill()
		<-a.done
	}
	_ = a.cmd.Wait()
	if t.Failed() {
		t.Logf("--- agent %s log ---\n%s", a.id, a.log())
	}
}

func (a *agentProc) log() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return strings.Join(a.lines, "\n")
}

// waitLog waits for a log line containing every one of subs.
func (a *agentProc) waitLog(t *testing.T, what string, subs ...string) {
	t.Helper()
	waitFact(t, what+" in agent "+a.id+"'s log", &a.changed, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		for _, l := range a.lines {
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

// seedUncommittedMock writes the mock updater state an agent starts from: a
// build booted as a TRIAL on slot b (marked active, not good) — what a
// controlplane looks like after a self-update's reboot and before the saga's
// mark-good.
func seedUncommittedMock(t *testing.T, stateDir string) {
	t.Helper()
	dir := filepath.Join(stateDir, "updater")
	if err := os.MkdirAll(filepath.Join(dir, "bundles"), 0o755); err != nil {
		t.Fatal(err)
	}
	st := map[string]any{
		"activeSlot":     proto.SlotB,
		"inactiveSlot":   proto.SlotA,
		"currentVersion": "0.0.1-trial",
		"pendingSlot":    proto.SlotUnknown,
		"marks":          map[proto.UpdateSlot]proto.UpdateSlotState{proto.SlotA: proto.SlotStateInactive, proto.SlotB: proto.SlotStateActive},
	}
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// --- the controlplane --------------------------------------------------------

type cp struct {
	dataDir  string
	port     int
	selfNode string
	srv      *bus.Server
	svc      *bustls.Service
	key      *bustls.Key
	tokens   *busauth.Store
	jobStore *jobs.Store
	runner   *jobs.Runner
	settings *setup.Store
	mode     bustls.Mode
	// switched is closed when the switch to TLS-only has returned without
	// error; switches counts the calls. onSwitch, when set before the switch,
	// runs twice inside it with job intake closed and require recorded:
	// "before" the bus server is replaced and "after" it is, before intake
	// reopens.
	switched chan struct{}
	switches atomic.Int32
	onSwitch atomic.Pointer[func(phase string)]

	regMu   sync.Mutex
	regs    []proto.NodeRegisteredEvt
	changed signal

	evalMu    sync.Mutex
	evals     int
	evaluated signal

	stopFn func()
}

func (c *cp) stop() { c.stopFn() }

type cpOpts struct {
	dataDir string // reuse (a restart); "" is fresh
	port    int    // reuse (a restart); 0 lets the server pick
	// selfNode is RASPUTIN_SELF_NODE_ID: the controlplane's own node id, whose
	// agent answers the commit question, and for which the controlplane mints
	// its agent's bus token at start (agentTokenFile), as the api does.
	selfNode string
	// pinMode pins the mode the way RASPUTIN_BUS_TLS does; "" resolves it
	// from the recorded setting, as a real start does.
	pinMode bustls.Mode
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
	c := &cp{dataDir: o.dataDir, selfNode: o.selfNode, switched: make(chan struct{})}
	dbPath := filepath.Join(o.dataDir, "rasputin.db")

	settings, err := setup.OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	c.settings = settings
	mode, pinned := o.pinMode, o.pinMode != ""
	if !pinned {
		if mode, _, err = bustls.ResolveStartMode(ctx, settings); err != nil {
			t.Fatal(err)
		}
	}
	c.mode = mode

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
		TLS: serverTLS, AllowNonTLS: mode.AllowsPlaintext(),
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
	if o.selfNode != "" {
		// As cmd/rasputin-api does: before the responder admits anyone.
		if _, err := tokens.EnsureAgentToken(ctx, c.agentTokenFile(), o.selfNode); err != nil {
			t.Fatalf("EnsureAgentToken: %v", err)
		}
	}
	tokens.TrackSessions(srv)
	responder := busauth.NewResponder(srv.Conn(), issuer, tokens)
	var holdSvc atomic.Pointer[bustls.Service] // as cmd/rasputin-api wires it
	responder.SetHold(func() (bool, string) {
		if svc := holdSvc.Load(); svc != nil {
			return svc.Switching()
		}
		return false, ""
	})
	if err := responder.Start(); err != nil {
		t.Fatal(err)
	}
	invStore, err := inventory.OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	jobStore, err := jobs.OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	c.jobStore = jobStore
	c.runner = jobs.NewRunner(jobStore, srv.Conn())
	invSvc := inventory.NewService(invStore, srv.Conn())
	var switchedOnce sync.Once
	c.svc = bustls.NewService(bustls.Config{
		Key:             key,
		Settings:        settings,
		StartMode:       mode,
		StartModePinned: pinned,
		Nodes: func(ctx context.Context) ([]*proto.Node, error) {
			nodes, err := invStore.List(ctx)
			if err == nil {
				invStore.Presence(ctx, nodes)
			}
			return nodes, err
		},
		Plaintext: srv.PlaintextClients,
		NC:        srv.Conn(),
		Committed: func(ctx context.Context) (bool, string, error) {
			return updater.SelfBuildCommitted(ctx, jobStore, srv.Conn(), o.selfNode, 10*time.Second)
		},
		InFlight: func(ctx context.Context) ([]string, error) { return jobs.InFlight(ctx, jobStore) },
		Quiesce:  c.runner.QuiesceIfIdle,
		Reopen:   c.runner.Reopen,
		RequireTLS: func(ctx context.Context) error {
			c.switches.Add(1)
			hook := c.onSwitch.Load()
			if hook != nil {
				(*hook)("before")
			}
			err := srv.SetAllowNonTLS(ctx, false)
			if hook != nil {
				(*hook)("after")
			}
			if err == nil {
				switchedOnce.Do(func() { close(c.switched) })
			}
			return err
		},
		NoBus: func(err error) { t.Errorf("the switch left no bus: %v", err) },
		OnEvaluated: func(bustls.Mode, error) {
			c.evalMu.Lock()
			c.evals++
			c.evalMu.Unlock()
			c.evaluated.fire()
		},
	})
	holdSvc.Store(c.svc)
	if err := srv.OnClientDisconnect(c.svc.NoteDisconnect); err != nil {
		t.Fatal(err)
	}
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
			c.changed.fire()
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.svc.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	c.stopFn = func() {
		once.Do(func() {
			c.svc.Stop()
			invSvc.Stop()
			responder.Stop()
			srv.Stop()
			cancel()
			_ = invStore.Close()
			_ = jobStore.Close()
			_ = settings.Close()
			_ = tokens.Close()
		})
	}
	t.Cleanup(c.stop)
	return c
}

func (c *cp) url() string { return fmt.Sprintf("nats://127.0.0.1:%d", c.port) }

// agentTokenFile is where this controlplane mints its own agent's bus token.
func (c *cp) agentTokenFile() string {
	return filepath.Join(c.dataDir, "bus", proto.BusAgentTokenFileName)
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

func (c *cp) evaluations() int {
	c.evalMu.Lock()
	defer c.evalMu.Unlock()
	return c.evals
}

// waitEvaluatedAfter waits for an evaluation to complete after the count n was
// read — the positive fact behind "it looked, and did not move".
func (c *cp) waitEvaluatedAfter(t *testing.T, n int, what string) {
	t.Helper()
	waitFact(t, "evaluation after "+what, &c.evaluated, func() bool { return c.evaluations() > n }, func() string { return "" })
	c.svc.Wait()
}

func (c *cp) describeRegs() string {
	c.regMu.Lock()
	defer c.regMu.Unlock()
	return fmt.Sprintf("registrations: %+v", c.regs)
}

// waitRegistered waits for THIS instance to receive a registration from id
// whose busTls is want.
func (c *cp) waitRegistered(t *testing.T, id string, want bool) {
	t.Helper()
	c.waitRegisteredSince(t, 0, id, want)
}

func (c *cp) regCount() int {
	c.regMu.Lock()
	defer c.regMu.Unlock()
	return len(c.regs)
}

// waitRegisteredSince is waitRegistered counting only registrations after the
// first `since` this instance received.
func (c *cp) waitRegisteredSince(t *testing.T, since int, id string, want bool) {
	t.Helper()
	waitFact(t, fmt.Sprintf("registration from %s with busTls=%t (after #%d)", id, want, since), &c.changed, func() bool {
		c.regMu.Lock()
		defer c.regMu.Unlock()
		for _, ev := range c.regs[since:] {
			if v, ok := ev.Metadata[proto.MetadataBusTLS].(bool); ev.NodeID == id && ok && v == want {
				return true
			}
		}
		return false
	}, c.describeRegs)
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

// waitSwitched waits for the switch to TLS-only to complete.
func (c *cp) waitSwitched(t *testing.T) {
	t.Helper()
	select {
	case <-c.switched:
	case <-time.After(factDeadline):
		st, _ := c.svc.Status(context.Background())
		t.Fatalf("no switch to TLS-only within %s; status %+v", factDeadline, st)
	}
	c.svc.Wait()
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

// With the mode pinned to offer (RASPUTIN_BUS_TLS, the escape hatch): the
// right pin connects over TLS and says so; a wrong pin is refused by the agent
// and never registers; no pin still connects, in plaintext, and the server
// lists it. A pinned mode never moves, however ready things look.
func TestFunctional_PinnedOffer(t *testing.T) {
	skipShort(t)
	c := startCP(t, cpOpts{pinMode: bustls.ModeOffer})

	startAgent(t, agentOpts{id: "n-good", url: c.url(), token: c.mint(t, "n-good"), pin: c.key.Pin()})
	c.waitRegistered(t, "n-good", true)

	bad := startAgent(t, agentOpts{id: "n-bad", url: c.url(), token: c.mint(t, "n-bad"), pin: otherPin(t)})
	bad.waitLog(t, "the pin mismatch refusal", "does not match RASPUTIN_BUS_PIN")

	startAgent(t, agentOpts{id: "n-plain", url: c.url(), token: c.mint(t, "n-plain")})
	c.waitRegistered(t, "n-plain", false)

	if c.registeredAtAll("n-bad") {
		t.Fatal("a node with the wrong pin registered")
	}
	st, err := c.svc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode != bustls.ModeOffer || !st.ModePinned || st.Next != "" {
		t.Fatalf("pinned status = %+v, want offer, pinned, going nowhere", st)
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

// The whole automatic ladder, end to end, with no operator action:
//
//  1. offer: the controlplane (cp1) booted a build as a trial, and a
//     self-update job is in flight; it and a compute node (n1), both enrolled
//     before the pin existed, connect in plaintext. Nothing moves.
//  2. commit, each half on its own: the self-update job ends while cp1's agent
//     still reports the trial — nothing moves; the saga's mark-good lands and
//     the next job end re-evaluates — the api moves to migrate and delivers
//     the pin.
//  3. both agents save the pin, re-dial over TLS and register busTls=true; the
//     plaintext connections they closed are reported by disconnect events; a
//     job in flight still holds require back until it ends.
//  4. require, IN-PROCESS: job intake closes, require is recorded, the bus
//     server is replaced by one that refuses plaintext — the same bus.Server,
//     the same api connection, no restart — and a job submitted before and
//     after the server swap is refused with the retryable error, not lost.
//     Intake reopens; the same job then runs, over the new bus, to both
//     agents, which rejoined over TLS by themselves.
//  5. afterwards: plaintext is refused on the wire, no plaintext client is
//     listed, a node that never got a pin is refused, both agents restarted
//     with no pin in their environment rejoin from the pin they saved, and
//     the switch never runs again. A later restart of the controlplane comes
//     up in require and does not switch either.
func TestFunctional_AutomaticLadder(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	c := startCP(t, cpOpts{selfNode: "cp1"})
	if c.mode != bustls.ModeOffer {
		t.Fatalf("a fresh controlplane starts in %s, want offer", c.mode)
	}
	pin := c.key.Pin()

	// 1. An uncommitted build and a self-update in flight.
	now := time.Now().UTC()
	selfUpdate := &jobs.Job{ID: "01SELFUPDATE", Kind: "node.update", Spec: json.RawMessage(`{"nodeId":"cp1"}`), Status: jobs.StatusQueued, CreatedAt: now}
	if err := c.jobStore.CreateJob(ctx, selfUpdate); err != nil {
		t.Fatal(err)
	}
	if err := c.jobStore.MarkJobStarted(ctx, selfUpdate.ID, now); err != nil {
		t.Fatal(err)
	}
	cpState := t.TempDir()
	seedUncommittedMock(t, cpState)
	cpAgent := startAgent(t, agentOpts{id: "cp1", role: proto.RoleControlPlane, url: c.url(), tokenFile: c.agentTokenFile(), stateDir: cpState})
	n1Token, _, err := c.tokens.MintBound(ctx, "n1", "n1", "compute")
	if err != nil {
		t.Fatal(err)
	}
	n1 := startAgent(t, agentOpts{id: "n1", url: c.url(), token: n1Token})
	c.waitRegistered(t, "cp1", false)
	c.waitRegistered(t, "n1", false)
	c.svc.Wait() // the evaluations those registrations kicked
	st, err := c.svc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode != bustls.ModeOffer || st.Committed == nil || *st.Committed {
		t.Fatalf("status before commit = %+v, want offer and not committed", st)
	}
	if _, err := os.Stat(filepath.Join(n1.stateDir, "bus", "pin")); !os.IsNotExist(err) {
		t.Fatalf("a pin was delivered before the build committed (stat: %v)", err)
	}

	// Two more jobs in flight: one whose end is the trigger after mark-good,
	// one that holds require back.
	var others []*jobs.Job
	for _, id := range []string{"01TRIGGER", "01BLOCKER"} {
		j := &jobs.Job{ID: id, Kind: "mesh.reconcile", Spec: json.RawMessage(`{}`), Status: jobs.StatusQueued, CreatedAt: now}
		if err := c.jobStore.CreateJob(ctx, j); err != nil {
			t.Fatal(err)
		}
		if err := c.jobStore.MarkJobStarted(ctx, j.ID, now); err != nil {
			t.Fatal(err)
		}
		others = append(others, j)
	}

	// 2a. The self-update job ends, but the slot is still a trial.
	n := c.evaluations()
	c.runner.FinishDeferred(ctx, selfUpdate.ID, true, "")
	c.waitEvaluatedAfter(t, n, "the self-update job ended")
	if st, err = c.svc.Status(ctx); err != nil {
		t.Fatal(err)
	}
	if st.Mode != bustls.ModeOffer || st.Committed == nil || *st.Committed || !strings.Contains(st.CommittedDetail, "not good") {
		t.Fatalf("after the job ended with the slot uncommitted: %+v, want offer held back by the agent's report", st)
	}

	// 2b. mark-good on cp1's agent, as the saga does; the next job end is the
	// event that re-decides.
	markGood, err := json.Marshal(proto.UpdateMarkGoodCmd{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.srv.Conn().Request(proto.UpdateMarkGoodSubject("cp1"), markGood, 10*time.Second); err != nil {
		t.Fatalf("mark-good on cp1: %v", err)
	}
	c.runner.FinishDeferred(ctx, others[0].ID, true, "")
	blocker := others[1]

	// 3. Pins delivered, TLS re-dials, busTls=true everywhere.
	c.waitRegistered(t, "cp1", true)
	c.waitRegistered(t, "n1", true)
	for _, a := range []*agentProc{cpAgent, n1} {
		saved, err := os.ReadFile(filepath.Join(a.stateDir, "bus", "pin"))
		if err != nil || strings.TrimSpace(string(saved)) != pin {
			t.Fatalf("%s saved pin = (%q, %v), want %s", a.id, saved, err, pin)
		}
	}
	if got, _ := c.settings.Get(ctx, bustls.SettingKey); got != string(bustls.ModeMigrate) {
		t.Fatalf("recorded mode = %q with a job in flight, want migrate", got)
	}
	if got := c.switches.Load(); got != 0 {
		t.Fatalf("switched %d time(s) while a job was in flight", got)
	}

	// 4. The last job ends: require, switched in-process, once.
	pingOK := make(chan string, 4)
	c.runner.Register(jobs.Workflow{Kind: "probe.ping", Steps: []jobs.WorkflowStep{{Name: "ping", Timeout: 20 * time.Second, Do: func(sc *jobs.StepCtx) (json.RawMessage, error) {
		for _, id := range []string{"cp1", "n1"} {
			cmd, _ := json.Marshal(proto.DiagPingCmd{JobID: sc.JobID})
			if _, err := sc.NATS.RequestWithContext(sc.Ctx, proto.NodeCmdSubject(id, "diag.ping"), cmd); err != nil {
				return nil, fmt.Errorf("ping %s: %w", id, err)
			}
			pingOK <- id
		}
		return nil, nil
	}}}})
	api := c.srv.Conn()
	regsBefore := c.regCount()
	refused := map[string]error{}
	onSwitch := func(phase string) {
		_, refused[phase] = c.runner.Submit(ctx, "probe.ping", nil, "test")
		if got, _ := c.settings.Get(ctx, bustls.SettingKey); got != string(bustls.ModeRequire) {
			t.Errorf("%s the server swap the recorded mode is %q, want require", phase, got)
		}
		if on, _ := c.svc.Switching(); !on {
			t.Errorf("%s the server swap Switching() = false", phase)
		}
	}
	c.onSwitch.Store(&onSwitch)
	c.runner.FinishDeferred(ctx, blocker.ID, true, "")
	c.waitSwitched(t)
	for _, phase := range []string{"before", "after"} {
		if !errors.Is(refused[phase], jobs.ErrQuiesced) {
			t.Fatalf("Submit %s the server swap = %v, want ErrQuiesced (refused, retryable, not lost)", phase, refused[phase])
		}
	}
	if n, err := jobs.InFlight(ctx, c.jobStore); err != nil || len(n) != 0 {
		t.Fatalf("jobs in flight after refused submits: %q (%v)", n, err)
	}
	if got, _ := c.settings.Get(ctx, bustls.SettingKey); got != string(bustls.ModeRequire) {
		t.Fatalf("recorded mode = %q after the switch, want require", got)
	}
	if c.srv.Conn() != api || !api.IsConnected() || c.srv.AllowsPlaintext() {
		t.Fatalf("after the switch: same conn %t, connected %t, plaintext allowed %t", c.srv.Conn() == api, api.IsConnected(), c.srv.AllowsPlaintext())
	}
	st, err = c.svc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode != bustls.ModeRequire || st.PlaintextAllowed || st.Switching || st.SwitchFailed != "" {
		t.Fatalf("status after the switch = %+v", st)
	}
	// The agents rejoin the new server over TLS on their own reconnect loops.
	c.waitRegisteredSince(t, regsBefore, "cp1", true)
	c.waitRegisteredSince(t, regsBefore, "n1", true)
	// The retry of the refused submit is accepted and runs over the new bus.
	j, err := c.runner.Submit(ctx, "probe.ping", nil, "test")
	if err != nil {
		t.Fatalf("Submit after the switch = %v, want accepted", err)
	}
	for range 2 {
		select {
		case <-pingOK:
		case <-time.After(factDeadline):
			got, _ := c.jobStore.GetJob(ctx, j.ID)
			t.Fatalf("job %s did not reach both agents over the new bus: %+v", j.ID, got)
		}
	}
	c.runner.Wait()
	if got, err := c.jobStore.GetJob(ctx, j.ID); err != nil || got.Status != jobs.StatusSucceeded {
		t.Fatalf("job after the switch = %+v (%v), want succeeded", got, err)
	}

	// 5. Plaintext is refused, nobody is on it, an unpinned node is refused,
	// and the saved pins bring the agents back from a restart of their own.
	assertPlaintextRefused(t, c.port)
	plain, err := c.srv.PlaintextClients()
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != 0 {
		t.Fatalf("plaintext connections on a TLS-required bus: %+v", plain)
	}
	stray := startAgent(t, agentOpts{id: "n-unmigrated", url: c.url(), token: c.mint(t, "n-unmigrated")})
	stray.waitLog(t, "the TLS-required refusal of an unpinned node", "NATS connect", "tls")
	if c.registeredAtAll("n-unmigrated") {
		t.Fatal("an unpinned node registered on a TLS-required bus")
	}
	stray.stop(t)

	cpAgent.stop(t)
	n1.stop(t)
	regsBefore = c.regCount()
	startAgent(t, agentOpts{id: "cp1", role: proto.RoleControlPlane, url: c.url(), tokenFile: c.agentTokenFile(), stateDir: cpAgent.stateDir})
	n1b := startAgent(t, agentOpts{id: "n1", url: c.url(), token: n1Token, stateDir: n1.stateDir})
	n1b.waitLog(t, "the saved pin", "from file")
	n1b.waitLog(t, "a pinned TLS connection", "over TLS, server key pin verified")
	c.waitRegisteredSince(t, regsBefore, "cp1", true)
	c.waitRegisteredSince(t, regsBefore, "n1", true)
	if got := c.switches.Load(); got != 1 {
		t.Fatalf("switches = %d, want exactly 1", got)
	}

	// A later restart of the controlplane (a reboot, an update) starts in
	// require and has nothing to switch.
	c.stop()
	c2 := startCP(t, cpOpts{dataDir: c.dataDir, port: c.port, selfNode: "cp1"})
	if c2.mode != bustls.ModeRequire || c2.key.Pin() != pin {
		t.Fatalf("restarted controlplane: mode %s pin %s, want require and %s", c2.mode, c2.key.Pin(), pin)
	}
	c2.waitRegistered(t, "cp1", true)
	c2.waitRegistered(t, "n1", true)
	if got := c2.switches.Load(); got != 0 {
		t.Fatalf("a controlplane started in require switched %d time(s)", got)
	}
}

// assertPlaintextRefused dials the bus port in plaintext: the server's INFO
// says TLS is required, and a CONNECT written anyway gets no PONG — the
// connection is closed.
func assertPlaintextRefused(t *testing.T, port int) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second)) // bounds this one exchange
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "INFO ") {
		t.Fatalf("first line from the bus = (%q, %v), want INFO", line, err)
	}
	var info map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSpace(line), "INFO ")), &info); err != nil {
		t.Fatal(err)
	}
	if info["tls_required"] != true {
		t.Fatalf("INFO tls_required = %v, want true", info["tls_required"])
	}
	if _, err := conn.Write([]byte("CONNECT {\"verbose\":false,\"user\":\"n1\"}\r\nPING\r\n")); err != nil {
		t.Fatal(err)
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatalf("the bus neither answered nor closed a plaintext CONNECT: %v", err)
			}
			return
		}
		if strings.HasPrefix(line, "PONG") {
			t.Fatal("a plaintext CONNECT got PONG from a TLS-required bus")
		}
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
			c := startCP(t, cpOpts{dataDir: dataDir, pinMode: bustls.ModeRequire, cert: &cert})
			id := "n-" + name
			startAgent(t, agentOpts{id: id, url: c.url(), token: c.mint(t, id), pin: key.Pin()})
			c.waitRegistered(t, id, true)
			c.stop()
		})
	}
}

// The controlplane's own agent on the bus once loopback earns no trust
// (geekdojo-brain#140), with the REAL agent binary:
//
//  1. the agent starts BEFORE its api has minted the token file (an update
//     that puts the agent up first, or a slow api): its connect attempts fail
//     for want of a token, and it joins on its own once the file appears —
//     no restart, no timer, just its ordinary retry reading the file again;
//  2. an impostor agent on the same box, with no token, claiming an enrolled
//     node's id over 127.0.0.1, is refused and never registers — nor does one
//     claiming the controlplane's own id;
//  3. the token file is deleted and the controlplane restarts: it re-mints,
//     the old token stops authenticating, and the SAME agent process rejoins
//     with the new token.
func TestFunctional_ControlplaneAgentToken(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	// Offer, pinned: this test is about authentication, not the TLS ladder.
	c := startCP(t, cpOpts{pinMode: bustls.ModeOffer})
	tokenFile := c.agentTokenFile()

	// 1. No file yet (startCP minted nothing: no self node id).
	cpAgent := startAgent(t, agentOpts{id: "cp1", role: proto.RoleControlPlane, url: c.url(), tokenFile: tokenFile})
	cpAgent.waitLog(t, "a connect attempt with no token file", "no join token for this connection attempt", "does not exist yet")
	if c.registeredAtAll("cp1") {
		t.Fatal("the controlplane agent registered with no token")
	}
	if _, err := c.tokens.EnsureAgentToken(ctx, tokenFile, "cp1"); err != nil { // the api's start
		t.Fatal(err)
	}
	c.waitRegistered(t, "cp1", false)

	// 2. Impostors over loopback, no token.
	c.mint(t, "n-victim") // enrolled, not running
	for _, id := range []string{"n-victim", "cp1"} {
		imp := startAgent(t, agentOpts{id: id, url: c.url()})
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
	c2 := startCP(t, cpOpts{dataDir: c.dataDir, port: c.port, selfNode: "cp1", pinMode: bustls.ModeOffer})
	cur, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatalf("the restarted controlplane did not re-mint the token file: %v", err)
	}
	if string(cur) == string(old) {
		t.Fatal("the restarted controlplane wrote the old token back")
	}
	c2.waitRegistered(t, "cp1", false)
	cpAgent.waitLogSince(t, since, "the same agent process back on the bus", "reconnected to", fmt.Sprint(c2.port))
	if cpAgent.cmd.ProcessState != nil {
		t.Fatal("the controlplane agent process exited")
	}
	select {
	case <-cpAgent.done:
		t.Fatal("the controlplane agent process ended")
	default:
	}
	if ok, err := c2.tokens.Validate(ctx, strings.TrimSpace(string(old)), "cp1"); err != nil || ok {
		t.Fatalf("the replaced token still validates: (%v, %v)", ok, err)
	}
}
