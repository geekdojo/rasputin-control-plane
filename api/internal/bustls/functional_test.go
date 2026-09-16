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
// a registration that says busTls, a log line naming a refusal, the restart
// request. Nothing here sleeps to let something happen.
//
// What it does NOT prove: the OS or firewall images (firstboot, apply-seed,
// the seed scrub), mDNS resolution of <cluster>.local, a real RAUC slot commit
// (the controlplane agent runs the mock updater backend, whose commit model is
// unit-tested beside the RAUC one), systemd restarting the api, or real clocks
// on real hardware. That is the bench plan in the PR.
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
	restart  chan struct{} // closed when the service asks to restart

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
	// agent answers the commit question.
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
	c := &cp{dataDir: o.dataDir, selfNode: o.selfNode, restart: make(chan struct{})}
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
	responder := busauth.NewResponder(srv.Conn(), issuer, tokens)
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
	var restartOnce sync.Once
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
		Restart:  func() { restartOnce.Do(func() { close(c.restart) }) },
		OnEvaluated: func(bustls.Mode, error) {
			c.evalMu.Lock()
			c.evals++
			c.evalMu.Unlock()
			c.evaluated.fire()
		},
	})
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
	waitFact(t, fmt.Sprintf("registration from %s with busTls=%t", id, want), &c.changed, func() bool {
		c.regMu.Lock()
		defer c.regMu.Unlock()
		for _, ev := range c.regs {
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

// waitRestart waits for the service's restart request.
func (c *cp) waitRestart(t *testing.T) {
	t.Helper()
	select {
	case <-c.restart:
	case <-time.After(factDeadline):
		st, _ := c.svc.Status(context.Background())
		t.Fatalf("no restart request within %s; status %+v", factDeadline, st)
	}
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
//  4. require: job intake closes, require is recorded, the restart is asked
//     for exactly once, and a job submitted now is refused, not lost.
//  5. restart: the controlplane comes back, reads require, refuses plaintext;
//     both running agents rejoin over TLS by themselves; restarted with no pin
//     in their environment they rejoin from the pin they saved; a node that
//     never got a pin is refused.
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
	cpAgent := startAgent(t, agentOpts{id: "cp1", role: proto.RoleControlPlane, url: c.url(), stateDir: cpState})
	n1Token, _, err := c.tokens.MintBound(ctx, "n1", "n1")
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
	select {
	case <-c.restart:
		t.Fatal("restart requested while a job was in flight")
	default:
	}

	// 4. The last job ends: require, once.
	c.runner.FinishDeferred(ctx, blocker.ID, true, "")
	c.waitRestart(t)
	if got, _ := c.settings.Get(ctx, bustls.SettingKey); got != string(bustls.ModeRequire) {
		t.Fatalf("recorded mode = %q after the restart request, want require", got)
	}
	if _, err := c.runner.Submit(ctx, "anything", nil, "test"); err == nil || (!errors.Is(err, jobs.ErrQuiesced) && !strings.Contains(err.Error(), "unknown job kind")) {
		t.Fatalf("Submit during the restart window = %v", err)
	}
	c.runner.Register(jobs.Workflow{Kind: "probe", Steps: []jobs.WorkflowStep{{Name: "noop", Do: func(*jobs.StepCtx) (json.RawMessage, error) { return nil, nil }}}})
	if _, err := c.runner.Submit(ctx, "probe", nil, "test"); !errors.Is(err, jobs.ErrQuiesced) {
		t.Fatalf("Submit during the restart window = %v, want ErrQuiesced (refused, not lost)", err)
	}

	// 5. The restart the unit performs, same data dir and port.
	c.stop()
	c2 := startCP(t, cpOpts{dataDir: c.dataDir, port: c.port, selfNode: "cp1"})
	if c2.mode != bustls.ModeRequire || c2.key.Pin() != pin {
		t.Fatalf("restarted controlplane: mode %s pin %s, want require and %s", c2.mode, c2.key.Pin(), pin)
	}
	c2.waitRegistered(t, "cp1", true)
	c2.waitRegistered(t, "n1", true)

	cpAgent.stop(t)
	n1.stop(t)
	startAgent(t, agentOpts{id: "cp1", role: proto.RoleControlPlane, url: c2.url(), stateDir: cpAgent.stateDir})
	n1b := startAgent(t, agentOpts{id: "n1", url: c2.url(), token: n1Token, stateDir: n1.stateDir})
	n1b.waitLog(t, "the saved pin", "from file")
	n1b.waitLog(t, "a pinned TLS connection", "over TLS, server key pin verified")

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
	select {
	case <-c2.restart:
		t.Fatal("the restarted controlplane asked to restart again")
	default:
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
			startAgent(t, agentOpts{id: id, url: c.url(), pin: key.Pin()})
			c.waitRegistered(t, id, true)
			c.stop()
		})
	}
}
