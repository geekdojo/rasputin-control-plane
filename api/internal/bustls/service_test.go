package bustls

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

type memSettings struct {
	mu      sync.Mutex
	m       map[string]string
	failSet error
}

func (s *memSettings) Get(_ context.Context, k string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[k], nil
}

func (s *memSettings) Set(_ context.Context, k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failSet != nil {
		return s.failSet
	}
	if s.m == nil {
		s.m = map[string]string{}
	}
	s.m[k] = v
	return nil
}

func (s *memSettings) mode() string {
	v, _ := s.Get(context.Background(), SettingKey)
	return v
}

func node(id string, status proto.NodeStatus, busTLS any) *proto.Node {
	n := &proto.Node{ID: id, Role: proto.RoleCompute, Status: status, Metadata: map[string]any{}}
	if busTLS != nil {
		n.Metadata[proto.MetadataBusTLS] = busTLS
	}
	return n
}

// facts is every input the ladder reads, settable from a test.
type facts struct {
	mu        sync.Mutex
	nodes     []*proto.Node
	plain     []bus.PlaintextClient
	committed bool
	inFlight  []string
}

type fixture struct {
	svc       *Service
	settings  *memSettings
	f         *facts
	restarts  atomic.Int32
	restarted chan struct{} // closed on the first restart request
	reopens   atomic.Int32
	quiesced  atomic.Bool
}

func (x *fixture) set(fn func(f *facts)) {
	x.f.mu.Lock()
	defer x.f.mu.Unlock()
	fn(x.f)
}

// evaluate kicks one evaluation and waits for it (and any deliveries) to end.
func (x *fixture) evaluate() {
	x.svc.Kick("test")
	x.svc.Wait()
}

func newFixture(t *testing.T, start Mode, pinned bool, nc *nats.Conn) *fixture {
	t.Helper()
	k, _, err := EnsureKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	x := &fixture{settings: &memSettings{}, f: &facts{}, restarted: make(chan struct{})}
	x.svc = NewService(Config{
		Key:             k,
		Settings:        x.settings,
		StartMode:       start,
		StartModePinned: pinned,
		Nodes: func(context.Context) ([]*proto.Node, error) {
			x.f.mu.Lock()
			defer x.f.mu.Unlock()
			return x.f.nodes, nil
		},
		Plaintext: func() ([]bus.PlaintextClient, error) {
			x.f.mu.Lock()
			defer x.f.mu.Unlock()
			return x.f.plain, nil
		},
		NC: nc,
		Committed: func(context.Context) (bool, string, error) {
			x.f.mu.Lock()
			defer x.f.mu.Unlock()
			return x.f.committed, "test", nil
		},
		InFlight: func(context.Context) ([]string, error) {
			x.f.mu.Lock()
			defer x.f.mu.Unlock()
			return x.f.inFlight, nil
		},
		Quiesce: func(context.Context) (bool, []string, error) {
			x.f.mu.Lock()
			defer x.f.mu.Unlock()
			if len(x.f.inFlight) > 0 {
				return false, x.f.inFlight, nil
			}
			x.quiesced.Store(true)
			return true, nil, nil
		},
		Reopen: func() { x.reopens.Add(1); x.quiesced.Store(false) },
		Restart: func() {
			if x.restarts.Add(1) == 1 {
				close(x.restarted)
			}
		},
		DeliverTimeout: 5 * time.Second,
	})
	return x
}

// allReady makes every migrate → require fact true.
func allReady(f *facts) {
	f.committed = true
	f.nodes = []*proto.Node{node("cp1", proto.StatusOnline, true), node("n1", proto.StatusOffline, true)}
	f.plain = nil
	f.inFlight = nil
}

func TestResolveStartMode(t *testing.T) {
	ctx := context.Background()
	s := &memSettings{}

	t.Setenv(EnvMode, "")
	if m, pinned, err := ResolveStartMode(ctx, s); m != ModeOffer || pinned || err != nil {
		t.Fatalf("unset: (%s, %t, %v), want offer", m, pinned, err)
	}
	_ = s.Set(ctx, SettingKey, "require")
	if m, pinned, err := ResolveStartMode(ctx, s); m != ModeRequire || pinned || err != nil {
		t.Fatalf("setting: (%s, %t, %v), want require", m, pinned, err)
	}
	_ = s.Set(ctx, SettingKey, "bogus")
	if m, _, err := ResolveStartMode(ctx, s); m != ModeOffer || err == nil {
		t.Fatalf("bad setting: (%s, %v), want offer and an error", m, err)
	}
	t.Setenv(EnvMode, " Migrate ")
	if m, pinned, err := ResolveStartMode(ctx, s); m != ModeMigrate || !pinned || err != nil {
		t.Fatalf("env: (%s, %t, %v), want pinned migrate", m, pinned, err)
	}
	t.Setenv(EnvMode, "yes")
	if m, pinned, err := ResolveStartMode(ctx, s); m != ModeOffer || pinned || err == nil {
		t.Fatalf("bad env: (%s, %t, %v), want unpinned offer and an error", m, pinned, err)
	}
}

// offer → migrate happens on commit and on nothing else: every other fact
// true and the build uncommitted, the ladder does not move.
func TestLadder_NoMigrateWithoutCommit(t *testing.T) {
	x := newFixture(t, ModeOffer, false, nil)
	x.set(func(f *facts) { allReady(f); f.committed = false })
	x.evaluate()
	if x.svc.Mode() != ModeOffer || x.settings.mode() != "" || x.restarts.Load() != 0 {
		t.Fatalf("moved without commit: mode=%s setting=%q restarts=%d", x.svc.Mode(), x.settings.mode(), x.restarts.Load())
	}
	st, err := x.svc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Next != ModeMigrate || len(st.Blockers) != 1 || st.Committed == nil || *st.Committed {
		t.Fatalf("status = %+v, want Next migrate held back by the commit alone", st)
	}
}

// Each migrate → require fact holds the move back on its own.
func TestLadder_EachBlockingFactHoldsRequireBack(t *testing.T) {
	cases := map[string]func(f *facts){
		"a node reported plaintext":   func(f *facts) { f.nodes = append(f.nodes, node("n2", proto.StatusOnline, false)) },
		"a node never reported":       func(f *facts) { f.nodes = append(f.nodes, node("n2", proto.StatusOffline, nil)) },
		"a node reported a non-bool":  func(f *facts) { f.nodes = append(f.nodes, node("n2", proto.StatusOnline, "true")) },
		"a plaintext connection open": func(f *facts) { f.plain = []bus.PlaintextClient{{CID: 7, User: "stray", IP: "10.0.0.9"}} },
		"a job in flight":             func(f *facts) { f.inFlight = []string{"mesh.reconcile 01J"} },
		"no node enrolled":            func(f *facts) { f.nodes = nil },
	}
	for name, block := range cases {
		t.Run(name, func(t *testing.T) {
			x := newFixture(t, ModeMigrate, false, nil)
			x.set(func(f *facts) { allReady(f); block(f) })
			x.evaluate()
			if x.svc.Mode() != ModeMigrate || x.settings.mode() == string(ModeRequire) || x.restarts.Load() != 0 || x.quiesced.Load() {
				t.Fatalf("moved past a blocker: mode=%s setting=%q restarts=%d quiesced=%t", x.svc.Mode(), x.settings.mode(), x.restarts.Load(), x.quiesced.Load())
			}
			st, err := x.svc.Status(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(st.Blockers) != 1 {
				t.Fatalf("blockers = %q, want exactly the one fact", st.Blockers)
			}
		})
	}
}

// All facts true: require is persisted, intake closed, and the api restarts
// exactly once — however many events arrive after.
func TestLadder_AllFactsAdvanceToRequireAndRestartOnce(t *testing.T) {
	x := newFixture(t, ModeMigrate, false, nil)
	x.set(allReady)
	x.evaluate()
	if x.settings.mode() != string(ModeRequire) || x.svc.Mode() != ModeRequire {
		t.Fatalf("setting=%q mode=%s, want require", x.settings.mode(), x.svc.Mode())
	}
	if !x.quiesced.Load() {
		t.Fatal("restarted without closing job intake")
	}
	for i := 0; i < 3; i++ {
		x.evaluate()
		x.svc.OnRegistered(context.Background(), node("n1", proto.StatusOnline, true))
		x.svc.NoteDisconnect(99)
		x.svc.Wait()
	}
	if got := x.restarts.Load(); got != 1 {
		t.Fatalf("restarts = %d, want exactly 1", got)
	}
	st, err := x.svc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.RestartPending || !st.PlaintextAllowed {
		t.Fatalf("status = %+v, want restart pending on a server still allowing plaintext", st)
	}
}

// A process that started TLS-required never asks to restart.
func TestLadder_RequireAtStartIsTerminal(t *testing.T) {
	x := newFixture(t, ModeRequire, false, nil)
	x.set(allReady)
	x.evaluate()
	if x.restarts.Load() != 0 || x.quiesced.Load() {
		t.Fatalf("restarted from require: restarts=%d quiesced=%t", x.restarts.Load(), x.quiesced.Load())
	}
}

// If require cannot be persisted the api does not restart (it would come back
// allowing plaintext and try again forever), and job intake reopens.
func TestLadder_PersistFailureReopensIntakeAndDoesNotRestart(t *testing.T) {
	x := newFixture(t, ModeMigrate, false, nil)
	x.set(allReady)
	x.settings.failSet = errors.New("disk full")
	x.evaluate()
	if x.restarts.Load() != 0 || x.reopens.Load() != 1 || x.svc.Mode() != ModeMigrate {
		t.Fatalf("restarts=%d reopens=%d mode=%s, want no restart, intake reopened, still migrate", x.restarts.Load(), x.reopens.Load(), x.svc.Mode())
	}
}

// A fresh cluster whose every seed is pinned: committed, the controlplane's
// own agent already on TLS, nothing running — one evaluation goes all the way.
func TestLadder_FreshPinnedClusterGoesStraightToRequire(t *testing.T) {
	x := newFixture(t, ModeOffer, false, nil)
	x.set(func(f *facts) {
		allReady(f)
		f.nodes = []*proto.Node{node("cp1", proto.StatusOnline, true)}
	})
	x.evaluate()
	if x.settings.mode() != string(ModeRequire) || x.restarts.Load() != 1 {
		t.Fatalf("setting=%q restarts=%d, want require after one evaluation", x.settings.mode(), x.restarts.Load())
	}
}

// A pinned mode never moves, and a pinned mode below require is a standing
// warning; an unpinned ladder or a pinned require raises none.
func TestLadder_PinnedModeNeverMovesAndWarns(t *testing.T) {
	x := newFixture(t, ModeOffer, true, nil)
	x.set(allReady)
	x.evaluate()
	if x.svc.Mode() != ModeOffer || x.settings.mode() != "" || x.restarts.Load() != 0 {
		t.Fatalf("a pinned mode moved: mode=%s setting=%q", x.svc.Mode(), x.settings.mode())
	}
	a := x.svc.Alert(time.Now())
	if a == nil || a.ID != "bus-tls-pinned" || a.Severity != proto.AlertWarn || a.Source != proto.AlertSourceSecurity {
		t.Fatalf("Alert = %+v, want a bus-tls-pinned security warn", a)
	}
	if a := newFixture(t, ModeRequire, true, nil).svc.Alert(time.Now()); a != nil {
		t.Fatalf("pinned require warns: %+v", a)
	}
	if a := newFixture(t, ModeOffer, false, nil).svc.Alert(time.Now()); a != nil {
		t.Fatalf("unpinned offer warns: %+v", a)
	}
}

// The disconnect advisory can land before the server stops listing the
// connection; the id it names counts as closed, and is forgotten once the
// listing drops it.
func TestLadder_DisconnectEventOutranksAStaleListing(t *testing.T) {
	x := newFixture(t, ModeMigrate, false, nil)
	x.set(func(f *facts) {
		allReady(f)
		f.plain = []bus.PlaintextClient{{CID: 42, User: "n1", IP: "127.0.0.1"}}
	})
	x.evaluate()
	if x.restarts.Load() != 0 {
		t.Fatal("restarted with a plaintext connection listed")
	}
	x.svc.NoteDisconnect(42)
	x.svc.Wait()
	if x.restarts.Load() != 1 {
		t.Fatalf("restarts = %d after the last plaintext connection's disconnect, want 1", x.restarts.Load())
	}
	x.set(func(f *facts) { f.plain = nil })
	if _, err := x.svc.openPlaintext(); err != nil {
		t.Fatal(err)
	}
	x.svc.mu.Lock()
	left := len(x.svc.closedCIDs)
	x.svc.mu.Unlock()
	if left != 0 {
		t.Fatalf("closed ids kept after the listing dropped them: %d", left)
	}
}

// --- against a real bus ------------------------------------------------------

func startBus(t *testing.T) *nats.Conn {
	t.Helper()
	s, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go s.Start()
	if !s.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats not ready")
	}
	t.Cleanup(func() {
		s.Shutdown()
		s.WaitForShutdown()
	})
	nc, err := nats.Connect(s.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// fakeAgent answers bus.pin for id and records the pins it was handed.
func fakeAgent(t *testing.T, nc *nats.Conn, id string, got chan<- string) {
	t.Helper()
	_, err := nc.Subscribe(proto.NodeCmdSubject(id, proto.BusPinVerb), func(m *nats.Msg) {
		var cmd proto.BusPinCmd
		_ = json.Unmarshal(m.Data, &cmd)
		got <- cmd.Pin
		b, _ := json.Marshal(proto.BusPinAck{NodeID: id, OK: true, Pin: cmd.Pin, Reconnecting: true})
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
}

// Entering migrate sweeps the ONLINE nodes not on TLS; a registration brings
// an offline one its pin; offer delivers nothing.
func TestDelivery_OnlyInMigrateAndOnlyToNodesNotOnTLS(t *testing.T) {
	ctx := context.Background()
	nc := startBus(t)
	x := newFixture(t, ModeOffer, false, nc)
	got := make(chan string, 16)
	for _, id := range []string{"plain", "tls", "gone"} {
		fakeAgent(t, nc, id, got)
	}
	plain := node("plain", proto.StatusOnline, false)
	onTLS := node("tls", proto.StatusOnline, true)
	gone := node("gone", proto.StatusOffline, false)
	x.set(func(f *facts) { f.nodes = []*proto.Node{plain, onTLS, gone} })

	x.svc.OnRegistered(ctx, plain)
	x.svc.Wait()
	if len(got) != 0 {
		t.Fatalf("offer delivered a pin to %q", <-got)
	}

	x.set(func(f *facts) { f.committed = true })
	x.evaluate()
	if x.svc.Mode() != ModeMigrate {
		t.Fatalf("mode = %s after commit, want migrate", x.svc.Mode())
	}
	if n := len(got); n != 1 {
		t.Fatalf("entering migrate delivered %d pin(s), want 1 (plain only)", n)
	}
	if pin := <-got; pin != x.svc.Pin() {
		t.Fatalf("delivered %q, want the live pin %q", pin, x.svc.Pin())
	}

	x.svc.OnRegistered(ctx, gone)
	x.svc.OnRegistered(ctx, onTLS)
	x.svc.Wait()
	if n := len(got); n != 1 {
		t.Fatalf("registrations delivered %d pin(s), want 1 (the returning plaintext node)", n)
	}
}

// A job ending is an evaluation trigger: Start subscribes to job events, and a
// succeeded event re-decides without any other prompt.
func TestLadder_JobEndIsATrigger(t *testing.T) {
	nc := startBus(t)
	x := newFixture(t, ModeMigrate, false, nc)
	x.set(func(f *facts) { allReady(f); f.inFlight = []string{"backup.run 01J"} })
	if err := x.svc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(x.svc.Stop)
	x.svc.Wait()
	if x.restarts.Load() != 0 {
		t.Fatal("restarted with a job in flight")
	}

	x.set(func(f *facts) { f.inFlight = nil })
	ev, _ := json.Marshal(proto.JobEvent{Type: proto.JobSucceeded, JobID: "01J", Ts: time.Now().UTC()})
	if err := nc.Publish(proto.JobEventsSubject("01J"), ev); err != nil {
		t.Fatal(err)
	}
	select {
	case <-x.restarted:
	case <-time.After(10 * time.Second): // deadline on the fact, not a sync sleep
		t.Fatalf("no restart after the job-end event (restarts=%d)", x.restarts.Load())
	}
	if x.restarts.Load() != 1 {
		t.Fatalf("restarts = %d after the job-end event, want 1", x.restarts.Load())
	}
}
