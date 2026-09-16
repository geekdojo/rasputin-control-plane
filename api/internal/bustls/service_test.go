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
	mu sync.Mutex
	m  map[string]string
}

func (s *memSettings) Get(_ context.Context, k string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[k], nil
}

func (s *memSettings) Set(_ context.Context, k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]string{}
	}
	s.m[k] = v
	return nil
}

func node(id string, status proto.NodeStatus, busTLS any) *proto.Node {
	n := &proto.Node{ID: id, Role: proto.RoleCompute, Status: status, Metadata: map[string]any{}}
	if busTLS != nil {
		n.Metadata[proto.MetadataBusTLS] = busTLS
	}
	return n
}

type fixture struct {
	svc      *Service
	settings *memSettings
	restarts atomic.Int32
	mu       sync.Mutex
	nodes    []*proto.Node
	plain    []bus.PlaintextClient
}

func (f *fixture) setNodes(n ...*proto.Node) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodes = n
}

func newFixture(t *testing.T, start Mode, pinned bool, nc *nats.Conn) *fixture {
	t.Helper()
	k, _, err := EnsureKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{settings: &memSettings{}}
	f.svc = NewService(Config{
		Key:             k,
		Settings:        f.settings,
		StartMode:       start,
		StartModePinned: pinned,
		Nodes: func(context.Context) ([]*proto.Node, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.nodes, nil
		},
		Plaintext: func() ([]bus.PlaintextClient, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.plain, nil
		},
		NC:             nc,
		Restart:        func() { f.restarts.Add(1) },
		DeliverTimeout: 5 * time.Second,
	})
	return f
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

func TestStatus_ReadinessIsEveryNodeOnTLSAndNoPlaintext(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, ModeOffer, false, nil)

	st, err := f.svc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Ready || len(st.Blockers) != 1 {
		t.Fatalf("an empty inventory reads ready=%t blockers=%v; want not ready, one blocker", st.Ready, st.Blockers)
	}
	if st.Pin != f.svc.Pin() || !st.PlaintextAllowed || st.RestartPending {
		t.Fatalf("status = %+v", st)
	}

	f.setNodes(
		node("a", proto.StatusOnline, true),
		node("b", proto.StatusOffline, false), // reported plaintext, and offline: still blocks
		node("c", proto.StatusOnline, nil),    // never reported
		node("d", proto.StatusOnline, "true"), // a string is not a report of true
	)
	st, err = f.svc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Ready || len(st.Blockers) != 3 {
		t.Fatalf("ready=%t blockers=%v, want three blockers (b, c, d)", st.Ready, st.Blockers)
	}
	byID := map[string]NodeTLS{}
	for _, n := range st.Nodes {
		byID[n.ID] = n
	}
	if !byID["a"].BusTLS || byID["b"].BusTLS || !byID["b"].Reported || byID["c"].Reported {
		t.Fatalf("node reports = %+v", st.Nodes)
	}

	f.setNodes(node("a", proto.StatusOnline, true), node("b", proto.StatusOffline, true))
	f.mu.Lock()
	f.plain = []bus.PlaintextClient{{User: "stray", IP: "10.0.0.9"}}
	f.mu.Unlock()
	if st, _ = f.svc.Status(ctx); st.Ready {
		t.Fatalf("ready with a plaintext connection open: %+v", st)
	}
	f.mu.Lock()
	f.plain = nil
	f.mu.Unlock()
	if st, _ = f.svc.Status(ctx); !st.Ready || len(st.Blockers) != 0 {
		t.Fatalf("every node on TLS and no plaintext, but ready=%t blockers=%v", st.Ready, st.Blockers)
	}
}

func TestSetMode_RequireWaitsForTheFact(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, ModeMigrate, false, nil)
	f.setNodes(node("a", proto.StatusOnline, true), node("b", proto.StatusOnline, false))

	_, err := f.svc.SetMode(ctx, ModeRequire)
	var nr *NotReadyError
	if !errors.As(err, &nr) || len(nr.Blockers) != 1 {
		t.Fatalf("SetMode(require) with a plaintext node = %v, want NotReadyError naming it", err)
	}
	if v, _ := f.settings.Get(ctx, SettingKey); v != "" {
		t.Fatalf("a refused require was persisted as %q", v)
	}
	if f.restarts.Load() != 0 {
		t.Fatal("a refused require restarted the api")
	}

	f.setNodes(node("a", proto.StatusOnline, true), node("b", proto.StatusOnline, true))
	st, err := f.svc.SetMode(ctx, ModeRequire)
	if err != nil {
		t.Fatalf("SetMode(require) when ready: %v", err)
	}
	if v, _ := f.settings.Get(ctx, SettingKey); v != string(ModeRequire) {
		t.Fatalf("setting = %q, want require", v)
	}
	if st.Mode != ModeRequire || !st.RestartPending || !st.PlaintextAllowed {
		t.Fatalf("status after require = %+v, want mode require, restart pending, running server still allowing plaintext", st)
	}
	if got := f.restarts.Load(); got != 1 {
		t.Fatalf("restarts = %d, want 1", got)
	}
	// Asking again while the restart is on its way does not ask twice.
	if _, err := f.svc.SetMode(ctx, ModeRequire); err != nil {
		t.Fatal(err)
	}
	if got := f.restarts.Load(); got != 1 {
		t.Fatalf("restarts = %d after a repeat, want 1", got)
	}
}

// Leaving require is the recovery path and is never gated.
func TestSetMode_LeavingRequireIsNeverRefused(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, ModeRequire, false, nil)
	f.setNodes(node("a", proto.StatusOnline, false))
	if _, err := f.svc.SetMode(ctx, ModeOffer); err != nil {
		t.Fatalf("SetMode(offer) from require: %v", err)
	}
	if got := f.restarts.Load(); got != 1 {
		t.Fatalf("restarts = %d, want 1 (plaintext is allowed again only after a restart)", got)
	}
}

func TestSetMode_OfferToMigrateNeedsNoRestart(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, ModeOffer, false, nil)
	if _, err := f.svc.SetMode(ctx, ModeMigrate); err != nil {
		t.Fatal(err)
	}
	if f.restarts.Load() != 0 {
		t.Fatal("offer → migrate restarted the api; the server option did not change")
	}
}

func TestSetMode_PinnedByEnv(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, ModeMigrate, true, nil)
	if _, err := f.svc.SetMode(ctx, ModeOffer); !errors.Is(err, ErrModePinned) {
		t.Fatalf("SetMode on a pinned mode = %v, want ErrModePinned", err)
	}
	if v, _ := f.settings.Get(ctx, SettingKey); v != "" {
		t.Fatalf("a pinned mode wrote the setting: %q", v)
	}
}

// --- delivery against a real bus -------------------------------------------

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

func TestDelivery_OnlyInMigrateAndOnlyToNodesNotOnTLS(t *testing.T) {
	ctx := context.Background()
	nc := startBus(t)
	f := newFixture(t, ModeOffer, false, nc)
	got := make(chan string, 16)
	for _, id := range []string{"plain", "tls", "gone"} {
		fakeAgent(t, nc, id, got)
	}
	plain := node("plain", proto.StatusOnline, false)
	onTLS := node("tls", proto.StatusOnline, true)
	gone := node("gone", proto.StatusOffline, false)
	f.setNodes(plain, onTLS, gone)

	// offer: registrations deliver nothing.
	f.svc.OnRegistered(ctx, plain)
	f.svc.Wait()
	if len(got) != 0 {
		t.Fatalf("offer delivered a pin to %q", <-got)
	}

	// Entering migrate sweeps the ONLINE nodes not on TLS.
	if _, err := f.svc.SetMode(ctx, ModeMigrate); err != nil {
		t.Fatal(err)
	}
	f.svc.Wait()
	if n := len(got); n != 1 {
		t.Fatalf("entering migrate delivered %d pin(s), want 1 (plain only)", n)
	}
	if pin := <-got; pin != f.svc.Pin() {
		t.Fatalf("delivered %q, want the live pin %q", pin, f.svc.Pin())
	}

	// A registration is the fact that brings the offline node back.
	f.svc.OnRegistered(ctx, gone)
	f.svc.OnRegistered(ctx, onTLS)
	f.svc.Wait()
	if n := len(got); n != 1 {
		t.Fatalf("registrations delivered %d pin(s), want 1 (the returning plaintext node)", n)
	}

	ack, err := f.svc.Deliver(ctx, "plain")
	if err != nil || !ack.OK {
		t.Fatalf("Deliver = (%+v, %v)", ack, err)
	}
	<-got
}
