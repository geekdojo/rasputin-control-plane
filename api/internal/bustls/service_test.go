package bustls

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

type memSettings struct {
	mu      sync.Mutex
	m       map[string]string
	failSet error
	// onSet, when set, is told every value written (the ordering log).
	onSet func(k, v string)
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
	if s.onSet != nil {
		s.onSet(k, v)
	}
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
	svc      *Service
	settings *memSettings
	f        *facts
	switches atomic.Int32
	switched chan struct{} // closed when the first RequireTLS returns
	reopens  atomic.Int32
	quiesced atomic.Bool
	noBus    atomic.Int32

	// switchErr is what RequireTLS returns; duringSwitch, when set, runs
	// inside it (with intake closed and require recorded).
	switchErr    error
	duringSwitch func()

	logMu sync.Mutex
	log   []string // the order things happened in
}

func (x *fixture) note(e string) {
	x.logMu.Lock()
	defer x.logMu.Unlock()
	x.log = append(x.log, e)
}

func (x *fixture) events() []string {
	x.logMu.Lock()
	defer x.logMu.Unlock()
	return append([]string(nil), x.log...)
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
	x := &fixture{settings: &memSettings{}, f: &facts{}, switched: make(chan struct{})}
	x.settings.onSet = func(k, v string) { x.note("persist " + v) }
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
			x.note("quiesce")
			return true, nil, nil
		},
		Reopen: func() { x.reopens.Add(1); x.quiesced.Store(false); x.note("reopen") },
		RequireTLS: func(context.Context) error {
			x.note("switch")
			if x.duringSwitch != nil {
				x.duringSwitch()
			}
			if x.switches.Add(1) == 1 {
				defer close(x.switched)
			}
			return x.switchErr
		},
		NoBus:          func(error) { x.noBus.Add(1) },
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

// aFleet is a StartFacts for a controlplane that serves TLS and has nodes
// enrolled, not all of them on TLS.
var aFleet = StartFacts{TLSAvailable: true, Enrolled: 2, AllReportedTLS: false}

func TestResolveStartMode(t *testing.T) {
	ctx := context.Background()
	s := &memSettings{}

	t.Setenv(EnvMode, "")
	// Nothing recorded and nodes enrolled: still offer. The offer → migrate
	// gate (the build is committed) is what stops a rollback stranding a node
	// that was already handed a pin, so an existing fleet keeps it.
	got := ResolveStartMode(ctx, s, aFleet)
	if got.Mode != ModeOffer || got.Pinned || got.Derived || got.Fault != "" {
		t.Fatalf("unset with a fleet: %+v, want plain offer", got)
	}
	_ = s.Set(ctx, SettingKey, "require")
	if got := ResolveStartMode(ctx, s, aFleet); got.Mode != ModeRequire || got.Pinned || got.Derived || got.Fault != "" {
		t.Fatalf("setting: %+v, want require", got)
	}
	t.Setenv(EnvMode, " Migrate ")
	if got := ResolveStartMode(ctx, s, aFleet); got.Mode != ModeMigrate || !got.Pinned || got.Fault != "" {
		t.Fatalf("env: %+v, want pinned migrate", got)
	}
}

// A fresh cluster — nothing recorded, no node enrolled — starts in require and
// records it, so the next start does not fall back to offer once its own agent
// has registered and "no node is enrolled" is no longer true.
func TestResolveStartMode_FreshClusterStartsInRequire(t *testing.T) {
	ctx := context.Background()
	t.Setenv(EnvMode, "")
	fresh := StartFacts{TLSAvailable: true, Enrolled: 0, AllReportedTLS: true}

	got := ResolveStartMode(ctx, &memSettings{}, fresh)
	if got.Mode != ModeRequire || got.Pinned || !got.Derived || got.Fault != "" || got.Why == "" {
		t.Fatalf("fresh: %+v, want a derived, unfaulted require with a reason", got)
	}
	// ...but not when this api cannot serve TLS at all: recording require
	// would name a rung the bus is not running.
	noTLS := StartFacts{TLSAvailable: false, Enrolled: 0, AllReportedTLS: true}
	if got := ResolveStartMode(ctx, &memSettings{}, noTLS); got.Mode != ModeMigrate || !got.Derived {
		t.Fatalf("fresh with no bus key: %+v, want a derived migrate", got)
	}
}

// A mode nobody can read never resolves to offer. It resolves UP: to require
// when every enrolled node is on TLS, and to migrate when one is not.
func TestResolveStartMode_UnreadableModeNeverResolvesToOffer(t *testing.T) {
	ctx := context.Background()
	allOnTLS := StartFacts{TLSAvailable: true, Enrolled: 3, AllReportedTLS: true}

	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) Settings
	}{
		{"a malformed setting", func(t *testing.T) Settings {
			s := &memSettings{}
			_ = s.Set(context.Background(), SettingKey, "bogus")
			t.Setenv(EnvMode, "")
			return s
		}},
		{"a malformed env mode", func(t *testing.T) Settings {
			t.Setenv(EnvMode, "yes")
			return &memSettings{}
		}},
		{"a settings store that will not read", func(t *testing.T) Settings {
			t.Setenv(EnvMode, "")
			return unreadableSettings{}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.setup(t)
			got := ResolveStartMode(ctx, s, allOnTLS)
			if got.Mode != ModeRequire || got.Pinned || !got.Derived || got.Fault == "" {
				t.Fatalf("all on TLS: %+v, want a faulted, derived require", got)
			}
			got = ResolveStartMode(ctx, s, aFleet)
			if got.Mode != ModeMigrate || !got.Derived || got.Fault == "" {
				t.Fatalf("not all on TLS: %+v, want a faulted, derived migrate", got)
			}
			if got.Mode == ModeOffer {
				t.Fatal("resolved to offer")
			}
		})
	}
}

type unreadableSettings struct{}

func (unreadableSettings) Get(context.Context, string) (string, error) {
	return "", errors.New("database is locked")
}
func (unreadableSettings) Set(context.Context, string, string) error {
	return errors.New("database is locked")
}

func TestFactsFromNodes(t *testing.T) {
	if f := FactsFromNodes(true, nil); f.Enrolled != 0 || !f.AllReportedTLS || !f.TLSAvailable {
		t.Fatalf("no nodes: %+v, want 0 enrolled and a vacuously true AllReportedTLS", f)
	}
	on := []*proto.Node{node("a", proto.StatusOnline, true), node("b", proto.StatusOffline, true)}
	if f := FactsFromNodes(true, on); f.Enrolled != 2 || !f.AllReportedTLS {
		t.Fatalf("all on TLS: %+v", f)
	}
	mixed := append(on, node("c", proto.StatusOnline, false), node("d", proto.StatusOnline, nil))
	if f := FactsFromNodes(true, mixed); f.Enrolled != 4 || f.AllReportedTLS {
		t.Fatalf("one plaintext and one silent: %+v, want AllReportedTLS false", f)
	}
}

// A start that had to ignore the mode it was given says so as a standing
// alert, whichever rung it derived.
func TestAlert_UnreadableStartMode(t *testing.T) {
	svc := NewService(Config{StartMode: ModeRequire, StartFault: "the recorded bus TLS mode could not be read: database is locked"})
	a := svc.Alert(time.Now())
	if a == nil || a.ID != StartFaultAlertID || a.Severity != proto.AlertWarn {
		t.Fatalf("alert = %+v, want a %s warn", a, StartFaultAlertID)
	}
	if !strings.Contains(a.Detail, "database is locked") || !strings.Contains(a.Detail, string(ModeRequire)) {
		t.Fatalf("detail = %q, want the fault and the mode it ran as", a.Detail)
	}
	if svc := NewService(Config{StartMode: ModeRequire}); svc.Alert(time.Now()) != nil {
		t.Fatalf("a clean start raised an alert")
	}
}

// offer → migrate happens on commit and on nothing else: every other fact
// true and the build uncommitted, the ladder does not move.
func TestLadder_NoMigrateWithoutCommit(t *testing.T) {
	x := newFixture(t, ModeOffer, false, nil)
	x.set(func(f *facts) { allReady(f); f.committed = false })
	x.evaluate()
	if x.svc.Mode() != ModeOffer || x.settings.mode() != "" || x.switches.Load() != 0 {
		t.Fatalf("moved without commit: mode=%s setting=%q switches=%d", x.svc.Mode(), x.settings.mode(), x.switches.Load())
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
			if x.svc.Mode() != ModeMigrate || x.settings.mode() == string(ModeRequire) || x.switches.Load() != 0 || x.quiesced.Load() {
				t.Fatalf("moved past a blocker: mode=%s setting=%q switches=%d quiesced=%t", x.svc.Mode(), x.settings.mode(), x.switches.Load(), x.quiesced.Load())
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

// All facts true: intake closes, require is persisted, the bus server is
// replaced, and only then does intake reopen — in exactly that order, once,
// however many events arrive after. The process is not asked to end.
func TestLadder_AllFactsSwitchToRequireInOrderOnce(t *testing.T) {
	x := newFixture(t, ModeMigrate, false, nil)
	x.set(allReady)
	x.duringSwitch = func() {
		if !x.quiesced.Load() {
			t.Error("the bus server was replaced with job intake open")
		}
		if got := x.settings.mode(); got != string(ModeRequire) {
			t.Errorf("the bus server was replaced with the setting at %q, want require recorded first", got)
		}
		if on, _ := x.svc.Switching(); !on {
			t.Error("Switching() = false during the replacement: the auth-callout hold would not apply")
		}
	}
	x.evaluate()
	if want := []string{"quiesce", "persist require", "switch", "reopen"}; !slices.Equal(x.events(), want) {
		t.Fatalf("order = %q, want %q", x.events(), want)
	}
	if x.settings.mode() != string(ModeRequire) || x.svc.Mode() != ModeRequire || x.quiesced.Load() {
		t.Fatalf("setting=%q mode=%s quiesced=%t, want require with intake open", x.settings.mode(), x.svc.Mode(), x.quiesced.Load())
	}
	for i := 0; i < 3; i++ {
		x.evaluate()
		x.svc.OnRegistered(context.Background(), node("n1", proto.StatusOnline, true))
		x.svc.NoteDisconnect(99)
		x.svc.Wait()
	}
	if got := x.switches.Load(); got != 1 {
		t.Fatalf("switches = %d, want exactly 1", got)
	}
	st, err := x.svc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Switching || st.PlaintextAllowed || st.SwitchFailed != "" || st.Next != "" {
		t.Fatalf("status = %+v, want require on a server refusing plaintext, nothing pending", st)
	}
	if on, _ := x.svc.Switching(); on || x.noBus.Load() != 0 {
		t.Fatalf("Switching=%t noBus=%d after a clean switch", on, x.noBus.Load())
	}
	if a := x.svc.Alert(time.Now()); a != nil {
		t.Fatalf("a clean switch raised %+v", a)
	}
}

// A job submitted while the bus server is being replaced is refused with the
// retryable error — the real job runner's intake, closed by the real
// QuiesceIfIdle — and the same submit succeeds once the switch is over.
func TestLadder_SubmitDuringTheSwitchIsRefusedThenAccepted(t *testing.T) {
	ctx := context.Background()
	store, err := jobs.OpenStore(ctx, filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	runner := jobs.NewRunner(store, startBus(t))
	ran := make(chan struct{})
	runner.Register(jobs.Workflow{Kind: "probe", Steps: []jobs.WorkflowStep{{Name: "noop", Do: func(*jobs.StepCtx) (json.RawMessage, error) {
		close(ran)
		return nil, nil
	}}}})

	x := newFixture(t, ModeMigrate, false, nil)
	x.set(allReady)
	x.svc.cfg.Quiesce = runner.QuiesceIfIdle
	x.svc.cfg.Reopen = runner.Reopen
	var during error
	x.duringSwitch = func() { _, during = runner.Submit(ctx, "probe", nil, "test") }
	x.evaluate()

	if !errors.Is(during, jobs.ErrQuiesced) {
		t.Fatalf("Submit during the switch = %v, want jobs.ErrQuiesced (retryable, nothing recorded)", during)
	}
	if n, _ := jobs.InFlight(ctx, store); len(n) != 0 {
		t.Fatalf("the refused submit left rows in the ledger: %q", n)
	}
	j, err := runner.Submit(ctx, "probe", nil, "test")
	if err != nil {
		t.Fatalf("Submit after the switch = %v, want accepted", err)
	}
	select {
	case <-ran:
	case <-time.After(10 * time.Second): // a deadline on the fact
		t.Fatalf("job %s accepted after the switch never ran", j.ID)
	}
	runner.Wait()
}

// The replacement server did not start and the bus came back as it was:
// migrate is recorded again, intake reopens, a standing warning is raised, and
// no event makes the api try again in this process.
func TestLadder_SwitchFallbackReopensRecordsMigrateAndWarns(t *testing.T) {
	x := newFixture(t, ModeMigrate, false, nil)
	x.set(allReady)
	x.switchErr = fmt.Errorf("%w: port in use", bus.ErrFellBack)
	x.evaluate()
	if want := []string{"quiesce", "persist require", "switch", "persist migrate", "reopen"}; !slices.Equal(x.events(), want) {
		t.Fatalf("order = %q, want %q", x.events(), want)
	}
	if x.settings.mode() != string(ModeMigrate) || x.svc.Mode() != ModeMigrate || x.quiesced.Load() || x.noBus.Load() != 0 {
		t.Fatalf("setting=%q mode=%s quiesced=%t noBus=%d, want migrate, intake open, the bus still there", x.settings.mode(), x.svc.Mode(), x.quiesced.Load(), x.noBus.Load())
	}
	a := x.svc.Alert(time.Now())
	if a == nil || a.ID != SwitchFailedAlertID || a.Severity != proto.AlertWarn || a.Source != proto.AlertSourceSecurity || !strings.Contains(a.Detail, "port in use") {
		t.Fatalf("Alert = %+v, want a %s security warning naming the cause", a, SwitchFailedAlertID)
	}
	st, err := x.svc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.PlaintextAllowed || st.Switching || !strings.Contains(st.SwitchFailed, "port in use") || len(st.Blockers) != 1 {
		t.Fatalf("status = %+v, want plaintext allowed, the failure named as the one blocker", st)
	}
	for i := 0; i < 3; i++ {
		x.svc.OnRegistered(context.Background(), node("n1", proto.StatusOnline, true))
		x.svc.NoteDisconnect(99)
		x.evaluate()
	}
	if got := x.switches.Load(); got != 1 {
		t.Fatalf("switches = %d after a fallback and more events, want 1 (no retry loop)", got)
	}
}

// No bus at all after the switch: the api is told (it ends the process as a
// bus that fails at boot does), and intake is not reopened onto no bus.
func TestLadder_NoBusAfterTheSwitchIsReported(t *testing.T) {
	x := newFixture(t, ModeMigrate, false, nil)
	x.set(allReady)
	x.switchErr = errors.New("bus: NO BUS: nothing starts")
	x.evaluate()
	if x.noBus.Load() != 1 || x.reopens.Load() != 0 || !x.quiesced.Load() {
		t.Fatalf("noBus=%d reopens=%d quiesced=%t, want NoBus once and intake still closed", x.noBus.Load(), x.reopens.Load(), x.quiesced.Load())
	}
	x.evaluate()
	if x.switches.Load() != 1 {
		t.Fatalf("switches = %d, want 1", x.switches.Load())
	}
}

// A process that started TLS-required never switches.
func TestLadder_RequireAtStartIsTerminal(t *testing.T) {
	x := newFixture(t, ModeRequire, false, nil)
	x.set(allReady)
	x.evaluate()
	if x.switches.Load() != 0 || x.quiesced.Load() {
		t.Fatalf("switched from require: switches=%d quiesced=%t", x.switches.Load(), x.quiesced.Load())
	}
}

// If require cannot be persisted the bus is not switched (the record would say
// migrate while the server refuses plaintext, and a restart would undo it),
// and job intake reopens.
func TestLadder_PersistFailureReopensIntakeAndDoesNotSwitch(t *testing.T) {
	x := newFixture(t, ModeMigrate, false, nil)
	x.set(allReady)
	x.settings.failSet = errors.New("disk full")
	x.evaluate()
	if x.switches.Load() != 0 || x.reopens.Load() != 1 || x.svc.Mode() != ModeMigrate {
		t.Fatalf("switches=%d reopens=%d mode=%s, want no switch, intake reopened, still migrate", x.switches.Load(), x.reopens.Load(), x.svc.Mode())
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
	if x.settings.mode() != string(ModeRequire) || x.switches.Load() != 1 {
		t.Fatalf("setting=%q switches=%d, want require after one evaluation", x.settings.mode(), x.switches.Load())
	}
}

// A pinned mode never moves, and a pinned mode below require is a standing
// warning; an unpinned ladder or a pinned require raises none.
func TestLadder_PinnedModeNeverMovesAndWarns(t *testing.T) {
	x := newFixture(t, ModeOffer, true, nil)
	x.set(allReady)
	x.evaluate()
	if x.svc.Mode() != ModeOffer || x.settings.mode() != "" || x.switches.Load() != 0 {
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
	if x.switches.Load() != 0 {
		t.Fatal("switched with a plaintext connection listed")
	}
	x.svc.NoteDisconnect(42)
	x.svc.Wait()
	if x.switches.Load() != 1 {
		t.Fatalf("switches = %d after the last plaintext connection's disconnect, want 1", x.switches.Load())
	}
	// A switch clears the noted ids: the new server numbers connections anew.
	x.svc.mu.Lock()
	noted := len(x.svc.closedCIDs)
	x.svc.mu.Unlock()
	if noted != 0 {
		t.Fatalf("closed ids kept across the switch: %d", noted)
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
	if x.switches.Load() != 0 {
		t.Fatal("switched with a job in flight")
	}

	x.set(func(f *facts) { f.inFlight = nil })
	ev, _ := json.Marshal(proto.JobEvent{Type: proto.JobSucceeded, JobID: "01J", Ts: time.Now().UTC()})
	if err := nc.Publish(proto.JobEventsSubject("01J"), ev); err != nil {
		t.Fatal(err)
	}
	select {
	case <-x.switched:
	case <-time.After(10 * time.Second): // deadline on the fact, not a sync sleep
		t.Fatalf("no switch after the job-end event (switches=%d)", x.switches.Load())
	}
	if x.switches.Load() != 1 {
		t.Fatalf("switches = %d after the job-end event, want 1", x.switches.Load())
	}
}

// Wait is "every evaluation and delivery started so far has finished", and it
// is called while events keep arriving — the functional test calls it with
// agents still registering. Kicks racing a Wait must be safe. (A sync.WaitGroup
// is not: an Add from zero concurrent with Wait is a data race, and the race
// detector caught exactly that, 1 run in 20, in TestFunctional_AutomaticLadder.)
func TestService_WaitWithConcurrentKicks(t *testing.T) {
	x := newFixture(t, ModeOffer, false, nil)
	x.set(func(f *facts) { f.committed = false })
	var kickers sync.WaitGroup
	for i := 0; i < 200; i++ {
		kickers.Add(1)
		go func() {
			defer kickers.Done()
			x.svc.Kick("concurrent")
			x.svc.OnRegistered(context.Background(), node("n1", proto.StatusOnline, true))
		}()
		x.svc.Wait()
	}
	kickers.Wait()
	x.svc.Wait()
}
