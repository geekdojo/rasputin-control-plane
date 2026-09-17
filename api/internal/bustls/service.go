package bustls

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Mode is how the bus treats plaintext, and whether the api is handing out the
// pin. The api moves itself up the ladder; nobody calls anything (Bryce,
// 2026-09-16: "alpha users are not going to run Postman queries").
//
//	offer    TLS is served beside plaintext. Nodes that already carry a pin (a
//	         provisioned set, an Add-node seed) use TLS; nobody is told a pin.
//	migrate  As offer, and the api delivers the pin to every node that is not
//	         on TLS. Each node saves it and re-dials over TLS.
//	require  The server refuses plaintext.
//
// Transitions, each on a checkable fact and never on a clock:
//
//	offer → migrate    the controlplane's running build is COMMITTED on its A/B
//	                   slot (Config.Committed). A delivered pin cannot be taken
//	                   back over the bus, and an api rolled back to a pre-TLS
//	                   build would strand every pinned node, so delivery waits
//	                   until nothing automatic can roll this build back.
//	migrate → require  every enrolled node reports busTls=true, the server holds
//	                   no plaintext client connection (the controlplane's own
//	                   loopback agent included), and no job is in flight. Then
//	                   job intake closes, require is persisted, the embedded
//	                   bus server is replaced in-process by one that refuses
//	                   plaintext (Config.RequireTLS; nats-server cannot change
//	                   the setting on reload), and intake reopens once the
//	                   api's own bus connection is back. The api process and
//	                   its HTTP server stay up throughout.
//
// Nothing moves back down on its own. RASPUTIN_BUS_TLS pins a mode (the escape
// hatch for a controlplane with a node that cannot speak TLS); a pinned mode is
// never changed, and a pinned mode other than require raises a standing warning.
//
// Re-evaluation is event-driven: a node registering, a client connection
// closing, a job ending, and the service starting. Each evaluation's I/O is
// bounded by a timeout; nothing waits on a clock for a fact to change.
type Mode string

const (
	ModeOffer   Mode = "offer"
	ModeMigrate Mode = "migrate"
	ModeRequire Mode = "require"
)

// SettingKey is where the api records the rung it reached (the settings table,
// so an identity restore brings it back with everything else).
const SettingKey = "bus.tls_mode"

// EnvMode, when set, pins the mode and stops the automatic ladder.
const EnvMode = "RASPUTIN_BUS_TLS"

// ParseMode accepts the three names, case-insensitively. It returns the
// package constant, never the caller's string.
func ParseMode(s string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case ModeOffer:
		return ModeOffer, nil
	case ModeMigrate:
		return ModeMigrate, nil
	case ModeRequire:
		return ModeRequire, nil
	}
	return "", fmt.Errorf("bus TLS mode %q: want offer, migrate or require", s)
}

// AllowsPlaintext is the server option the mode maps to.
func (m Mode) AllowsPlaintext() bool { return m != ModeRequire }

// Settings is the slice of setup.Store the service needs.
type Settings interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string) error
}

// ResolveStartMode decides the mode for this process start: the env pin when
// set, else the recorded rung, else offer. A malformed value is an error the
// caller reports and survives — as offer, the rung that changes nothing.
func ResolveStartMode(ctx context.Context, settings Settings) (mode Mode, pinned bool, err error) {
	if v := strings.TrimSpace(os.Getenv(EnvMode)); v != "" {
		m, perr := ParseMode(v)
		if perr != nil {
			return ModeOffer, false, fmt.Errorf("%s: %w; running as %q", EnvMode, perr, ModeOffer)
		}
		return m, true, nil
	}
	if settings == nil {
		return ModeOffer, false, nil
	}
	v, gerr := settings.Get(ctx, SettingKey)
	if gerr != nil {
		return ModeOffer, false, fmt.Errorf("read %s: %w; running as %q", SettingKey, gerr, ModeOffer)
	}
	if strings.TrimSpace(v) == "" {
		return ModeOffer, false, nil
	}
	m, perr := ParseMode(v)
	if perr != nil {
		return ModeOffer, false, fmt.Errorf("setting %s: %w; running as %q", SettingKey, perr, ModeOffer)
	}
	return m, false, nil
}

// Config wires a Service.
type Config struct {
	Key      *Key
	Settings Settings
	// StartMode is the mode the embedded server was started in, and
	// StartModePinned whether it came from EnvMode (ResolveStartMode).
	StartMode       Mode
	StartModePinned bool
	// Nodes lists inventory — every enrolled node, online or not.
	Nodes func(ctx context.Context) ([]*proto.Node, error)
	// Plaintext lists open plaintext client connections (bus.Server).
	Plaintext func() ([]bus.PlaintextClient, error)
	// NC delivers the pin and carries the job events the service listens to.
	NC *nats.Conn
	// Committed reports whether the controlplane's running build is committed
	// (updater.SelfBuildCommitted), with the reason either way.
	Committed func(ctx context.Context) (bool, string, error)
	// InFlight lists jobs in flight, for the status page (jobs.InFlight).
	InFlight func(ctx context.Context) ([]string, error)
	// Quiesce closes job intake if and only if nothing is in flight
	// (jobs.Runner.QuiesceIfIdle); Reopen undoes it (jobs.Runner.Reopen).
	Quiesce func(ctx context.Context) (bool, []string, error)
	Reopen  func()
	// RequireTLS makes the running bus refuse plaintext without ending this
	// process (bus.Server.SetAllowNonTLS(ctx, false)). It returns nil once
	// the new server is up and the api's own bus connection is back on it; an
	// error wrapping bus.ErrFellBack when the new server did not start and
	// the bus came back as it was, still accepting plaintext; and any other
	// error when there is no working bus. Called at most once per process.
	RequireTLS func(ctx context.Context) error
	// NoBus is called when RequireTLS left the api without a working bus. The
	// api cannot run like that; the caller ends the process the way a bus
	// that fails to start at boot does. nil (tests) only logs and halts the
	// ladder.
	NoBus func(err error)
	// DeliverTimeout bounds one bus.pin request; EvalTimeout bounds one
	// evaluation's I/O; SwitchTimeout bounds RequireTLS (the old server's
	// shutdown, the new one's start and the api's in-process reconnect).
	// Defaults 10s, 30s and 60s.
	DeliverTimeout time.Duration
	EvalTimeout    time.Duration
	SwitchTimeout  time.Duration
	// OnEvaluated, when set, is called after every evaluation with the rung it
	// left the ladder on. A test seam: it makes "an evaluation ran and did not
	// move" something a test can wait for instead of sleeping.
	OnEvaluated func(mode Mode, err error)
}

// Service owns the ladder, the facts and pin delivery.
type Service struct {
	cfg Config

	mu   sync.Mutex
	mode Mode // the rung reached (what the setting now says)
	// plaintextAllowed is what the RUNNING bus server does.
	plaintextAllowed bool
	// switching is true from persisting require until the replaced bus is
	// up and job intake has reopened (or the switch failed).
	switching bool
	// switchFailed is why the switch to TLS-only did not happen; the ladder
	// does not try again in this process (see evaluate).
	switchFailed string
	stopped      bool
	pending      map[string]bool // node ids with a delivery in flight
	// closedCIDs are connections a disconnect advisory reported closed. The
	// advisory can precede the server dropping the connection from Connz, so
	// the listing is filtered through this set. Pruned to ids still listed.
	closedCIDs map[uint64]bool
	// evaluating / dirty coalesce kicks: one evaluation at a time, and a kick
	// during one makes it run once more.
	evaluating bool
	dirty      bool
	// active counts evaluation loops and deliveries running; idle (on mu) is
	// broadcast when it reaches zero. Not a sync.WaitGroup: events keep
	// starting work while Wait or Stop waits, and a WaitGroup's Add from zero
	// concurrent with its Wait is a data race.
	active int
	idle   *sync.Cond
	sub    *nats.Subscription
}

// NewService builds the service. It does no I/O; Start begins listening.
func NewService(cfg Config) *Service {
	if cfg.DeliverTimeout <= 0 {
		cfg.DeliverTimeout = 10 * time.Second
	}
	if cfg.EvalTimeout <= 0 {
		cfg.EvalTimeout = 30 * time.Second
	}
	if cfg.SwitchTimeout <= 0 {
		cfg.SwitchTimeout = 60 * time.Second
	}
	if cfg.StartMode == "" {
		cfg.StartMode = ModeOffer
	}
	s := &Service{cfg: cfg, mode: cfg.StartMode, plaintextAllowed: cfg.StartMode.AllowsPlaintext(), pending: map[string]bool{}, closedCIDs: map[uint64]bool{}}
	s.idle = sync.NewCond(&s.mu)
	return s
}

// Start subscribes to job events (a job ending can release both transitions)
// and runs the first evaluation. Node registrations and client disconnects
// arrive through OnRegistered and NoteDisconnect, which the caller wires.
func (s *Service) Start() error {
	if s.cfg.NC != nil {
		sub, err := s.cfg.NC.Subscribe(proto.JobEventsSubject("*"), func(m *nats.Msg) {
			var ev proto.JobEvent
			if json.Unmarshal(m.Data, &ev) != nil {
				return
			}
			if ev.Type == proto.JobSucceeded || ev.Type == proto.JobFailed {
				s.Kick("job " + ev.JobID + " " + string(ev.Type))
			}
		})
		if err != nil {
			return fmt.Errorf("bustls: subscribe job events: %w", err)
		}
		s.sub = sub
	}
	s.Kick("start")
	return nil
}

// Stop stops evaluating and waits for evaluations and deliveries in flight.
func (s *Service) Stop() {
	s.mu.Lock()
	s.stopped = true
	s.mu.Unlock()
	if s.sub != nil {
		_ = s.sub.Unsubscribe()
	}
	s.Wait()
}

// Wait blocks until no evaluation or delivery is running: every one started
// so far, and any they started in turn, has finished.
func (s *Service) Wait() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.active > 0 {
		s.idle.Wait()
	}
}

// finished marks one evaluation loop or delivery done. Called without mu.
func (s *Service) finished() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active--
	if s.active == 0 {
		s.idle.Broadcast()
	}
}

// Pin is the live pin.
func (s *Service) Pin() string { return s.cfg.Key.Pin() }

// Mode is the rung reached.
func (s *Service) Mode() Mode {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mode
}

// Switching reports whether the bus is being switched to TLS-only right now:
// require is recorded, and the replaced server is not up with job intake
// reopened yet. The auth-callout responder holds new connections while it is
// true (busauth.Responder.SetHold), so no node registers — and no registration
// hook submits a job — before intake reopens.
func (s *Service) Switching() (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.switching {
		return false, ""
	}
	return true, "the control plane is switching its bus to TLS-only; retry in a moment"
}

// NodeTLS is one inventory node's report.
type NodeTLS struct {
	ID     string           `json:"id"`
	Role   proto.NodeRole   `json:"role"`
	Status proto.NodeStatus `json:"status"`
	// BusTLS is what the node last reported at registration: true only for a
	// connection that was TLS with the pin verified. Reported tells "said
	// false" from "never said" (an agent that predates the field).
	BusTLS   bool `json:"busTls"`
	Reported bool `json:"reported"`
}

// Status is the whole picture GET /api/bus/tls serves.
type Status struct {
	Mode       Mode `json:"mode"`
	ModePinned bool `json:"modePinned"`
	// PlaintextAllowed is what the RUNNING server does. It differs from Mode
	// only while the bus is being switched (Switching).
	PlaintextAllowed bool `json:"plaintextAllowed"`
	// Switching is true while the embedded bus server is being replaced by
	// one that refuses plaintext: job intake is closed for that moment.
	Switching bool `json:"switching"`
	// SwitchFailed says why the last switch to TLS-only did not happen. The
	// bus runs as before, and the api tries again only after it restarts.
	SwitchFailed string `json:"switchFailed,omitempty"`
	// Pin is the value to seed as RASPUTIN_BUS_PIN. Public.
	Pin string `json:"pin"`
	// Next is the rung the api moves to once Blockers is empty; "" at require
	// or when the mode is pinned.
	Next Mode `json:"next,omitempty"`
	// Blockers is every fact holding Next back, in words. Empty with Next set
	// means the move is under way.
	Blockers []string `json:"blockers"`

	Committed            *bool                 `json:"controlplaneCommitted,omitempty"`
	CommittedDetail      string                `json:"controlplaneCommittedDetail,omitempty"`
	Nodes                []NodeTLS             `json:"nodes"`
	PlaintextConnections []bus.PlaintextClient `json:"plaintextConnections"`
	JobsInFlight         []string              `json:"jobsInFlight"`
}

// Status computes the picture now. It changes nothing.
func (s *Service) Status(ctx context.Context) (Status, error) {
	s.mu.Lock()
	mode, plaintext, switching, failed := s.mode, s.plaintextAllowed, s.switching, s.switchFailed
	s.mu.Unlock()
	st := Status{
		Mode:                 mode,
		ModePinned:           s.cfg.StartModePinned,
		PlaintextAllowed:     plaintext,
		Switching:            switching,
		SwitchFailed:         failed,
		Pin:                  s.Pin(),
		Blockers:             []string{},
		Nodes:                []NodeTLS{},
		PlaintextConnections: []bus.PlaintextClient{},
		JobsInFlight:         []string{},
	}
	nodes, err := s.cfg.Nodes(ctx)
	if err != nil {
		return st, fmt.Errorf("bustls: list inventory: %w", err)
	}
	for _, n := range nodes {
		on, reported := BusTLSOf(n)
		st.Nodes = append(st.Nodes, NodeTLS{ID: n.ID, Role: n.Role, Status: n.Status, BusTLS: on, Reported: reported})
	}
	sort.Slice(st.Nodes, func(i, j int) bool { return st.Nodes[i].ID < st.Nodes[j].ID })
	if switching {
		// The server is being replaced; there is no listing to read, and the
		// old server's connections are all closing.
		return st, nil
	}
	if st.PlaintextConnections, err = s.openPlaintext(); err != nil {
		return st, err
	}
	if s.cfg.InFlight != nil {
		if st.JobsInFlight, err = s.cfg.InFlight(ctx); err != nil {
			return st, fmt.Errorf("bustls: list jobs in flight: %w", err)
		}
	}
	if s.cfg.StartModePinned {
		if mode != ModeRequire {
			st.Blockers = append(st.Blockers, fmt.Sprintf("the mode is pinned to %q by %s on the controlplane; the api will not move it", mode, EnvMode))
		}
		return st, nil
	}
	switch mode {
	case ModeOffer:
		st.Next = ModeMigrate
		ok, why, cerr := s.committed(ctx)
		st.Committed, st.CommittedDetail = &ok, why
		if cerr != nil {
			st.CommittedDetail = cerr.Error()
		}
		if !ok {
			st.Blockers = append(st.Blockers, "the controlplane's build is not committed: "+st.CommittedDetail)
		}
	case ModeMigrate:
		st.Next = ModeRequire
		if failed != "" {
			st.Blockers = append(st.Blockers, "the last switch to TLS-only failed and the bus came back accepting plaintext ("+failed+"); the api tries again when it restarts")
		}
		st.Blockers = append(st.Blockers, requireBlockers(st.Nodes, st.PlaintextConnections, st.JobsInFlight)...)
	}
	return st, nil
}

func (s *Service) committed(ctx context.Context) (bool, string, error) {
	if s.cfg.Committed == nil {
		return false, "no commit check is wired", nil
	}
	ok, why, err := s.cfg.Committed(ctx)
	if err != nil {
		return false, "", err
	}
	return ok, why, nil
}

// openPlaintext is the server's plaintext listing minus connections a
// disconnect advisory already reported closed.
func (s *Service) openPlaintext() ([]bus.PlaintextClient, error) {
	listed, err := s.cfg.Plaintext()
	if err != nil {
		return nil, fmt.Errorf("bustls: list plaintext connections: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stillListed := map[uint64]bool{}
	out := []bus.PlaintextClient{}
	for _, c := range listed {
		stillListed[c.CID] = true
		if !s.closedCIDs[c.CID] {
			out = append(out, c)
		}
	}
	// A closed id the server no longer lists will never be listed again (ids
	// are not reused), so it is no longer needed.
	for cid := range s.closedCIDs {
		if !stillListed[cid] {
			delete(s.closedCIDs, cid)
		}
	}
	return out, nil
}

func requireBlockers(nodes []NodeTLS, plain []bus.PlaintextClient, jobs []string) []string {
	out := []string{}
	if len(nodes) == 0 {
		out = append(out, "no node is enrolled yet — the controlplane's own agent has not registered")
	}
	for _, n := range nodes {
		switch {
		case n.BusTLS:
		case !n.Reported:
			out = append(out, fmt.Sprintf("%s has not reported bus TLS (its agent predates it, or it has not registered since)", n.ID))
		default:
			out = append(out, fmt.Sprintf("%s last registered over plaintext", n.ID))
		}
	}
	for _, c := range plain {
		who := c.User
		if who == "" {
			who = c.Name
		}
		if who == "" {
			who = "an unnamed client"
		}
		out = append(out, fmt.Sprintf("%s is connected over plaintext from %s", who, c.IP))
	}
	for _, j := range jobs {
		out = append(out, "job in flight: "+j)
	}
	return out
}

// BusTLSOf reads a node's report out of its registration metadata.
func BusTLSOf(n *proto.Node) (tlsOn, reported bool) {
	if n == nil || n.Metadata == nil {
		return false, false
	}
	v, ok := n.Metadata[proto.MetadataBusTLS]
	if !ok {
		return false, false
	}
	b, isBool := v.(bool)
	return isBool && b, true
}

// Kick asks for an evaluation. Coalesced: at most one runs at a time, and kicks
// that arrive during one make it run once more. Never blocks.
func (s *Service) Kick(reason string) {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.dirty = true
	if s.evaluating {
		s.mu.Unlock()
		return
	}
	s.evaluating = true
	s.active++
	s.mu.Unlock()
	go func() {
		defer s.finished()
		for {
			s.mu.Lock()
			if !s.dirty || s.stopped {
				s.evaluating = false
				s.mu.Unlock()
				return
			}
			s.dirty = false
			s.mu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), s.cfg.EvalTimeout)
			err := s.evaluate(ctx)
			if err != nil {
				log.Printf("bustls: evaluate (after %q): %q", reason, err.Error())
			}
			cancel()
			if s.cfg.OnEvaluated != nil {
				s.cfg.OnEvaluated(s.Mode(), err)
			}
		}
	}()
}

// evaluate moves the ladder as far as the facts allow right now.
func (s *Service) evaluate(ctx context.Context) error {
	if s.cfg.StartModePinned {
		return nil
	}
	if s.Mode() == ModeOffer {
		ok, why, err := s.committed(ctx)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		if err := s.cfg.Settings.Set(ctx, SettingKey, string(ModeMigrate)); err != nil {
			return fmt.Errorf("persist %q: %w", ModeMigrate, err)
		}
		s.mu.Lock()
		s.mode = ModeMigrate
		s.mu.Unlock()
		log.Printf("bustls: offer → migrate: the controlplane's build is committed (%q); delivering the bus pin to nodes not on TLS", why)
		s.DeliverToAll(ctx)
	}
	s.mu.Lock()
	ready := s.mode == ModeMigrate && s.plaintextAllowed && s.switchFailed == "" && s.cfg.RequireTLS != nil
	s.mu.Unlock()
	if !ready {
		return nil
	}
	st, err := s.Status(ctx)
	if err != nil {
		return err
	}
	if len(st.Blockers) > 0 {
		return nil
	}
	// Close job intake, atomically with the check that nothing is in flight:
	// a job submitted from here on is refused with an error its caller can
	// retry, not started on a bus that is about to be replaced.
	if s.cfg.Quiesce != nil {
		ok, inFlight, qerr := s.cfg.Quiesce(ctx)
		if qerr != nil {
			return fmt.Errorf("quiesce jobs: %w", qerr)
		}
		if !ok {
			log.Printf("bustls: ready for require but jobs are in flight (%q); waiting for them to end", inFlight)
			return nil
		}
	}
	if err := s.cfg.Settings.Set(ctx, SettingKey, string(ModeRequire)); err != nil {
		s.reopen()
		return fmt.Errorf("persist %q (job intake reopened): %w", ModeRequire, err)
	}
	s.mu.Lock()
	s.mode = ModeRequire
	s.switching = true
	s.mu.Unlock()
	log.Printf("bustls: migrate → require: every node is on TLS with the pin verified, no plaintext connection is open and no job is in flight; replacing the bus server in-process so it refuses plaintext (the api keeps running)")
	return s.switchToRequire()
}

// switchToRequire replaces the running bus server with one that refuses
// plaintext, with job intake closed and require recorded, and then reopens
// intake. The order is the guarantee: intake reopens only once RequireTLS has
// returned, which is once the api's own bus connection — the one every job,
// subscription and the auth-callout responder use — is back on the server.
func (s *Service) switchToRequire() error {
	// Its own bound: the evaluation's context has already spent time on the
	// facts, and a replacement is a shutdown, a start and a reconnect.
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.SwitchTimeout)
	defer cancel()
	err := s.cfg.RequireTLS(ctx)
	switch {
	case err == nil:
		s.mu.Lock()
		// Connection ids restart on a new server; an id noted on the old one
		// must not hide a connection on this one.
		s.closedCIDs = map[uint64]bool{}
		s.mu.Unlock()
		s.finishSwitch(ModeRequire, false, "")
		log.Printf("bustls: require: the bus refuses plaintext; job intake reopened; nodes rejoin over TLS on their own reconnect")
		return nil
	case errors.Is(err, bus.ErrFellBack):
		// The bus is back as it was. Record migrate again, so what the
		// setting says is what the server does and a restart comes up in a
		// mode that is known to start. Do not try again in this process: the
		// fallback just dropped every node, their registrations would re-run
		// this evaluation, and a switch that fails again would drop them
		// again, over and over. A restart is the next attempt.
		why := err.Error()
		back, cancelBack := context.WithTimeout(context.Background(), s.cfg.EvalTimeout)
		perr := s.cfg.Settings.Set(back, SettingKey, string(ModeMigrate))
		cancelBack()
		if perr != nil {
			why += fmt.Sprintf(" (and recording %q again failed: %v; the next start comes up in require)", ModeMigrate, perr)
		}
		s.finishSwitch(ModeMigrate, true, why)
		return fmt.Errorf("the switch to TLS-only failed; the bus accepts plaintext as before and job intake reopened: %s", why)
	default:
		s.mu.Lock()
		s.switchFailed = err.Error()
		s.mu.Unlock()
		if s.cfg.NoBus != nil {
			s.cfg.NoBus(err)
		}
		return fmt.Errorf("the switch to TLS-only left no working bus: %w", err)
	}
}

// finishSwitch records the outcome of a switch and reopens job intake, in
// that order, and only then clears switching (which releases the
// auth-callout hold).
func (s *Service) finishSwitch(mode Mode, plaintext bool, failed string) {
	s.mu.Lock()
	s.mode, s.plaintextAllowed, s.switchFailed = mode, plaintext, failed
	s.mu.Unlock()
	s.reopen()
	s.mu.Lock()
	s.switching = false
	s.mu.Unlock()
}

func (s *Service) reopen() {
	if s.cfg.Reopen != nil {
		s.cfg.Reopen()
	}
}

// OnRegistered is the inventory hook: in migrate, a node that registered
// without TLS is handed the pin; any registration re-evaluates the ladder.
func (s *Service) OnRegistered(_ context.Context, n *proto.Node) {
	if n == nil {
		return
	}
	if s.Mode() == ModeMigrate {
		if on, _ := BusTLSOf(n); !on {
			s.deliverAsync(n.ID)
		}
	}
	s.Kick("registration of " + n.ID)
}

// NoteDisconnect is the disconnect-advisory hook (bus.Server.OnClientDisconnect).
func (s *Service) NoteDisconnect(cid uint64) {
	s.mu.Lock()
	s.closedCIDs[cid] = true
	s.mu.Unlock()
	s.Kick(fmt.Sprintf("connection %d closed", cid))
}

// DeliverToAll hands the pin to every ONLINE node not reporting TLS. Offline
// nodes get it when they register.
func (s *Service) DeliverToAll(ctx context.Context) {
	nodes, err := s.cfg.Nodes(ctx)
	if err != nil {
		log.Printf("bustls: deliver pin: list inventory: %q", err.Error())
		return
	}
	for _, n := range nodes {
		if n.Status != proto.StatusOnline {
			continue
		}
		if on, _ := BusTLSOf(n); on {
			continue
		}
		s.deliverAsync(n.ID)
	}
}

func (s *Service) deliverAsync(nodeID string) {
	s.mu.Lock()
	if s.pending[nodeID] || s.stopped {
		s.mu.Unlock()
		return
	}
	s.pending[nodeID] = true
	s.active++
	s.mu.Unlock()
	go func() {
		defer s.finished()
		defer func() {
			s.mu.Lock()
			delete(s.pending, nodeID)
			s.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), s.cfg.DeliverTimeout)
		defer cancel()
		ack, err := s.Deliver(ctx, nodeID)
		switch {
		case err != nil:
			log.Printf("bustls: deliver pin to %q: %q", nodeID, err.Error())
		case !ack.OK:
			log.Printf("bustls: %q refused the pin: %q", nodeID, ack.Detail)
		default:
			log.Printf("bustls: %q holds the pin (reconnecting=%t)", nodeID, ack.Reconnecting)
		}
	}()
}

// Deliver sends the pin to one node and returns its answer.
func (s *Service) Deliver(ctx context.Context, nodeID string) (*proto.BusPinAck, error) {
	if s.cfg.NC == nil {
		return nil, errors.New("bustls: no bus connection")
	}
	payload, err := json.Marshal(proto.BusPinCmd{Pin: s.Pin()})
	if err != nil {
		return nil, err
	}
	msg, err := s.cfg.NC.RequestWithContext(ctx, proto.NodeCmdSubject(nodeID, proto.BusPinVerb), payload)
	if err != nil {
		return nil, err
	}
	var ack proto.BusPinAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		return nil, fmt.Errorf("bustls: decode ack from %s: %w", nodeID, err)
	}
	return &ack, nil
}

// Alert is the standing security warning the ladder's state deserves, or nil:
// a pinned mode other than require keeps plaintext accepted on purpose, and
// that must not look healthy in the UI (the bus-auth-off precedent, #123); a
// switch to TLS-only that failed keeps it accepted by accident.
func (s *Service) Alert(now time.Time) *proto.Alert {
	s.mu.Lock()
	failed, plaintext, mode := s.switchFailed, s.plaintextAllowed, s.mode
	s.mu.Unlock()
	if failed != "" && plaintext && mode == ModeMigrate {
		return &proto.Alert{
			ID:       SwitchFailedAlertID,
			Severity: proto.AlertWarn,
			Source:   proto.AlertSourceSecurity,
			Title:    "Node bus still accepts plaintext (switch to TLS-only failed)",
			Detail: "Every node is on TLS, so the controlplane tried to restart its node bus to refuse unencrypted connections, but the new bus did not start: " + failed + ". " +
				"The bus came back as it was and nodes reconnected. The api tries again the next time it starts; its log names the error.",
			Since: now,
		}
	}
	if !s.cfg.StartModePinned || s.cfg.StartMode == ModeRequire {
		return nil
	}
	return &proto.Alert{
		ID:       "bus-tls-pinned",
		Severity: proto.AlertWarn,
		Source:   proto.AlertSourceSecurity,
		Title:    "Node bus accepts plaintext (bus TLS mode pinned)",
		Detail: fmt.Sprintf("%s=%s on the controlplane pins the bus TLS mode, so the bus keeps accepting unencrypted connections and will not move to TLS-only by itself. "+
			"Remove it from node.env once every node can use TLS.", EnvMode, s.cfg.StartMode),
		Since: now,
	}
}

// SwitchFailedAlertID is the alert raised when the switch to TLS-only failed
// and the bus fell back to accepting plaintext.
const SwitchFailedAlertID = "bus-tls-require-failed"

// UnavailableAlert is the standing warning for a controlplane whose bus key did
// not load: the bus is plaintext-only.
func UnavailableAlert(now time.Time) *proto.Alert {
	return &proto.Alert{
		ID:       "bus-tls-unavailable",
		Severity: proto.AlertWarn,
		Source:   proto.AlertSourceSecurity,
		Title:    "Node bus is not encrypted (bus key did not load)",
		Detail:   "The controlplane could not load /var/lib/rasputin/bus/bus.key, so the bus runs plaintext-only and nodes that pin its key cannot join. The api log names the error; restoring the identity backup puts the key back.",
		Since:    now,
	}
}
