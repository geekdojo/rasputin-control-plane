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

// Mode is how the bus treats plaintext, and whether the api is pushing the pin.
//
// The ladder is #448's migration order, one rung per step, each moved by an
// operator action and — for the last rung — only when a checkable fact says
// it is safe. Nothing here moves on a timer.
//
//	offer    TLS is served beside plaintext. Nodes that already carry a pin
//	         (a provisioned set, an Add-node seed) connect over TLS; nobody is
//	         told a pin. The default, and the only rung that changes nothing
//	         for a node — so upgrading the controlplane is not itself the
//	         migration.
//	migrate  As offer, and the api delivers the pin to every node that
//	         registers without reporting busTls=true (and to every online one
//	         the moment the mode is entered). Each node persists it and
//	         reconnects over TLS.
//	require  Plaintext is refused by the server. Entered only when every
//	         inventory node reports busTls=true and no plaintext connection is
//	         open. Needs an api restart, because nats-server cannot reload the
//	         setting.
//
// Why offer and migrate are separate rungs: a delivered pin cannot be taken
// back over the bus. A node that holds one refuses plaintext for good, so an
// api that is rolled back to a build with no TLS strands every pinned node.
// Delivery therefore starts when the operator says the controlplane build is
// the one they are keeping — not the moment it boots.
type Mode string

const (
	ModeOffer   Mode = "offer"
	ModeMigrate Mode = "migrate"
	ModeRequire Mode = "require"
)

// SettingKey is where the chosen mode is persisted (the settings table, so it
// is in the identity backup with everything else the operator decided).
const SettingKey = "bus.tls_mode"

// EnvMode, when set, pins the mode: the api reads it instead of the setting
// and refuses to change it. The escape hatch for a controlplane whose setting
// is wrong and whose UI is unreachable — `RASPUTIN_BUS_TLS=migrate` in
// node.env turns plaintext back on after a restart.
const EnvMode = "RASPUTIN_BUS_TLS"

// ParseMode accepts the three names, case-insensitively.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(strings.ToLower(strings.TrimSpace(s))); m {
	case ModeOffer, ModeMigrate, ModeRequire:
		return m, nil
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
// set, else the persisted setting, else offer. A malformed value is an error
// the caller reports and survives — as offer, the rung that changes nothing.
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
	// NC delivers the pin.
	NC *nats.Conn
	// Restart ends this process so the unit starts a new one with the new
	// server option. Called at most once, after the mode is persisted.
	Restart func()
	// DeliverTimeout bounds one bus.pin request. Default 10s.
	DeliverTimeout time.Duration
}

// Service owns the mode, the readiness fact and pin delivery.
type Service struct {
	cfg Config

	mu      sync.Mutex
	mode    Mode // the configured mode (what the setting now says)
	pending map[string]bool
	// restarting is set once Restart has been called.
	restarting bool
	wg         sync.WaitGroup
}

// NewService builds the service. It does no I/O.
func NewService(cfg Config) *Service {
	if cfg.DeliverTimeout <= 0 {
		cfg.DeliverTimeout = 10 * time.Second
	}
	if cfg.StartMode == "" {
		cfg.StartMode = ModeOffer
	}
	return &Service{cfg: cfg, mode: cfg.StartMode, pending: map[string]bool{}}
}

// Pin is the live pin.
func (s *Service) Pin() string { return s.cfg.Key.Pin() }

// NodeTLS is one inventory node's report.
type NodeTLS struct {
	ID     string           `json:"id"`
	Role   proto.NodeRole   `json:"role"`
	Status proto.NodeStatus `json:"status"`
	// BusTLS is what the node last reported at registration: true only for a
	// connection that was TLS with the pin verified. false covers "reported
	// plaintext" and "never reported" (an agent that predates the field) —
	// both block require; Reported tells them apart.
	BusTLS   bool `json:"busTls"`
	Reported bool `json:"reported"`
}

// Status is the whole picture GET /api/bus/tls serves.
type Status struct {
	// Mode is the configured mode; ModePinned says it came from EnvMode and
	// cannot be changed through the api.
	Mode       Mode `json:"mode"`
	ModePinned bool `json:"modePinned"`
	// PlaintextAllowed is what the RUNNING server does, which differs from
	// Mode only between a mode change that needs a restart and that restart.
	PlaintextAllowed bool `json:"plaintextAllowed"`
	RestartPending   bool `json:"restartPending"`
	// Pin is the value to seed as RASPUTIN_BUS_PIN. Public: it is a hash of a
	// public key.
	Pin string `json:"pin"`
	// Ready is the fact require waits for: at least one node, every inventory
	// node reporting busTls=true, and no plaintext connection open.
	Ready                bool                  `json:"ready"`
	Blockers             []string              `json:"blockers"`
	Nodes                []NodeTLS             `json:"nodes"`
	PlaintextConnections []bus.PlaintextClient `json:"plaintextConnections"`
}

// Status computes the picture from inventory and the server, now.
func (s *Service) Status(ctx context.Context) (Status, error) {
	s.mu.Lock()
	mode := s.mode
	s.mu.Unlock()
	st := Status{
		Mode:             mode,
		ModePinned:       s.cfg.StartModePinned,
		PlaintextAllowed: s.cfg.StartMode.AllowsPlaintext(),
		RestartPending:   mode.AllowsPlaintext() != s.cfg.StartMode.AllowsPlaintext(),
		Pin:              s.Pin(),
		Blockers:         []string{},
		Nodes:            []NodeTLS{},
	}
	nodes, err := s.cfg.Nodes(ctx)
	if err != nil {
		return st, fmt.Errorf("bustls: list inventory: %w", err)
	}
	for _, n := range nodes {
		tlsOn, reported := BusTLSOf(n)
		st.Nodes = append(st.Nodes, NodeTLS{ID: n.ID, Role: n.Role, Status: n.Status, BusTLS: tlsOn, Reported: reported})
	}
	sort.Slice(st.Nodes, func(i, j int) bool { return st.Nodes[i].ID < st.Nodes[j].ID })
	plain, err := s.cfg.Plaintext()
	if err != nil {
		return st, fmt.Errorf("bustls: list plaintext connections: %w", err)
	}
	st.PlaintextConnections = plain
	st.Blockers = blockers(st.Nodes, plain)
	st.Ready = len(st.Blockers) == 0
	return st, nil
}

func blockers(nodes []NodeTLS, plain []bus.PlaintextClient) []string {
	out := []string{}
	if len(nodes) == 0 {
		out = append(out, "no node is enrolled — a bus with nobody on it proves nothing about the nodes that will join it")
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

// ErrModePinned: the mode comes from EnvMode.
var ErrModePinned = errors.New("the bus TLS mode is pinned by " + EnvMode + " on the controlplane; change it there")

// NotReadyError is require refused, with the reasons.
type NotReadyError struct{ Blockers []string }

func (e *NotReadyError) Error() string {
	return "plaintext cannot be turned off yet: " + strings.Join(e.Blockers, "; ")
}

// SetMode moves the ladder.
//
// require is refused unless Status says Ready at the moment of the call —
// the checkable fact, re-derived here rather than trusted from an earlier
// read. Leaving require (back to migrate or offer) is never refused: it is
// the recovery path for a node that cannot speak TLS.
//
// A change that flips whether plaintext is allowed persists the mode and then
// restarts the api, because nats-server cannot reload that option. The restart
// is the same one a prepared restore takes: every job in flight ends the way
// any api restart ends it. Entering migrate delivers the pin to every online
// node that is not already on TLS.
func (s *Service) SetMode(ctx context.Context, m Mode) (Status, error) {
	if s.cfg.StartModePinned {
		st, _ := s.Status(ctx)
		return st, ErrModePinned
	}
	if m == ModeRequire {
		st, err := s.Status(ctx)
		if err != nil {
			return st, err
		}
		if !st.Ready {
			return st, &NotReadyError{Blockers: st.Blockers}
		}
	}
	if err := s.cfg.Settings.Set(ctx, SettingKey, string(m)); err != nil {
		return Status{}, fmt.Errorf("bustls: persist mode: %w", err)
	}
	s.mu.Lock()
	prev := s.mode
	s.mode = m
	restart := m.AllowsPlaintext() != s.cfg.StartMode.AllowsPlaintext() && !s.restarting
	if restart {
		s.restarting = true
	}
	s.mu.Unlock()
	log.Printf("bustls: mode %s → %s", prev, m)

	if m == ModeMigrate && prev != ModeMigrate {
		s.DeliverToAll(ctx)
	}
	st, err := s.Status(ctx)
	if restart && s.cfg.Restart != nil {
		log.Printf("bustls: plaintext is now %s by the configured mode and nats-server cannot reload that — restarting the api", allowWord(m.AllowsPlaintext()))
		s.cfg.Restart()
	}
	return st, err
}

func allowWord(b bool) string {
	if b {
		return "allowed"
	}
	return "refused"
}

// OnRegistered is the inventory hook: in migrate, a node that just registered
// without TLS is handed the pin. Registration is the fact "this node is here
// and reachable now", so delivery follows it instead of a retry timer. Never
// blocks — delivery runs on its own goroutine, one at a time per node.
func (s *Service) OnRegistered(_ context.Context, n *proto.Node) {
	s.mu.Lock()
	mode := s.mode
	s.mu.Unlock()
	if mode != ModeMigrate || n == nil {
		return
	}
	if on, _ := BusTLSOf(n); on {
		return
	}
	s.deliverAsync(n.ID)
}

// DeliverToAll hands the pin to every ONLINE node not reporting TLS. Offline
// nodes get it when they register (OnRegistered).
func (s *Service) DeliverToAll(ctx context.Context) {
	nodes, err := s.cfg.Nodes(ctx)
	if err != nil {
		log.Printf("bustls: deliver pin: list inventory: %v", err)
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
	if s.pending[nodeID] {
		s.mu.Unlock()
		return
	}
	s.pending[nodeID] = true
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
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
			log.Printf("bustls: deliver pin to %s: %v", nodeID, err)
		case !ack.OK:
			log.Printf("bustls: %s refused the pin: %s", nodeID, ack.Detail)
		default:
			log.Printf("bustls: %s holds the pin (reconnecting=%t)", nodeID, ack.Reconnecting)
		}
	}()
}

// Wait blocks until every delivery started so far has finished. For tests and
// shutdown.
func (s *Service) Wait() { s.wg.Wait() }

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
