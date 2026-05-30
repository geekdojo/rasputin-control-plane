package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Status-transition thresholds. Tuned for a 10s heartbeat interval.
const (
	staleAfter   = 30 * time.Second
	offlineAfter = 2 * time.Minute
)

// Service subscribes to agent heartbeat and registration events, maintains
// the inventory ledger, and emits inventory change events when a node's
// status, role, or membership changes.
type Service struct {
	store *Store
	nc    *nats.Conn

	mu           sync.Mutex
	statusByNode map[string]proto.NodeStatus // last published status per node

	ctx    context.Context
	cancel context.CancelFunc
	subs   []*nats.Subscription
	wg     sync.WaitGroup
}

// NewService constructs an inventory Service bound to a store and bus.
func NewService(store *Store, nc *nats.Conn) *Service {
	return &Service{
		store:        store,
		nc:           nc,
		statusByNode: make(map[string]proto.NodeStatus),
	}
}

// Start subscribes to the bus and launches the transition-tick loop.
func (s *Service) Start(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)

	if err := s.seed(s.ctx); err != nil {
		return err
	}

	sub, err := s.nc.Subscribe(proto.AllHeartbeatsFilter, s.handleHeartbeat)
	if err != nil {
		return err
	}
	s.subs = append(s.subs, sub)

	sub, err = s.nc.Subscribe("rasputin.node.*.evt.registered", s.handleRegistered)
	if err != nil {
		return err
	}
	s.subs = append(s.subs, sub)

	s.wg.Add(1)
	go s.tickLoop()
	return nil
}

// Stop unsubscribes and waits for the tick loop to exit.
func (s *Service) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	for _, sub := range s.subs {
		_ = sub.Unsubscribe()
	}
	s.wg.Wait()
}

// Store exposes the underlying store for read-only HTTP handlers.
func (s *Service) Store() *Store { return s.store }

func (s *Service) seed(ctx context.Context) error {
	nodes, err := s.store.List(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range nodes {
		s.statusByNode[n.ID] = ComputeStatus(n.LastSeen)
	}
	return nil
}

func (s *Service) handleHeartbeat(m *nats.Msg) {
	nodeID, ok := nodeIDFromSubject(m.Subject)
	if !ok {
		return
	}
	var hb proto.HeartbeatEvt
	if err := json.Unmarshal(m.Data, &hb); err != nil {
		return
	}

	now := time.Now().UTC()
	if err := s.store.TouchLastSeen(s.ctx, nodeID, now); err != nil {
		// Unknown node: ignore the heartbeat. The agent will re-emit a
		// registration on next reconnect, which is what creates rows.
		if !errors.Is(err, sql.ErrNoRows) {
			log.Printf("inventory: touch %s: %v", nodeID, err)
		}
		return
	}

	s.mu.Lock()
	prev, known := s.statusByNode[nodeID]
	s.statusByNode[nodeID] = proto.StatusOnline
	s.mu.Unlock()

	if !known || prev != proto.StatusOnline {
		if n, _ := s.store.Get(s.ctx, nodeID); n != nil {
			n.Status = proto.StatusOnline
			s.emit(n, proto.InventoryOnline)
		}
	}
}

func (s *Service) handleRegistered(m *nats.Msg) {
	var ev proto.NodeRegisteredEvt
	if err := json.Unmarshal(m.Data, &ev); err != nil {
		return
	}
	if ev.NodeID == "" {
		return
	}
	if !proto.ValidRole(ev.Role) {
		log.Printf("inventory: reject %s: invalid role %q", ev.NodeID, ev.Role)
		return
	}
	now := time.Now().UTC()

	existing, err := s.store.Get(s.ctx, ev.NodeID)
	if err != nil {
		log.Printf("inventory: get %s: %v", ev.NodeID, err)
		return
	}

	if existing == nil {
		n := &proto.Node{
			ID:           ev.NodeID,
			Role:         ev.Role,
			Hostname:     ev.Hostname,
			AgentVersion: ev.AgentVersion,
			Capabilities: ev.Capabilities,
			Metadata:     ev.Metadata,
			FirstSeen:    now,
			LastSeen:     now,
			Status:       proto.StatusOnline,
		}
		if err := s.store.Insert(s.ctx, n); err != nil {
			log.Printf("inventory: insert %s: %v", ev.NodeID, err)
			return
		}
		s.mu.Lock()
		s.statusByNode[ev.NodeID] = proto.StatusOnline
		s.mu.Unlock()
		s.emit(n, proto.InventoryAdded)
		return
	}

	existing.Role = ev.Role
	existing.Hostname = ev.Hostname
	existing.AgentVersion = ev.AgentVersion
	existing.Capabilities = ev.Capabilities
	existing.Metadata = ev.Metadata
	existing.LastSeen = now
	if err := s.store.Update(s.ctx, existing); err != nil {
		log.Printf("inventory: update %s: %v", ev.NodeID, err)
		return
	}

	s.mu.Lock()
	prev := s.statusByNode[ev.NodeID]
	s.statusByNode[ev.NodeID] = proto.StatusOnline
	s.mu.Unlock()
	existing.Status = proto.StatusOnline

	if prev != proto.StatusOnline {
		s.emit(existing, proto.InventoryOnline)
	} else {
		s.emit(existing, proto.InventoryUpdated)
	}
}

func (s *Service) tickLoop() {
	defer s.wg.Done()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			s.scanForTransitions()
		}
	}
}

func (s *Service) scanForTransitions() {
	nodes, err := s.store.List(s.ctx)
	if err != nil {
		return
	}
	for _, n := range nodes {
		cur := ComputeStatus(n.LastSeen)
		s.mu.Lock()
		prev := s.statusByNode[n.ID]
		if cur != prev {
			s.statusByNode[n.ID] = cur
		}
		s.mu.Unlock()
		if cur == prev {
			continue
		}
		n.Status = cur
		switch cur {
		case proto.StatusOnline:
			s.emit(n, proto.InventoryOnline)
		case proto.StatusStale:
			s.emit(n, proto.InventoryStale)
		case proto.StatusOffline:
			s.emit(n, proto.InventoryOffline)
		}
	}
}

func (s *Service) emit(n *proto.Node, change proto.InventoryChangeType) {
	ev := proto.InventoryChangeEvt{
		Change: change,
		Node:   *n,
		Ts:     time.Now().UTC(),
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return
	}
	subj := proto.InventoryChangedSubject(n.ID, string(change))
	if err := s.nc.Publish(subj, payload); err != nil {
		log.Printf("inventory: publish %s: %v", subj, err)
	}
}

// ComputeStatus derives a node's status from its last heartbeat timestamp
// against staleAfter (30s) / offlineAfter (2m) thresholds. Exported so the
// HTTP handlers and the alerts aggregator can share the same logic — the
// nodes table doesn't persist status, every consumer has to compute it.
func ComputeStatus(lastSeen time.Time) proto.NodeStatus {
	gap := time.Since(lastSeen)
	switch {
	case gap < staleAfter:
		return proto.StatusOnline
	case gap < offlineAfter:
		return proto.StatusStale
	default:
		return proto.StatusOffline
	}
}

// nodeIDFromSubject extracts the id from "rasputin.node.<id>.<rest>".
func nodeIDFromSubject(subject string) (string, bool) {
	parts := strings.Split(subject, ".")
	if len(parts) < 4 || parts[0] != "rasputin" || parts[1] != "node" {
		return "", false
	}
	return parts[2], true
}

