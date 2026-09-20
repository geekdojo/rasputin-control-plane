package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/busident"
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

	// onNodeAdded, if set, is invoked AFTER a brand-new node row is inserted
	// (the existing==nil first-registration path only). It must not block
	// registration: handleRegistered logs-and-swallows any error. Wired in
	// main.go to avoid an inventory→firewall import cycle — mirrors the
	// auth.Service.SetLoginHook → mesh.EnsureUser pattern.
	onNodeAdded func(ctx context.Context, n *proto.Node)

	// onRegistered, if set, is invoked after EVERY successful registration —
	// the first one and every reconnect alike. See SetOnRegistered.
	onRegistered func(ctx context.Context, n *proto.Node)

	// onNodeKeyChanged, if set, is invoked when an accepted registration
	// REPLACED a key this node had already registered. See
	// SetOnNodeKeyChanged.
	onNodeKeyChanged func(ctx context.Context, change NodeKeyChange)

	// selfNodeID / selfLANIP: the node this api runs on, and its LAN address as
	// the api itself knows it. See SetSelfLANIP. selfMu serializes that node's
	// registration writes with RefreshSelfLANIP, so a registration that read the
	// old address cannot land after the refresh that replaced it.
	selfNodeID string
	selfLANIP  func() string
	selfMu     sync.Mutex

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

// SetOnNodeAdded registers a callback fired exactly on a node's FIRST
// registration (the insert path), after the InventoryAdded event is emitted.
// Reconnects re-run handleRegistered but hit the update path, so they do not
// fire this. The hook must be safe to fail: handleRegistered logs-and-swallows
// errors and never lets a hook block registration. Set before Start.
func (s *Service) SetOnNodeAdded(fn func(ctx context.Context, n *proto.Node)) {
	s.onNodeAdded = fn
}

// SetOnRegistered registers a callback fired after every successful
// registration, first or repeat, once the row is written and the change event
// emitted. An agent registers on every bus (re)connect, so this is the fact
// "this node is back and reachable now" — the trigger for work that could not
// reach it while it was away, instead of retrying that work on a timer. Same
// contract as SetOnNodeAdded: it must not block, and it runs on the bus
// callback goroutine. Set before Start.
func (s *Service) SetOnRegistered(fn func(ctx context.Context, n *proto.Node)) {
	s.onRegistered = fn
}

// SetOnNodeKeyChanged registers the audit-and-alert callback for a node whose
// registered key was REPLACED — a purpose that already had a hash now has a
// different one. A first registration does not fire it: that is a node
// acquiring an identity, not one changing it.
//
// The change means the node was reflashed (its keys live where its join token
// lives and survive a sysupgrade) or somebody with its token registered a key
// of their own. The api cannot tell those apart, which is precisely why it is
// surfaced rather than decided. Same contract as SetOnRegistered: it must not
// block, and it runs on the bus callback goroutine. Set before Start.
func (s *Service) SetOnNodeKeyChanged(fn func(ctx context.Context, change NodeKeyChange)) {
	s.onNodeKeyChanged = fn
}

// recordNodeKeys applies a registration's reported node keys
// (geekdojo/geekdojo-brain#514). It is the whole accept rule in one place:
//
//   - Nothing reported: nothing happens. That is an agent that predates the
//     keys, and a node whose bus connection is not pinned — which reports
//     nothing by design. Neither is a failure, and neither retires a key the
//     node registered earlier.
//   - Reported over an unpinned connection: REFUSED and logged. The node is
//     not rejected — its registration stands, it simply keeps whatever keys
//     were already recorded and stays on the legacy path.
//   - A malformed report: refused whole, for the same reason.
//   - Otherwise recorded, and a replacement is audited here and handed to
//     onNodeKeyChanged, which raises the alert.
//
// It never fails a registration: a node the api cannot record keys for is
// still a node in inventory, and refusing it would take it off the bus over a
// change to a credential it does not need to be there.
func (s *Service) recordNodeKeys(nodeID string, metadata map[string]any) {
	keys, ok, err := proto.DecodeNodeKeys(metadata)
	if err != nil {
		log.Printf("inventory: WARN %s reported unusable node keys, ignoring the whole report (its recorded keys are unchanged): %v", nodeID, err)
		return
	}
	if !ok {
		return
	}
	if !proto.NodeKeysAcceptable(metadata) {
		// A key is taken only where the node has proven which control plane
		// it is talking to. An agent of this release does not send one on an
		// unpinned link, so reaching here means an older or other client.
		log.Printf("inventory: WARN refusing node keys from %s: it did not register over a pinned TLS bus connection (%s=true). "+
			"Deliver the bus pin to this node, or reseed it, and the keys will be accepted on its next registration.",
			nodeID, proto.MetadataBusTLS)
		return
	}
	change, err := s.store.SetNodeKeys(s.ctx, nodeID, keys)
	if err != nil {
		log.Printf("inventory: WARN could not record node keys for %s (its recorded keys are unchanged): %v", nodeID, err)
		return
	}
	if !change.Changed() {
		return
	}
	if len(change.Replaced) == 0 {
		log.Printf("inventory: %s registered node key(s) %s", nodeID, change.Current)
		return
	}
	// The audit record of a key change: which node, which purposes, what it
	// was and what it is now. Hashes are public values, so the whole thing
	// can go in the log an operator reads.
	for _, p := range change.Replaced {
		log.Printf("inventory: WARN node key CHANGED for %s: purpose %q was %s, now %s. "+
			"Expected after a reflash; if this node was not reflashed, revoke its join token and investigate.",
			nodeID, p, change.Previous[p], change.Current[p])
	}
	if s.onNodeKeyChanged != nil {
		s.onNodeKeyChanged(s.ctx, change)
	}
}

// SetSelfLANIP makes the api authoritative for its own node's LAN address.
// Set before Start.
//
// Every other node's address is what its agent reports on registration, and
// that stays true. The control plane's own row is different because the api is
// on the same host and follows the address from kernel events (package
// lanaddr), while the co-located agent measures it with a default-route lookup
// and only on a bus (re)connect. That agent connects over the local host, so a
// new lease never makes it reconnect, and with only the 192.168.1.2 fallback —
// which has no gateway — it reports no address at all. /api/nodes therefore
// kept showing the address from API start, both while the node was on .2 and
// after it moved to a new lease (geekdojo/geekdojo-brain#431).
//
// fn returns the current address, or "" when the node has none. A registration
// for nodeID takes fn's address in place of the agent's whenever fn has one.
func (s *Service) SetSelfLANIP(nodeID string, fn func() string) {
	s.selfNodeID = nodeID
	s.selfLANIP = fn
}

// RefreshSelfLANIP writes the api's current address into its own node's row and
// emits InventoryUpdated when that changed it. Call it when the address changes.
// "" is written too: a control plane that holds no usable LAN address should
// not go on advertising the last one it had. A node with no row yet (its agent
// has not registered) is left alone; the registration will carry the address.
func (s *Service) RefreshSelfLANIP(ctx context.Context) error {
	if s.selfLANIP == nil || s.selfNodeID == "" {
		return nil
	}
	s.selfMu.Lock()
	defer s.selfMu.Unlock()
	changed, err := s.store.SetLANIP(ctx, s.selfNodeID, s.selfLANIP())
	if err != nil || !changed {
		return err
	}
	n, err := s.store.Get(ctx, s.selfNodeID)
	if err != nil || n == nil {
		return err
	}
	s.mu.Lock()
	if st, ok := s.statusByNode[n.ID]; ok {
		n.Status = st
	}
	s.mu.Unlock()
	s.emit(n, proto.InventoryUpdated)
	return nil
}

// Remove deletes a node from inventory, clears its in-memory status entry,
// and emits an InventoryRemoved change event carrying the last known Node
// payload. Returns sql.ErrNoRows if the id is unknown.
//
// No blocklist: if the agent later re-registers under the same id,
// handleRegistered will recreate the row. That's intentional for v1 —
// removal is for nodes that are permanently gone (dead hardware), not for
// preventing a return.
func (s *Service) Remove(ctx context.Context, id string) error {
	n, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}
	if n == nil {
		return sql.ErrNoRows
	}
	if err := s.store.Delete(ctx, id); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.statusByNode, id)
	s.mu.Unlock()
	s.emit(n, proto.InventoryRemoved)
	return nil
}

func (s *Service) seed(ctx context.Context) error {
	nodes, err := s.store.List(ctx)
	if err != nil {
		return err
	}
	s.store.Presence(ctx, nodes)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range nodes {
		s.statusByNode[n.ID] = n.Status
	}
	return nil
}

func (s *Service) handleHeartbeat(m *nats.Msg) {
	nodeID, ok := busident.NodeIDFromSubject(m.Subject)
	if !ok {
		return
	}
	var hb proto.HeartbeatEvt
	if err := json.Unmarshal(m.Data, &hb); err != nil {
		return
	}

	// Membership and liveness come from the registry, in memory: a heartbeat
	// from a node the api does not admit — never registered, removed, or its
	// last join token revoked — is dropped, and an accepted one records the
	// node's last-seen in the registry. The heartbeat path reads and writes
	// no database (geekdojo-brain#585). The agent of a dropped node re-emits
	// a registration on its next reconnect, which is what creates rows.
	now := time.Now().UTC()
	if !s.store.Registry().Touch(nodeID, now) {
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
	// The node id comes from the subject, which the bus scopes to the
	// publisher's credential; a payload naming a different node is dropped.
	ev, err := busident.DecodeRegistered(m.Subject, m.Data)
	if err != nil {
		log.Printf("inventory: drop registration on %q: %v", m.Subject, err)
		return
	}
	if !proto.ValidRole(ev.Role) {
		log.Printf("inventory: reject %s: invalid role %q", ev.NodeID, ev.Role)
		return
	}
	if s.selfLANIP != nil && ev.NodeID == s.selfNodeID {
		s.selfMu.Lock()
		defer s.selfMu.Unlock()
		if ip := s.selfLANIP(); ip != "" {
			ev.LANIP = ip
		}
	}
	now := time.Now().UTC()

	// Membership, role and the cluster-size cap are decided from the registry,
	// in memory — the api's one node list (geekdojo-brain#585). The database
	// is read only to hydrate the row a re-registration updates, below.
	reg := s.store.Registry()
	entry, known := reg.Lookup(ev.NodeID)
	if known && entry.Member && entry.Role != ev.Role {
		// A node cannot change roles once enrolled: changing role means
		// remove, reflash, re-add. A re-registration presenting a different
		// role is rejected outright and the row is left exactly as it was —
		// no field updates, no re-confirmed image version, no last-seen bump.
		// Removal deletes the row, so a re-added node takes the insert path
		// with whatever role it presents.
		log.Printf("inventory: WARN reject registration from %s: node is enrolled as role %q but presented role %q; "+
			"a node cannot change roles once enrolled (remove it, reflash, and re-add it)",
			ev.NodeID, entry.Role, ev.Role)
		return
	}

	var existing *proto.Node
	if known && entry.Member {
		var err error
		existing, err = s.store.Get(s.ctx, ev.NodeID)
		if err != nil {
			log.Printf("inventory: get %s: %v", ev.NodeID, err)
			return
		}
		// The registry says member and the row is gone: the row is the record,
		// so take the insert path and let it be rebuilt.
	}

	if existing == nil {
		// Cluster-size cap: never insert a row past proto.MaxClusterNodes.
		// This is the backstop for enrollment paths that don't pass through
		// a mint on this api — a preseeded matched set, whose hashes are
		// loaded straight into the token store, and the controlplane's own
		// agent, whose token the api mints at start rather than through
		// POST /api/bus/tokens (geekdojo-brain#140).
		// Re-registrations of known nodes take the update path below and are
		// never affected. Bench-verified 2026-07-15 that without this, a 25th
		// node enrolls straight into inventory.
		if count := reg.MemberCount(); count >= proto.MaxClusterNodes {
			log.Printf("inventory: reject %s: cluster is at the %d-node cap", ev.NodeID, proto.MaxClusterNodes)
			return
		}
		n := &proto.Node{
			ID:           ev.NodeID,
			Role:         ev.Role,
			Hostname:     ev.Hostname,
			AgentVersion: ev.AgentVersion,
			ImageVersion: ev.ImageVersion,
			// A registration IS a confirmation: the agent read this value off
			// the rootfs it is currently running, and it is alive enough to
			// say so. ADR-0005 Decision 4.
			ImageVersionConfirmedAt: &now,
			Architecture:            ev.Architecture,
			LANIP:                   ev.LANIP,
			Capabilities:            ev.Capabilities,
			Metadata:                ev.Metadata,
			Storage:                 ev.Storage,
			FirstSeen:               now,
			LastSeen:                now,
			Status:                  proto.StatusOnline,
		}
		if err := s.store.Insert(s.ctx, n); err != nil {
			log.Printf("inventory: insert %s: %v", ev.NodeID, err)
			return
		}
		s.mu.Lock()
		s.statusByNode[ev.NodeID] = proto.StatusOnline
		s.mu.Unlock()
		s.emit(n, proto.InventoryAdded)
		// After the row exists: the registry entry the keys hang off is
		// created by Insert, and a key recorded for a node with no row
		// would be a key nothing can ever admit.
		s.recordNodeKeys(ev.NodeID, ev.Metadata)
		if s.onNodeAdded != nil {
			// First-registration hook (e.g. firewall baseline seeding). Run
			// synchronously but never let it break registration — the hook is
			// responsible for its own error handling; we just guard the call.
			s.onNodeAdded(s.ctx, n)
		}
		if s.onRegistered != nil {
			s.onRegistered(s.ctx, n)
		}
		return
	}

	existing.Hostname = ev.Hostname
	existing.AgentVersion = ev.AgentVersion
	existing.ImageVersion = ev.ImageVersion
	// Re-confirmed on every re-registration, which is what makes an
	// unconfirmed row self-healing: any node that comes back clears its own
	// doubt, and the ones that never do are exactly the ones whose version
	// should stop reading as agreed (ADR-0005 Decision 4).
	existing.ImageVersionConfirmedAt = &now
	// Only overwrite arch when reported — a pre-arch agent reconnecting (arch="")
	// must not wipe an arch we already learned.
	if ev.Architecture != "" {
		existing.Architecture = ev.Architecture
	}
	// Same guard for storage: a pre-storage agent reports nil.
	if ev.Storage != nil {
		existing.Storage = ev.Storage
	}
	// LANIP changes on most reboots (no DHCP MAC reservations), so a new value
	// SHOULD overwrite — but a pre-LANIP agent reporting "" must not wipe a
	// learned IP. A changed IP rides out on the InventoryUpdated/Online emit
	// below (the full Node is included), which is the reconcile trigger the CP
	// nameserver's live read and Slice 2c's reconnect job both hang off.
	if ev.LANIP != "" {
		existing.LANIP = ev.LANIP
	}
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
	s.recordNodeKeys(ev.NodeID, ev.Metadata)
	if s.onRegistered != nil {
		s.onRegistered(s.ctx, existing)
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
	// One mesh read per scan, not per node: the derived status (presence.go)
	// is what the ws payload carries, so a node that lapses while its mesh
	// device is online transitions to off-bus, not to a flat offline that the
	// next poll would silently correct.
	s.store.Presence(s.ctx, nodes)
	for _, n := range nodes {
		cur := n.Status
		s.mu.Lock()
		prev := s.statusByNode[n.ID]
		if cur != prev {
			s.statusByNode[n.ID] = cur
		}
		s.mu.Unlock()
		if cur == prev {
			continue
		}
		switch cur {
		case proto.StatusOnline:
			s.emit(n, proto.InventoryOnline)
		case proto.StatusStale:
			s.emit(n, proto.InventoryStale)
		case proto.StatusOffline:
			s.emit(n, proto.InventoryOffline)
		case proto.StatusOffBus:
			s.emit(n, proto.InventoryOffBus)
		}
	}
}

func (s *Service) emit(n *proto.Node, change proto.InventoryChangeType) {
	// The UI replaces its copy of the node with this payload wholesale, so it
	// carries membership too — otherwise every transition would blank the
	// MESH row until the next poll. Status is left as the caller set it: a
	// heartbeat or registration IS online, whatever the mesh says.
	if n.Mesh == nil {
		if byNode := s.store.mesh(s.ctx); byNode != nil {
			if m, ok := byNode[n.ID]; ok {
				n.Mesh = m
			} else {
				n.Mesh = &proto.MeshMembership{State: proto.MeshAbsent}
			}
		}
	}
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

// ComputeStatus derives a node's HEARTBEAT status from its last heartbeat
// timestamp against staleAfter (30s) / offlineAfter (2m) thresholds. Exported
// so every consumer shares the thresholds — the nodes table doesn't persist
// status. It never returns StatusOffBus: that needs the mesh side of the join,
// which is DeriveStatus (presence.go). Gating on "== StatusOnline" against
// either function means the same thing.
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
