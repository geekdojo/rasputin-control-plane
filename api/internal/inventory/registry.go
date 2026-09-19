package inventory

import (
	"context"
	"fmt"
	"sync"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Registry is the api's ONE in-memory node list: every fact a node-facing
// authorization decision reads, per node, in one entry. The collector
// ingress's TLS handshake reads it and nothing else, so no connection or
// request does a database lookup to decide whether a node may connect.
//
// It lives in inventory because inventory owns the node of record: the nodes
// table, registration and removal all happen here, and the node keys Step 6
// adds are reported in registration metadata and stored on the node row, so
// they land in this same entry. Token liveness is owned by the token store
// (busauth), which sits below this package; it pushes that fact in through
// busauth.LivenessSink, which Registry implements.
//
// Loaded once at start — membership by OpenStore from the nodes table, token
// liveness by busauth.Store.SetLivenessSink from the token table — and then
// changed only by the events that change it: registration and removal
// (Store.Insert / Store.Delete), and every mint, preload, adoption, revoke and
// tombstone re-apply (pushed by busauth). No timer re-reads it.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]*RegistryEntry
	hooks   []func(nodeID string)
}

// RegistryEntry is what the api holds about one node.
type RegistryEntry struct {
	// Member: the node has a row in inventory (it registered and was not
	// removed).
	Member bool
	// Role is the role it registered as; empty while it is not a member.
	Role proto.NodeRole
	// TokenLive: it holds a join token the bus would admit it with
	// (unrevoked, bound, naming a valid role).
	TokenLive bool
	// Step 6 adds the node's registered key SPKIs here.
}

// admitted is the one rule node-facing admission applies.
func (e *RegistryEntry) admitted() bool { return e != nil && e.Member && e.TokenLive }

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{entries: map[string]*RegistryEntry{}}
}

// Admitted reports whether nodeID is a current member holding a live token.
// Memory only.
func (r *Registry) Admitted(nodeID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.entries[nodeID].admitted()
}

// Lookup returns a copy of nodeID's entry, and whether there is one.
func (r *Registry) Lookup(nodeID string) (RegistryEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[nodeID]
	if !ok {
		return RegistryEntry{}, false
	}
	return *e, true
}

// OnNodeExcluded registers fn to run, outside the registry's lock, each time a
// node stops being admitted: it was removed from inventory, or its last live
// token was revoked. The collector ingress closes the node's connections.
func (r *Registry) OnNodeExcluded(fn func(nodeID string)) {
	r.mu.Lock()
	r.hooks = append(r.hooks, fn)
	r.mu.Unlock()
}

// update applies change to the entries of the nodes ids names — read under
// the lock, so a whole-set change sees every entry — and fires the exclusion
// hooks for every node that went from admitted to not.
func (r *Registry) update(ids func(entries map[string]*RegistryEntry) []string, change func(id string, e *RegistryEntry)) {
	var excluded []string
	r.mu.Lock()
	for _, id := range ids(r.entries) {
		e := r.entries[id]
		if e == nil {
			e = &RegistryEntry{}
			r.entries[id] = e
		}
		was := e.admitted()
		change(id, e)
		if was && !e.admitted() {
			excluded = append(excluded, id)
		}
		if !e.Member && !e.TokenLive {
			delete(r.entries, id)
		}
	}
	hooks := r.hooks
	r.mu.Unlock()
	for _, id := range excluded {
		for _, fn := range hooks {
			fn(id)
		}
	}
}

func one(id string) func(map[string]*RegistryEntry) []string {
	return func(map[string]*RegistryEntry) []string { return []string{id} }
}

// setMember records a registration (member=true) or a removal.
func (r *Registry) setMember(nodeID string, role proto.NodeRole, member bool) {
	r.update(one(nodeID), func(_ string, e *RegistryEntry) {
		e.Member = member
		e.Role = ""
		if member {
			e.Role = role
		}
	})
}

// SetTokenLive implements busauth.LivenessSink.
func (r *Registry) SetTokenLive(nodeID string, live bool) {
	r.update(one(nodeID), func(_ string, e *RegistryEntry) { e.TokenLive = live })
}

// ReplaceTokenLive implements busauth.LivenessSink: exactly the nodes in live
// hold a live token.
func (r *Registry) ReplaceTokenLive(live map[string]bool) {
	r.update(func(entries map[string]*RegistryEntry) []string {
		ids := make([]string, 0, len(entries)+len(live))
		for id := range entries {
			ids = append(ids, id)
		}
		for id := range live {
			if entries[id] == nil {
				ids = append(ids, id)
			}
		}
		return ids
	}, func(id string, e *RegistryEntry) { e.TokenLive = live[id] })
}

// loadMembers fills membership from the nodes table. OpenStore calls it once.
func (s *Store) loadMembers(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id, role FROM nodes`)
	if err != nil {
		return fmt.Errorf("inventory: load the node registry: %w", err)
	}
	defer func() { _ = rows.Close() }()
	type member struct {
		id   string
		role proto.NodeRole
	}
	var ms []member
	for rows.Next() {
		var m member
		if err := rows.Scan(&m.id, &m.role); err != nil {
			return fmt.Errorf("inventory: load the node registry: %w", err)
		}
		ms = append(ms, m)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("inventory: load the node registry: %w", err)
	}
	for _, m := range ms {
		s.registry.setMember(m.id, m.role, true)
	}
	return nil
}

// Registry returns the store's node registry.
func (s *Store) Registry() *Registry { return s.registry }
