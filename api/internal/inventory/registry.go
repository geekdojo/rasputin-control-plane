package inventory

import (
	"context"
	"fmt"
	"sort"
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
	// byKey is the reverse index the node listener reads: one registered
	// key SPKI hash to the node that registered it and what it is for. It
	// is what makes admission a map lookup under a read lock rather than a
	// scan of every node, and it is kept in step with the entries under the
	// same write lock, so the two can never disagree.
	byKey     map[string]KeyOwner
	hooks     []func(nodeID string)
	keyRetire []func(nodeID string, retired []string)
}

// KeyOwner names the node a registered key belongs to and what the key is
// for.
type KeyOwner struct {
	NodeID  string
	Purpose proto.NodeKeyPurpose
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
	// Keys are the node's registered key SPKI hashes, by purpose — what a
	// node-facing TLS handshake compares the peer's key against
	// (geekdojo/geekdojo-brain#514). Empty for a node that has not
	// registered any: every node on the legacy path, and every node whose
	// bus connection is not yet pinned.
	Keys proto.NodeKeys
}

// admitted is the one rule node-facing admission applies.
func (e *RegistryEntry) admitted() bool { return e != nil && e.Member && e.TokenLive }

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{entries: map[string]*RegistryEntry{}, byKey: map[string]KeyOwner{}}
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
	out := *e
	out.Keys = e.Keys.Clone()
	return out, true
}

// KeyOwner reports which node registered the key with this SPKI hash, and
// what the key is for. Memory only, one map lookup: nothing on a connection
// or request path reads the database to answer it.
//
// It answers REGISTRATION only. Whether that node may connect right now is
// Admitted, and AdmitKey asks both at once, which is what a handshake wants.
func (r *Registry) KeyOwner(spki string) (KeyOwner, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	o, ok := r.byKey[spki]
	return o, ok
}

// AdmitKey is the one rule a node-facing TLS handshake applies: this SPKI is
// registered, AND the node that registered it is a current inventory member
// holding a live join token. Both facts under one read lock, so a handshake
// cannot see a key whose owner was excluded between the two lookups.
func (r *Registry) AdmitKey(spki string) (KeyOwner, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	o, ok := r.byKey[spki]
	if !ok || !r.entries[o.NodeID].admitted() {
		return KeyOwner{}, false
	}
	return o, true
}

// OnNodeExcluded registers fn to run, outside the registry's lock, each time a
// node stops being admitted: it was removed from inventory, or its last live
// token was revoked. The collector ingress closes the node's connections.
func (r *Registry) OnNodeExcluded(fn func(nodeID string)) {
	r.mu.Lock()
	r.hooks = append(r.hooks, fn)
	r.mu.Unlock()
}

// OnKeysRetired registers fn to run, outside the registry's lock, each time a
// node's registered keys change: retired holds the SPKI hashes that are no
// longer registered for it. The node listener ends the HTTPS sessions held
// under them, so a replaced key stops working at once rather than lasting as
// long as somebody keeps a connection open.
func (r *Registry) OnKeysRetired(fn func(nodeID string, retired []string)) {
	r.mu.Lock()
	r.keyRetire = append(r.keyRetire, fn)
	r.mu.Unlock()
}

// update applies change to the entries of the nodes ids names — read under
// the lock, so a whole-set change sees every entry — and fires the exclusion
// hooks for every node that went from admitted to not, and the key-retirement
// hooks for every SPKI that stopped being registered.
func (r *Registry) update(ids func(entries map[string]*RegistryEntry) []string, change func(id string, e *RegistryEntry)) {
	var excluded []string
	retired := map[string][]string{}
	r.mu.Lock()
	for _, id := range ids(r.entries) {
		e := r.entries[id]
		if e == nil {
			e = &RegistryEntry{}
			r.entries[id] = e
		}
		was := e.admitted()
		before := e.Keys.Clone()
		change(id, e)
		if was && !e.admitted() {
			excluded = append(excluded, id)
		}
		if !e.Member && !e.TokenLive {
			e.Keys = nil
			delete(r.entries, id)
		}
		if gone := r.reindexKeysLocked(id, before, e.Keys); len(gone) > 0 {
			retired[id] = append(retired[id], gone...)
		}
	}
	hooks := r.hooks
	keyHooks := r.keyRetire
	r.mu.Unlock()
	for _, id := range excluded {
		for _, fn := range hooks {
			fn(id)
		}
	}
	for id, gone := range retired {
		for _, fn := range keyHooks {
			fn(id, gone)
		}
	}
}

// reindexKeysLocked moves nodeID from before to after in the reverse index and
// returns the SPKI hashes that stopped being registered for it. Caller holds
// the write lock.
func (r *Registry) reindexKeysLocked(nodeID string, before, after proto.NodeKeys) []string {
	var retired []string
	for p, spki := range before {
		if after[p] == spki {
			continue
		}
		// Only drop the index entry this node owns: a hash another node
		// holds is not this node's to remove, and SetNodeKeys refuses to
		// let two nodes register the same key in the first place.
		if o, ok := r.byKey[spki]; ok && o.NodeID == nodeID {
			delete(r.byKey, spki)
		}
		retired = append(retired, spki)
	}
	for p, spki := range after {
		if before[p] == spki {
			continue
		}
		r.byKey[spki] = KeyOwner{NodeID: nodeID, Purpose: p}
	}
	sort.Strings(retired)
	return retired
}

// setKeys records nodeID's registered keys. A node with no entry yet — a
// registration whose row write has not reached the registry — gets one, the
// same way setMember and SetTokenLive make one.
func (r *Registry) setKeys(nodeID string, keys proto.NodeKeys) {
	r.update(one(nodeID), func(_ string, e *RegistryEntry) { e.Keys = keys.Clone() })
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
			return
		}
		// Removal clears the node's key registrations, the same cascade
		// that deletes its rows: a node that is gone has no registered
		// identity, and a later re-add re-registers its keys.
		e.Keys = nil
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
