package inventory

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Registry is the api's ONE in-memory node list: every fact a node-facing
// authorization decision reads, per node, in one entry. Every membership and
// liveness decision the api makes about a node reads it and nothing else, so
// no connection, request or heartbeat does a database lookup to decide
// whether a node may connect, may be heard, or should be converged.
//
// What reads it today:
//
//   - the bus auth callout, per connection (busauth.Store.Admit): the token
//     the connection presents must be one of the node's live token hashes;
//   - the collector ingress, per TLS handshake (api.WireObsIngest);
//   - inventory's heartbeat and registration handlers;
//   - the collector reconcile and per-node deploy;
//   - the mesh enrol validate step and the two mesh converge steps.
//
// It lives in inventory because inventory owns the node of record: the nodes
// table, registration and removal all happen here, and the node keys Step 6
// adds are reported in registration metadata and stored on the node row, so
// they land in this same entry. Token liveness is owned by the token store
// (busauth), which sits below this package; it pushes that fact in through
// busauth.NodeRegistry, which Registry implements.
//
// Loaded once at start — membership and last-seen by OpenStore from the nodes
// table, token liveness by busauth.Store.SetNodeRegistry from the token table
// — and then changed only by the events that change it: registration and
// removal (Store.Insert / Store.Delete), heartbeats (Touch), and every mint,
// preload, adoption, revoke and tombstone re-apply (pushed by busauth). No
// timer re-reads it.
//
// # Fail closed
//
// A registry that has not finished loading admits nobody. Both loads set a
// flag; Admitted and TokenAdmits answer false until both are set, so a start
// in which the token table could not be read (main logs it) refuses every
// node rather than falling back to a database read or to an empty-means-yes
// reading of an unloaded map.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]*RegistryEntry
	hooks   []func(nodeID string)

	// membersLoaded is set by loadMembers, tokensLoaded by ReplaceLiveTokens
	// — the two whole-set loads that happen at api start. See "Fail closed".
	membersLoaded bool
	tokensLoaded  bool
}

// RegistryEntry is what the api holds about one node.
type RegistryEntry struct {
	// Member: the node has a row in inventory (it registered and was not
	// removed).
	Member bool
	// Role is the role it registered as; empty while it is not a member.
	Role proto.NodeRole
	// TokenLive: it holds at least one join token the bus would admit it with
	// (unrevoked, bound to it, naming a valid role).
	TokenLive bool
	// LastSeen is the last time the node was heard from — a heartbeat or a
	// registration. Zero while nothing has been heard. This is the live
	// value: heartbeats update it here and nowhere else, and the node row's
	// last_seen column is the floor it is loaded from at start and is
	// rewritten on every registration.
	LastSeen time.Time
	// tokens is the set of live token hashes bound to this node, pushed by
	// busauth. It is what the bus auth callout checks a presented token
	// against; TokenLive is len(tokens) > 0. Hashes only — the token store
	// remains the source of truth for the token itself, and no plaintext ever
	// reaches this package.
	tokens map[string]struct{}
	// Step 6 adds the node's registered key SPKIs here.
}

// admitted is the one rule node-facing admission applies.
func (e *RegistryEntry) admitted() bool { return e != nil && e.Member && e.TokenLive }

// empty reports whether an entry holds nothing worth keeping.
func (e *RegistryEntry) empty() bool {
	return !e.Member && !e.TokenLive && e.LastSeen.IsZero()
}

// view is the copy Lookup hands out: no internal map escapes.
func (e *RegistryEntry) view() RegistryEntry {
	return RegistryEntry{Member: e.Member, Role: e.Role, TokenLive: e.TokenLive, LastSeen: e.LastSeen}
}

// NewRegistry returns an empty registry. Nothing is admitted until both whole
// sets have loaded.
func NewRegistry() *Registry {
	return &Registry{entries: map[string]*RegistryEntry{}}
}

// loaded reports whether both whole-set loads have run. Callers hold mu.
func (r *Registry) loaded() bool { return r.membersLoaded && r.tokensLoaded }

// Loaded reports whether the registry has finished loading. Until it has,
// every admission answer is false.
func (r *Registry) Loaded() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.loaded()
}

// Admitted reports whether nodeID is a current member holding a live token.
// Memory only, and false until the registry has loaded.
func (r *Registry) Admitted(nodeID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.loaded() && r.entries[nodeID].admitted()
}

// TokenAdmits reports whether tokenHash is one of nodeID's live join-token
// hashes — the bus auth callout's whole check, answered from memory and false
// until the registry has loaded.
//
// It does NOT require membership: a node connects to the bus before it has
// ever registered, and registration itself arrives over that connection. What
// it does require is that the hash is recorded under the presented node id,
// which is the binding rule (geekdojo-brain#423); a hash that is not in any
// node's set is revoked, tombstoned, unbound, role-less or simply unknown,
// and busauth pushes exactly the set that is none of those.
func (r *Registry) TokenAdmits(nodeID, tokenHash string) bool {
	if nodeID == "" || tokenHash == "" {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.loaded() {
		return false
	}
	e := r.entries[nodeID]
	if e == nil {
		return false
	}
	_, ok := e.tokens[tokenHash]
	return ok
}

// IsMember reports whether nodeID is a current inventory member — the "is
// this a node?" question, answered from memory instead of a row lookup. It
// does NOT carry token liveness: Admitted is the question a node-facing
// admission asks.
func (r *Registry) IsMember(nodeID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.membersLoaded {
		return false
	}
	e := r.entries[nodeID]
	return e != nil && e.Member
}

// Member is one node as the registry holds it — id, role and last-seen, the
// three facts a caller needs to decide whether to act on a node without
// hydrating its row.
type Member struct {
	ID       string
	Role     proto.NodeRole
	LastSeen time.Time
}

// Members returns every current inventory member, newest-registered order not
// guaranteed. It is the node SET, from memory: a caller that needs only id,
// role and last-seen (the mesh enrolment converge) reads this instead of
// listing the nodes table. An unloaded registry returns nothing.
func (r *Registry) Members() []Member {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.membersLoaded {
		return nil
	}
	out := make([]Member, 0, len(r.entries))
	for id, e := range r.entries {
		if e.Member {
			out = append(out, Member{ID: id, Role: e.Role, LastSeen: e.LastSeen})
		}
	}
	slices.SortFunc(out, func(a, b Member) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// Lookup returns a copy of nodeID's entry, and whether there is one.
func (r *Registry) Lookup(nodeID string) (RegistryEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[nodeID]
	if !ok {
		return RegistryEntry{}, false
	}
	return e.view(), true
}

// MemberCount returns how many nodes are current inventory members — what the
// cluster-size cap counts, without a COUNT(*) on the registration path.
func (r *Registry) MemberCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, e := range r.entries {
		if e.Member {
			n++
		}
	}
	return n
}

// Touch records that nodeID was heard from at t and reports whether the
// registry accepted it: a heartbeat is accepted only from a current inventory
// member. Memory only; nothing is written to the database, and no entry is
// created for a node that has none.
//
// The refusal is the membership check the heartbeat handler used to make by
// writing the nodes table and reading how many rows it matched.
//
// Membership, and not admission: a heartbeat arrives over a bus connection
// the callout already admitted on the token, so re-applying token liveness
// here would add nothing on an enforced bus — and it would silence every node
// on an api started with RASPUTIN_BUS_AUTH=off, where no token gates anything
// and so no node holds a live one.
//
// Membership loaded, not the whole registry, for the same reason: the nodes
// table is read at OpenStore, so it is always loaded before anything can
// heartbeat, and a token load that failed must not also stop the api hearing
// the nodes it has.
func (r *Registry) Touch(nodeID string, t time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.membersLoaded {
		return false
	}
	e := r.entries[nodeID]
	if e == nil || !e.Member {
		return false
	}
	if t.After(e.LastSeen) {
		e.LastSeen = t
	}
	return true
}

// lastSeen returns the live last-seen for nodeID, or the zero time.
func (r *Registry) lastSeen(nodeID string) time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if e := r.entries[nodeID]; e != nil {
		return e.LastSeen
	}
	return time.Time{}
}

// OnNodeExcluded registers fn to run, outside the registry's lock, each time a
// node stops being admitted: it was removed from inventory, or its last live
// token was revoked. The collector ingress closes the node's connections, and
// the token store closes its bus sessions and drops its takeover records.
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
		e.TokenLive = len(e.tokens) > 0
		if was && !e.admitted() {
			excluded = append(excluded, id)
		}
		if e.empty() {
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

// setMember records a registration (member=true) or a removal. lastSeen moves
// the node's live last-seen forward; the zero time leaves it alone.
func (r *Registry) setMember(nodeID string, role proto.NodeRole, member bool, lastSeen time.Time) {
	r.update(one(nodeID), func(_ string, e *RegistryEntry) {
		e.Member = member
		e.Role = ""
		if member {
			e.Role = role
		}
		if lastSeen.After(e.LastSeen) {
			e.LastSeen = lastSeen
		}
		if !member {
			e.LastSeen = time.Time{}
		}
	})
}

// setTokens replaces one node's live token hashes.
func setTokens(e *RegistryEntry, hashes []string) {
	if len(hashes) == 0 {
		e.tokens = nil
		return
	}
	e.tokens = make(map[string]struct{}, len(hashes))
	for _, h := range hashes {
		if h != "" {
			e.tokens[h] = struct{}{}
		}
	}
}

// SetLiveTokens implements busauth.NodeRegistry: these, and only these, are
// the live join-token hashes bound to nodeID.
func (r *Registry) SetLiveTokens(nodeID string, hashes []string) {
	r.update(one(nodeID), func(_ string, e *RegistryEntry) { setTokens(e, hashes) })
}

// ReplaceLiveTokens implements busauth.NodeRegistry: the whole live set at
// once, as read from the token table when the registry is attached. It is
// also what marks token liveness loaded — before it runs, nothing is
// admitted.
func (r *Registry) ReplaceLiveTokens(live map[string][]string) {
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
	}, func(id string, e *RegistryEntry) { setTokens(e, live[id]) })
	r.mu.Lock()
	r.tokensLoaded = true
	r.mu.Unlock()
}

// loadMembers fills membership and last-seen from the nodes table. OpenStore
// calls it once; it is what marks membership loaded.
func (s *Store) loadMembers(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id, role, last_seen FROM nodes`)
	if err != nil {
		return fmt.Errorf("inventory: load the node registry: %w", err)
	}
	defer func() { _ = rows.Close() }()
	type member struct {
		id       string
		role     proto.NodeRole
		lastSeen sql.NullInt64
	}
	var ms []member
	for rows.Next() {
		var m member
		if err := rows.Scan(&m.id, &m.role, &m.lastSeen); err != nil {
			return fmt.Errorf("inventory: load the node registry: %w", err)
		}
		ms = append(ms, m)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("inventory: load the node registry: %w", err)
	}
	for _, m := range ms {
		var seen time.Time
		if m.lastSeen.Valid {
			seen = fromMillis(m.lastSeen.Int64)
		}
		s.registry.setMember(m.id, m.role, true, seen)
	}
	s.registry.mu.Lock()
	s.registry.membersLoaded = true
	s.registry.mu.Unlock()
	return nil
}

// Registry returns the store's node registry.
func (s *Store) Registry() *Registry { return s.registry }
