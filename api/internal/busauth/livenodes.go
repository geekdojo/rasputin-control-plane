package busauth

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Token liveness, pushed to — and then read back from — the node registry.
//
// Which join tokens the bus would admit a node with (unrevoked, bound to that
// node, naming a valid role) is one of the facts the api's single in-memory
// node registry keeps (inventory.Registry). This store does not keep a second
// copy: it is the source of the fact, and it pushes the fact into the
// registry through a NodeRegistry — the whole set once, when the registry is
// attached at start, and then one node at a time, from every mint, preload,
// adoption, revoke and tombstone re-apply that touches that node. No timer
// re-reads it.
//
// The auth callout then READS the same registry, per connection, instead of
// the token table (Store.Admit): the presented token's hash must be one of
// the presented node's live hashes. That is the whole check — the three
// refusals Validate spells out against the database (revoked, unbound,
// role-less) are exactly the rows the live set leaves out.
//
// The registry is an interface defined here, not the registry type itself,
// because the registry's package (inventory) sits above this one: the
// dependency points from inventory to busauth, never back.
//
// A refresh that cannot read the database pushes the node as holding NO live
// token: failing to learn that a node may connect is a refusal, never an
// admission. So is a registry that was never attached — see Store.admits.

// NodeRegistry is the api's one in-memory node list, as this package uses it:
// the sink token liveness is pushed to, and the list the auth callout checks
// a presented token against. *inventory.Registry implements it.
type NodeRegistry interface {
	// ReplaceLiveTokens sets every node's live join-token hashes at once: the
	// nodes in live hold exactly those, every other node holds none.
	ReplaceLiveTokens(live map[string][]string)
	// SetLiveTokens sets one node's live join-token hashes.
	SetLiveTokens(nodeID string, hashes []string)
	// TokenAdmits reports, from memory, whether tokenHash is one of nodeID's
	// live join-token hashes.
	TokenAdmits(nodeID, tokenHash string) bool
}

// registryRef holds the attached registry for the lock-free read on the
// admission path. The same object the pushes go to — not a second copy. It is
// read without sinkMu deliberately: a push holds sinkMu while the registry
// runs its exclusion hooks, and one of those hooks closes the node's bus
// sessions under the session lock, which the admission path already holds.
type registryRef struct{ reg NodeRegistry }

// SetNodeRegistry attaches the registry and pushes the whole live set into it,
// read from the database. From then on every token event pushes the nodes it
// touched, and the auth callout answers from it. Held under the same lock as
// those pushes, so no event between the read and the attach is lost.
//
// Until it has run — and if it returns an error, for good — this store admits
// nobody: see Store.admits.
func (s *Store) SetNodeRegistry(ctx context.Context, reg NodeRegistry) error {
	s.sinkMu.Lock()
	defer s.sinkMu.Unlock()
	set, err := s.liveTokensByNode(ctx)
	if err != nil {
		return err
	}
	reg.ReplaceLiveTokens(set)
	s.sink = reg
	s.reg.Store(&registryRef{reg: reg})
	return nil
}

// registry returns the attached registry, or nil.
func (s *Store) registry() NodeRegistry {
	if r := s.reg.Load(); r != nil {
		return r.reg
	}
	return nil
}

// admits is the auth callout's whole token check, answered from the node
// registry with no database read: the presented token's hash must be one of
// the presented node id's live hashes.
//
// With no registry attached it answers false. That is the fail-closed rule:
// the api attaches the registry before the callout responder starts, so a
// store serving connections without one has had its load fail, and a load
// that failed is a reason to refuse every node, not a reason to fall back to
// a per-connection database read.
func (s *Store) admits(plaintext, presentedNodeID string) bool {
	if plaintext == "" || presentedNodeID == "" {
		return false
	}
	reg := s.registry()
	if reg == nil {
		log.Printf("busauth: refusing node %q: the node registry has not loaded, so no node is admitted", oneLine(presentedNodeID))
		return false
	}
	return reg.TokenAdmits(presentedNodeID, HashToken(plaintext))
}

// liveTokensByNode reads, from the database, every node's live token hashes:
// unrevoked, bound to a node id, and naming a valid role. A row failing any of
// those is left out, which is how the callout comes to refuse it.
func (s *Store) liveTokensByNode(ctx context.Context) (map[string][]string, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT node_id, role, token_hash FROM bus_tokens
        WHERE revoked_at IS NULL AND node_id IS NOT NULL AND node_id != ''`)
	if err != nil {
		return nil, fmt.Errorf("busauth: load live nodes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	set := map[string][]string{}
	for rows.Next() {
		var (
			node string
			role sql.NullString
			hash string
		)
		if err := rows.Scan(&node, &role, &hash); err != nil {
			return nil, fmt.Errorf("busauth: load live nodes: %w", err)
		}
		if hash != "" && role.Valid && proto.ValidRole(proto.NodeRole(role.String)) {
			set[node] = append(set[node], hash)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("busauth: load live nodes: %w", err)
	}
	return set, nil
}

// oneLine removes line breaks, so a value cannot forge a log line.
func oneLine(v string) string {
	return strings.ReplaceAll(strings.ReplaceAll(v, "\n", ""), "\r", "")
}

// refreshNodes re-reads each node's live token hashes after an event that may
// have changed them and pushes them to the registry. With no registry attached
// yet it does nothing: SetNodeRegistry reads the whole set when it attaches.
func (s *Store) refreshNodes(ctx context.Context, nodeIDs ...string) {
	s.sinkMu.Lock()
	defer s.sinkMu.Unlock()
	if s.sink == nil {
		return
	}
	for _, node := range nodeIDs {
		if node == "" {
			continue
		}
		hashes, err := s.liveTokenHashes(ctx, node)
		if err != nil {
			// The node id can arrive from a request path (node removal), so
			// line breaks are stripped from everything logged here.
			log.Printf("busauth: refreshing node %q's live join tokens: %s — treating it as holding none",
				oneLine(node), oneLine(err.Error()))
			hashes = nil
		}
		s.sink.SetLiveTokens(node, hashes)
	}
}
