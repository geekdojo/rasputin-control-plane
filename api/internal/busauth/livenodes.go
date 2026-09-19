package busauth

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The live-node set: which node ids hold at least one token the bus would
// admit them with (unrevoked, bound, naming a valid role).
//
// It exists so a node's other credentials can follow its token WITHOUT a
// database read on a hot path: the collector ingress checks it once per TLS
// handshake, and closes a node's open connections when the node leaves it
// (OnNodeRevoked). It is kept in memory and changed only by the events that
// change it — loaded once at OpenStore, then refreshed for a node by every
// mint, preload, adoption and revoke that touches that node. No timer
// re-reads it.
//
// A refresh that cannot read the database leaves the node NOT live: failing
// to learn that a node may connect is a refusal, never an admission.

// liveNodes is the Store's in-memory live-node set and its subscribers.
type liveNodes struct {
	set   map[string]bool
	hooks []func(nodeID string)
}

// NodeLive reports whether nodeID holds a token the bus would admit it with.
// In memory only: it never touches the database.
func (s *Store) NodeLive(nodeID string) bool {
	s.liveMu.RLock()
	defer s.liveMu.RUnlock()
	return s.live.set[nodeID]
}

// OnNodeRevoked registers fn to be called, outside the store's locks, each time
// a node leaves the live-node set — its last live token revoked, by an operator
// revoke or by node removal. The collector ingress uses it to close the node's
// open connections.
func (s *Store) OnNodeRevoked(fn func(nodeID string)) {
	s.liveMu.Lock()
	s.live.hooks = append(s.live.hooks, fn)
	s.liveMu.Unlock()
}

// loadLiveNodes reads the whole set from the database. OpenStore calls it once.
func (s *Store) loadLiveNodes(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `
        SELECT node_id, role FROM bus_tokens
        WHERE revoked_at IS NULL AND node_id IS NOT NULL AND node_id != ''`)
	if err != nil {
		return fmt.Errorf("busauth: load live nodes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	set := map[string]bool{}
	for rows.Next() {
		var (
			node string
			role sql.NullString
		)
		if err := rows.Scan(&node, &role); err != nil {
			return fmt.Errorf("busauth: load live nodes: %w", err)
		}
		if role.Valid && proto.ValidRole(proto.NodeRole(role.String)) {
			set[node] = true
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("busauth: load live nodes: %w", err)
	}
	s.liveMu.Lock()
	s.live.set = set
	s.liveMu.Unlock()
	return nil
}

// refreshNodes re-reads each node's liveness after an event that may have
// changed it, and calls the OnNodeRevoked hooks for every node that left the
// set. A read that fails counts as not live.
func (s *Store) refreshNodes(ctx context.Context, nodeIDs ...string) {
	var left []string
	var hooks []func(string)
	for _, node := range nodeIDs {
		if node == "" {
			continue
		}
		live, err := s.NodeHasLiveToken(ctx, node)
		if err != nil {
			log.Printf("busauth: refreshing whether node %q holds a live token: %v — treating it as not live", node, err)
			live = false
		}
		s.liveMu.Lock()
		was := s.live.set[node]
		if s.live.set == nil {
			s.live.set = map[string]bool{}
		}
		if live {
			s.live.set[node] = true
		} else {
			delete(s.live.set, node)
		}
		hooks = s.live.hooks
		s.liveMu.Unlock()
		if was && !live {
			left = append(left, node)
		}
	}
	for _, node := range left {
		for _, fn := range hooks {
			fn(node)
		}
	}
}
