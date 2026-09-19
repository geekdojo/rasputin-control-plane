package busauth

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Token liveness, pushed to the node registry.
//
// Whether a node holds a token the bus would admit it with (unrevoked, bound,
// naming a valid role) is one of the facts the api's single in-memory node
// registry keeps (inventory.Registry). This store does not keep a copy: it is
// the source of the fact, and it pushes the fact into the registry through a
// LivenessSink — the whole set once, when the sink is attached at start, and
// then one node at a time, from every mint, preload, adoption, revoke and
// tombstone re-apply that touches that node. No timer re-reads it.
//
// The sink is an interface defined here, not the registry type itself,
// because the registry's package (inventory) sits above this one: the
// dependency points from inventory to busauth, never back.
//
// A refresh that cannot read the database pushes the node as NOT live:
// failing to learn that a node may connect is a refusal, never an admission.

// LivenessSink receives token liveness. *inventory.Registry implements it.
type LivenessSink interface {
	// ReplaceTokenLive sets every node's token liveness at once: the nodes in
	// live are live, every other node is not.
	ReplaceTokenLive(live map[string]bool)
	// SetTokenLive sets one node's token liveness.
	SetTokenLive(nodeID string, live bool)
}

// SetLivenessSink attaches the registry and pushes the whole live set into it,
// read from the database. From then on every token event pushes the nodes it
// touched. Held under the same lock as those pushes, so no event between the
// read and the attach is lost.
func (s *Store) SetLivenessSink(ctx context.Context, sink LivenessSink) error {
	s.sinkMu.Lock()
	defer s.sinkMu.Unlock()
	set, err := s.liveNodeSet(ctx)
	if err != nil {
		return err
	}
	sink.ReplaceTokenLive(set)
	s.sink = sink
	return nil
}

// liveNodeSet reads, from the database, every node that holds a live token.
func (s *Store) liveNodeSet(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT node_id, role FROM bus_tokens
        WHERE revoked_at IS NULL AND node_id IS NOT NULL AND node_id != ''`)
	if err != nil {
		return nil, fmt.Errorf("busauth: load live nodes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	set := map[string]bool{}
	for rows.Next() {
		var (
			node string
			role sql.NullString
		)
		if err := rows.Scan(&node, &role); err != nil {
			return nil, fmt.Errorf("busauth: load live nodes: %w", err)
		}
		if role.Valid && proto.ValidRole(proto.NodeRole(role.String)) {
			set[node] = true
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

// refreshNodes re-reads each node's token liveness after an event that may
// have changed it and pushes it to the sink. With no sink attached yet it does
// nothing: SetLivenessSink reads the whole set when it attaches.
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
		live, err := s.NodeHasLiveToken(ctx, node)
		if err != nil {
			// The node id can arrive from a request path (node removal), so
			// line breaks are stripped from everything logged here.
			log.Printf("busauth: refreshing whether node %q holds a live token: %s — treating it as not live",
				oneLine(node), oneLine(err.Error()))
			live = false
		}
		s.sink.SetTokenLive(node, live)
	}
}
