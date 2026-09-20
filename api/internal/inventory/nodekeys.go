package inventory

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// A node's registered keys (geekdojo/geekdojo-brain#514).
//
// The agent generates two keys on the node and reports their SPKI hashes in
// registration metadata. The api records them here — durably, beside the node
// of record, so they survive a restart — and in the in-memory Registry, which
// is what an HTTPS handshake actually reads. The database is read exactly
// once, at start (loadKeys), and on the registration that changes a value.
// Nothing on a connection or request path touches it.
//
// Rules, from auth-methodology §5.2:
//
//   - A key is accepted only over a connection the node reports as TLS with
//     the bus pin verified. On an unpinned link a man-in-the-middle holding a
//     sniffed join token could otherwise register a key of its own.
//   - A registration presenting a DIFFERENT hash for a purpose replaces the
//     recorded one, again only over a pinned connection. Refusing changes
//     would strand every reflashed node; the change is audited and alerted
//     instead, which is what makes it visible. Keys live where the join token
//     lives and survive a sysupgrade, so a change means a reflash and the
//     alert stays rare.
//   - A hash another node has already registered is refused outright. Two
//     nodes cannot share an HTTPS identity, and the one case that produces
//     it — a key file copied off one node onto another — is exactly what the
//     refusal should stop. The unique index below is the same rule at the
//     database.

// ErrNodeKeyTaken is returned when a node reports a key another node has
// already registered.
var ErrNodeKeyTaken = errors.New("inventory: that node key is registered to another node")

// NodeKeyChange describes what one accepted report changed, for the caller
// that audits and alerts on it.
type NodeKeyChange struct {
	NodeID string
	// Previous is what was recorded before, empty on a first registration.
	Previous proto.NodeKeys
	// Current is what is recorded now.
	Current proto.NodeKeys
	// Replaced names the purposes whose hash changed to a different one — a
	// node key CHANGE, as distinct from a purpose registering for the first
	// time. This is what raises the alert.
	Replaced []proto.NodeKeyPurpose
}

// Changed reports whether anything was written.
func (c NodeKeyChange) Changed() bool { return !c.Previous.Equal(c.Current) }

// SetNodeKeys records nodeID's reported keys, returning what changed.
//
// Keys not mentioned in keys are left alone: an older agent that knows only
// one purpose must not retire the other. Passing an empty set is therefore a
// no-op, not a revocation — removal (Delete) is what clears a node's keys.
//
// The caller has already decided the report is acceptable
// (proto.NodeKeysAcceptable); this is the recording half.
func (s *Store) SetNodeKeys(ctx context.Context, nodeID string, keys proto.NodeKeys) (NodeKeyChange, error) {
	change := NodeKeyChange{NodeID: nodeID}
	if nodeID == "" {
		return change, errors.New("inventory: SetNodeKeys: node id required")
	}
	previous, err := s.NodeKeys(ctx, nodeID)
	if err != nil {
		return change, err
	}
	change.Previous = previous
	current := previous.Clone()
	if current == nil {
		current = proto.NodeKeys{}
	}
	for _, p := range keys.Purposes() {
		spki := keys[p]
		if current[p] == spki {
			continue
		}
		// In memory, and therefore without a query: the reverse index is
		// authoritative for "who holds this key" and is kept in step with
		// the table under the registry's own lock.
		if o, taken := s.registry.KeyOwner(spki); taken && o.NodeID != nodeID {
			return change, fmt.Errorf("%w (%s holds it)", ErrNodeKeyTaken, o.NodeID)
		}
		if current[p] != "" {
			change.Replaced = append(change.Replaced, p)
		}
		current[p] = spki
	}
	change.Current = current
	if !change.Changed() {
		return change, nil
	}
	now := tsMillis(time.Now().UTC())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return change, fmt.Errorf("inventory: record node keys for %s: %w", nodeID, err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, p := range current.Purposes() {
		if previous[p] == current[p] {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
            INSERT INTO node_keys (node_id, purpose, spki, recorded_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(node_id, purpose) DO UPDATE SET spki = excluded.spki, recorded_at = excluded.recorded_at`,
			nodeID, string(p), current[p], now); err != nil {
			return change, fmt.Errorf("inventory: record node keys for %s: %w", nodeID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return change, fmt.Errorf("inventory: record node keys for %s: %w", nodeID, err)
	}
	s.registry.setKeys(nodeID, current)
	return change, nil
}

// NodeKeys returns the keys recorded for a node, nil when it has none.
// Read from the database: this is the durable record, not the admission path.
func (s *Store) NodeKeys(ctx context.Context, nodeID string) (proto.NodeKeys, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT purpose, spki FROM node_keys WHERE node_id = ?`, nodeID)
	if err != nil {
		return nil, fmt.Errorf("inventory: read node keys for %s: %w", nodeID, err)
	}
	defer func() { _ = rows.Close() }()
	var out proto.NodeKeys
	for rows.Next() {
		var purpose, spki string
		if err := rows.Scan(&purpose, &spki); err != nil {
			return nil, fmt.Errorf("inventory: read node keys for %s: %w", nodeID, err)
		}
		if out == nil {
			out = proto.NodeKeys{}
		}
		out[proto.NodeKeyPurpose(purpose)] = spki
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read node keys for %s: %w", nodeID, err)
	}
	return out, nil
}

// deleteNodeKeys drops a node's key registrations. Called by Delete, so a
// removed node's keys go with its row — the revocation cascade of §5.2.
func (s *Store) deleteNodeKeys(ctx context.Context, nodeID string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM node_keys WHERE node_id = ?`, nodeID); err != nil {
		return fmt.Errorf("inventory: delete node keys for %s: %w", nodeID, err)
	}
	return nil
}

// loadKeys fills the registry's key index from the table. OpenStore calls it
// once, beside loadMembers: after this, every registered key an HTTPS
// handshake could present is in memory, so the listener is correct from the
// first connection rather than only for nodes that have re-registered since
// the api started.
func (s *Store) loadKeys(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id, purpose, spki FROM node_keys`)
	if err != nil {
		return fmt.Errorf("inventory: load the node key registry: %w", err)
	}
	defer func() { _ = rows.Close() }()
	byNode := map[string]proto.NodeKeys{}
	for rows.Next() {
		var nodeID, purpose, spki string
		if err := rows.Scan(&nodeID, &purpose, &spki); err != nil {
			return fmt.Errorf("inventory: load the node key registry: %w", err)
		}
		if byNode[nodeID] == nil {
			byNode[nodeID] = proto.NodeKeys{}
		}
		byNode[nodeID][proto.NodeKeyPurpose(purpose)] = spki
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("inventory: load the node key registry: %w", err)
	}
	for nodeID, keys := range byNode {
		s.registry.setKeys(nodeID, keys)
	}
	return nil
}
