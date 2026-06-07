package firewall

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the SQLite-backed ledger for firewall intents and per-node state.
type Store struct {
	db *sql.DB
}

func OpenStore(ctx context.Context, path string) (*Store, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("firewall: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("firewall: apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func ms(t time.Time) int64     { return t.UnixMilli() }
func fromMs(v int64) time.Time { return time.UnixMilli(v).UTC() }

// ----- Intents ------------------------------------------------------------

func (s *Store) CreateIntent(ctx context.Context, i *Intent) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO firewall_intents (id, kind, name, enabled, spec, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
		i.ID, i.Kind, i.Name, boolToInt(i.Enabled), string(i.Spec),
		ms(i.CreatedAt), ms(i.UpdatedAt))
	return err
}

func (s *Store) UpdateIntent(ctx context.Context, i *Intent) error {
	res, err := s.db.ExecContext(ctx, `
        UPDATE firewall_intents
        SET kind = ?, name = ?, enabled = ?, spec = ?, updated_at = ?
        WHERE id = ?`,
		i.Kind, i.Name, boolToInt(i.Enabled), string(i.Spec),
		ms(i.UpdatedAt), i.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) DeleteIntent(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM firewall_intents WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) GetIntent(ctx context.Context, id string) (*Intent, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT id, kind, name, enabled, spec, created_at, updated_at
        FROM firewall_intents WHERE id = ?`, id)
	return scanIntent(row.Scan)
}

func (s *Store) ListIntents(ctx context.Context) ([]*Intent, error) {
	// Sort by created_at then id so Compile produces deterministic hashes.
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, kind, name, enabled, spec, created_at, updated_at
        FROM firewall_intents ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Intent
	for rows.Next() {
		i, err := scanIntent(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func scanIntent(scan func(...any) error) (*Intent, error) {
	var (
		i         Intent
		enabled   int
		spec      string
		createdAt int64
		updatedAt int64
	)
	if err := scan(&i.ID, &i.Kind, &i.Name, &enabled, &spec, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	i.Enabled = enabled != 0
	i.Spec = json.RawMessage(spec)
	i.CreatedAt = fromMs(createdAt)
	i.UpdatedAt = fromMs(updatedAt)
	return &i, nil
}

// ----- NodeState ----------------------------------------------------------

func (s *Store) GetNodeState(ctx context.Context, nodeID string) (*NodeState, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT target_node_id, intent_hash, observed_hash, last_applied, last_reconciled
        FROM firewall_state WHERE target_node_id = ?`, nodeID)
	var (
		ns             NodeState
		lastApplied    sql.NullInt64
		lastReconciled sql.NullInt64
	)
	if err := row.Scan(&ns.NodeID, &ns.IntentHash, &ns.ObservedHash, &lastApplied, &lastReconciled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if lastApplied.Valid {
		t := fromMs(lastApplied.Int64)
		ns.LastApplied = &t
	}
	if lastReconciled.Valid {
		t := fromMs(lastReconciled.Int64)
		ns.LastReconciled = &t
	}
	ns.Drift = ns.ObservedHash != "" && ns.ObservedHash != ns.IntentHash
	return &ns, nil
}

// UpdateAfterApply records that we pushed intentHash to nodeID at ts. The
// observed_hash is reset to intentHash on the assumption that if the agent
// returned the same hash, the system is in sync — the next reconcile will
// re-verify.
func (s *Store) UpdateAfterApply(ctx context.Context, nodeID, intentHash string, ts time.Time) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO firewall_state (target_node_id, intent_hash, observed_hash, last_applied)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(target_node_id) DO UPDATE SET
            intent_hash = excluded.intent_hash,
            observed_hash = excluded.observed_hash,
            last_applied = excluded.last_applied`,
		nodeID, intentHash, intentHash, ms(ts))
	return err
}

// DeleteNodeState removes the per-node reconciliation row for nodeID. Used
// when a node is removed from inventory — the firewall state is keyed by
// node id and becomes meaningless once the node is gone. Returns
// (false, nil) if no row existed (node never had firewall state, common
// for non-firewall nodes), (true, nil) on a successful delete.
func (s *Store) DeleteNodeState(ctx context.Context, nodeID string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM firewall_state WHERE target_node_id = ?`, nodeID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// UpdateAfterReconcile records the observed hash from the agent at ts.
func (s *Store) UpdateAfterReconcile(ctx context.Context, nodeID, observedHash string, ts time.Time) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO firewall_state (target_node_id, intent_hash, observed_hash, last_reconciled)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(target_node_id) DO UPDATE SET
            observed_hash = excluded.observed_hash,
            last_reconciled = excluded.last_reconciled`,
		nodeID, "", observedHash, ms(ts))
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
