package bmc

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	_ "modernc.org/sqlite"
)

// Store is the SQLite-backed ledger of per-target BMC state.
type Store struct {
	db *sql.DB
}

func OpenStore(ctx context.Context, path string) (*Store, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("bmc: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("bmc: apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func ms(t time.Time) int64     { return t.UnixMilli() }
func fromMs(v int64) time.Time { return time.UnixMilli(v).UTC() }

// Upsert records the most recent BMC command result for a target node.
func (s *Store) Upsert(ctx context.Context, ns *NodeState) error {
	var lastCmdAt any
	if ns.LastCmdAt != nil {
		lastCmdAt = ms(*ns.LastCmdAt)
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO bmc_state (target_node_id, power_state, last_cmd, last_cmd_at, last_cmd_result, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(target_node_id) DO UPDATE SET
            power_state = excluded.power_state,
            last_cmd = excluded.last_cmd,
            last_cmd_at = excluded.last_cmd_at,
            last_cmd_result = excluded.last_cmd_result,
            updated_at = excluded.updated_at`,
		ns.TargetNodeID, string(ns.PowerState), ns.LastCmd, lastCmdAt,
		ns.LastCmdResult, ms(ns.UpdatedAt))
	return err
}

// Get returns the state row for a target, or (nil, nil) if unknown.
func (s *Store) Get(ctx context.Context, targetID string) (*NodeState, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT target_node_id, power_state, last_cmd, last_cmd_at, last_cmd_result, updated_at
        FROM bmc_state WHERE target_node_id = ?`, targetID)
	return scanState(row.Scan)
}

// List returns every BMC state row, ordered by target node id.
func (s *Store) List(ctx context.Context) ([]*NodeState, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT target_node_id, power_state, last_cmd, last_cmd_at, last_cmd_result, updated_at
        FROM bmc_state ORDER BY target_node_id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*NodeState
	for rows.Next() {
		ns, err := scanState(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, ns)
	}
	return out, rows.Err()
}

func scanState(scan func(...any) error) (*NodeState, error) {
	var (
		ns         NodeState
		state      string
		lastCmdAt  sql.NullInt64
		updatedAt  int64
	)
	if err := scan(&ns.TargetNodeID, &state, &ns.LastCmd, &lastCmdAt, &ns.LastCmdResult, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	ns.PowerState = proto.BMCPowerState(state)
	if lastCmdAt.Valid {
		t := fromMs(lastCmdAt.Int64)
		ns.LastCmdAt = &t
	}
	ns.UpdatedAt = fromMs(updatedAt)
	return &ns, nil
}
