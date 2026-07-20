package metrics

import (
	"context"
	"database/sql"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Store persists per-node metric samples to SQLite. The table is treated as
// a ring buffer — a GC loop deletes rows older than the retention window.
type Store struct {
	db *sql.DB
}

func OpenStore(ctx context.Context, path string) (*Store, error) {
	db, err := dbutil.Open(ctx, path, schema, "metrics")
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Insert writes every (name, value) pair from ev as a separate row, all in
// one transaction so a partial sample never lands.
func (s *Store) Insert(ctx context.Context, ev *proto.MetricsEvt) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
        INSERT OR REPLACE INTO metrics (node_id, name, ts, value)
        VALUES (?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	ts := ev.Ts.UnixMilli()
	for name, value := range ev.Metrics {
		if _, err := stmt.ExecContext(ctx, ev.NodeID, name, ts, value); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteBefore removes rows older than cutoff. Used by the GC loop.
func (s *Store) DeleteBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM metrics WHERE ts < ?`, cutoff.UnixMilli())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Point is one (ts, value) tuple in a returned series.
type Point struct {
	Ts    time.Time `json:"ts"`
	Value float64   `json:"value"`
}

// Series groups points by metric name for a given node + time window.
type Series struct {
	NodeID string             `json:"nodeId"`
	From   time.Time          `json:"from"`
	To     time.Time          `json:"to"`
	Series map[string][]Point `json:"series"`
}

// Query returns the time series for `names` (or all names if nil) for the
// node, within [from, to]. Points come back ordered by ts ascending.
func (s *Store) Query(ctx context.Context, nodeID string, names []string, from, to time.Time) (*Series, error) {
	out := &Series{
		NodeID: nodeID,
		From:   from,
		To:     to,
		Series: map[string][]Point{},
	}

	args := []any{nodeID, from.UnixMilli(), to.UnixMilli()}
	q := `SELECT name, ts, value FROM metrics WHERE node_id = ? AND ts >= ? AND ts <= ?`
	if len(names) > 0 {
		placeholders := make([]byte, 0, 2*len(names))
		for i := range names {
			if i > 0 {
				placeholders = append(placeholders, ',')
			}
			placeholders = append(placeholders, '?')
			args = append(args, names[i])
		}
		q += " AND name IN (" + string(placeholders) + ")"
	}
	q += " ORDER BY name ASC, ts ASC"

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			name string
			ts   int64
			val  float64
		)
		if err := rows.Scan(&name, &ts, &val); err != nil {
			return nil, err
		}
		out.Series[name] = append(out.Series[name], Point{
			Ts:    time.UnixMilli(ts).UTC(),
			Value: val,
		})
	}
	return out, rows.Err()
}
