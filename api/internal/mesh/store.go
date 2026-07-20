package mesh

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
)

// Store is the SQLite-backed ledger for mesh intents, tailnet state, and
// device cache.
type Store struct {
	db *sql.DB
}

func OpenStore(ctx context.Context, path string) (*Store, error) {
	db, err := dbutil.Open(ctx, path, schema, "mesh")
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func ms(t time.Time) int64     { return t.UnixMilli() }
func fromMs(v int64) time.Time { return time.UnixMilli(v).UTC() }

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ----- Intents ------------------------------------------------------------

func (s *Store) CreateIntent(ctx context.Context, i *Intent) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO mesh_intents (id, kind, name, enabled, spec, hs_id, hs_value, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		i.ID, i.Kind, i.Name, boolToInt(i.Enabled), string(i.Spec),
		i.HSID, i.HSValue, ms(i.CreatedAt), ms(i.UpdatedAt))
	return err
}

// SetIntentHSRef writes back the Headscale id + plaintext value (e.g. the
// preauth key string) once the apply step resolves them.
func (s *Store) SetIntentHSRef(ctx context.Context, id, hsID, hsValue string) error {
	_, err := s.db.ExecContext(ctx, `
        UPDATE mesh_intents SET hs_id = ?, hs_value = ?, updated_at = ?
        WHERE id = ?`, hsID, hsValue, ms(time.Now().UTC()), id)
	return err
}

func (s *Store) DeleteIntent(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM mesh_intents WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// UpdateIntent rewrites the mutable columns (name, enabled, spec, updated_at)
// for an existing intent. Hs_id / hs_value are NOT touched here — Headscale's
// view of a key is bound at mint and stays put even when the user renames the
// intent or toggles its enabled flag locally. Returns sql.ErrNoRows if the id
// doesn't exist.
func (s *Store) UpdateIntent(ctx context.Context, i *Intent) error {
	res, err := s.db.ExecContext(ctx, `
        UPDATE mesh_intents
        SET name = ?, enabled = ?, spec = ?, updated_at = ?
        WHERE id = ?`,
		i.Name, boolToInt(i.Enabled), string(i.Spec), ms(i.UpdatedAt), i.ID)
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
        SELECT id, kind, name, enabled, spec, hs_id, hs_value, created_at, updated_at
        FROM mesh_intents WHERE id = ?`, id)
	return scanIntent(row.Scan)
}

// ListIntents returns every intent ordered by created_at so Compile produces
// deterministic hashes.
func (s *Store) ListIntents(ctx context.Context) ([]*Intent, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, kind, name, enabled, spec, hs_id, hs_value, created_at, updated_at
        FROM mesh_intents ORDER BY created_at ASC, id ASC`)
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

// ListIntentsByKind filters to one kind (e.g. all preauth_key intents for
// the UI's keys table).
func (s *Store) ListIntentsByKind(ctx context.Context, kind string) ([]*Intent, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, kind, name, enabled, spec, hs_id, hs_value, created_at, updated_at
        FROM mesh_intents WHERE kind = ? ORDER BY created_at DESC, id ASC`, kind)
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
	if err := scan(&i.ID, &i.Kind, &i.Name, &enabled, &spec, &i.HSID, &i.HSValue,
		&createdAt, &updatedAt); err != nil {
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

// ----- State --------------------------------------------------------------

func (s *Store) GetState(ctx context.Context) (*MeshState, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT intent_hash, observed_hash, last_applied, last_reconciled
        FROM mesh_state WHERE id = 1`)
	var (
		ms_            MeshState
		lastApplied    sql.NullInt64
		lastReconciled sql.NullInt64
	)
	if err := row.Scan(&ms_.IntentHash, &ms_.ObservedHash, &lastApplied, &lastReconciled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &MeshState{}, nil
		}
		return nil, err
	}
	if lastApplied.Valid {
		t := fromMs(lastApplied.Int64)
		ms_.LastApplied = &t
	}
	if lastReconciled.Valid {
		t := fromMs(lastReconciled.Int64)
		ms_.LastReconciled = &t
	}
	// Canonicalize a never-applied intent_hash ("") to the empty-compile
	// hash before comparing — same fresh-install fix as the firewall
	// store (see firewall/store.go GetNodeState, found 2026-06-12).
	effectiveIntent := ms_.IntentHash
	if effectiveIntent == "" {
		if _, h, err := Compile(nil); err == nil {
			effectiveIntent = h
		}
	}
	// Drift requires a prior apply by definition (same refinement as the
	// firewall store, 2026-06-12): a never-applied tailnet shows PENDING,
	// not drift. Reserve drift for post-apply divergence.
	ms_.Drift = ms_.LastApplied != nil && ms_.ObservedHash != "" && ms_.ObservedHash != effectiveIntent
	return &ms_, nil
}

// UpdateAfterApply records intent_hash and last_applied; clears drift by
// setting observed_hash = intent_hash (the next reconcile re-verifies).
func (s *Store) UpdateAfterApply(ctx context.Context, intentHash string, ts time.Time) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO mesh_state (id, intent_hash, observed_hash, last_applied)
        VALUES (1, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            intent_hash = excluded.intent_hash,
            observed_hash = excluded.observed_hash,
            last_applied = excluded.last_applied`,
		intentHash, intentHash, ms(ts))
	return err
}

// UpdateAfterReconcile records the observed hash from the live Headscale
// state. The drift bool is computed in GetState from intent_hash vs
// observed_hash; we don't store it.
func (s *Store) UpdateAfterReconcile(ctx context.Context, observedHash string, ts time.Time) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO mesh_state (id, intent_hash, observed_hash, last_reconciled)
        VALUES (1, '', ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            observed_hash = excluded.observed_hash,
            last_reconciled = excluded.last_reconciled`,
		observedHash, ms(ts))
	return err
}

// ----- Devices ------------------------------------------------------------

func (s *Store) UpsertDevice(ctx context.Context, d *Device) error {
	tags, _ := json.Marshal(d.Tags)
	routes, _ := json.Marshal(d.AdvertisedRoutes)
	now := ms(time.Now().UTC())
	if d.FirstSeen.IsZero() {
		d.FirstSeen = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO mesh_devices (hs_id, user, hostname, tailnet_ip, tags, advertised_routes,
            rasputin_node_id, kind, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(hs_id) DO UPDATE SET
            user = excluded.user,
            hostname = excluded.hostname,
            tailnet_ip = excluded.tailnet_ip,
            tags = excluded.tags,
            advertised_routes = excluded.advertised_routes,
            rasputin_node_id = excluded.rasputin_node_id,
            kind = excluded.kind,
            last_seen = excluded.last_seen`,
		d.HSID, d.User, d.Hostname, d.TailnetIP, string(tags), string(routes),
		d.RasputinNodeID, d.Kind, ms(d.FirstSeen), now)
	return err
}

func (s *Store) ListDevices(ctx context.Context) ([]*Device, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT hs_id, user, hostname, tailnet_ip, tags, advertised_routes,
               rasputin_node_id, kind, first_seen, last_seen
        FROM mesh_devices ORDER BY first_seen ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Device
	for rows.Next() {
		var (
			d            Device
			tags, routes string
			firstSeen    int64
			lastSeen     int64
		)
		if err := rows.Scan(&d.HSID, &d.User, &d.Hostname, &d.TailnetIP, &tags, &routes,
			&d.RasputinNodeID, &d.Kind, &firstSeen, &lastSeen); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(tags), &d.Tags)
		_ = json.Unmarshal([]byte(routes), &d.AdvertisedRoutes)
		d.FirstSeen = fromMs(firstSeen)
		d.LastSeen = fromMs(lastSeen)
		out = append(out, &d)
	}
	return out, rows.Err()
}

// GetDeviceByRasputinNodeID returns the cached mesh device whose
// rasputin_node_id matches nodeID, or (nil, nil) if the node is not
// enrolled. Used by the node-removal cascade to find the hs_id to pass
// to Headscale.DeleteNode without making the caller list all devices.
func (s *Store) GetDeviceByRasputinNodeID(ctx context.Context, nodeID string) (*Device, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT hs_id, user, hostname, tailnet_ip, tags, advertised_routes,
               rasputin_node_id, kind, first_seen, last_seen
        FROM mesh_devices WHERE rasputin_node_id = ? LIMIT 1`, nodeID)
	var (
		d            Device
		tags, routes string
		firstSeen    int64
		lastSeen     int64
	)
	if err := row.Scan(&d.HSID, &d.User, &d.Hostname, &d.TailnetIP, &tags, &routes,
		&d.RasputinNodeID, &d.Kind, &firstSeen, &lastSeen); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	_ = json.Unmarshal([]byte(tags), &d.Tags)
	_ = json.Unmarshal([]byte(routes), &d.AdvertisedRoutes)
	d.FirstSeen = fromMs(firstSeen)
	d.LastSeen = fromMs(lastSeen)
	return &d, nil
}

func (s *Store) DeleteDevice(ctx context.Context, hsID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM mesh_devices WHERE hs_id = ?`, hsID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
