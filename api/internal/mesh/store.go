package mesh

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
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
	applyMigrations(ctx, db)
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// applyMigrations runs each statement in migrations, tolerating the
// already-applied case. Mirrors inventory.applyMigrations: CREATE TABLE IF NOT
// EXISTS cannot add a column to a database that predates it, so column
// additions live here and are expected to fail with "duplicate column name" on
// every open after the first.
func applyMigrations(ctx context.Context, db *sql.DB) {
	for _, stmt := range migrations {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			msg := err.Error()
			if strings.Contains(msg, "duplicate column name") ||
				strings.Contains(msg, "already exists") {
				continue
			}
			log.Printf("mesh: migration %q: %v", stmt, err)
		}
	}
}

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
        INSERT INTO mesh_intents (id, kind, name, enabled, spec, hs_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		i.ID, i.Kind, i.Name, boolToInt(i.Enabled), string(i.Spec),
		i.HSID, ms(i.CreatedAt), ms(i.UpdatedAt))
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
        SELECT id, kind, name, enabled, spec, hs_id, created_at, updated_at
        FROM mesh_intents WHERE id = ?`, id)
	return scanIntent(row.Scan)
}

// ListIntents returns every intent ordered by created_at so Compile produces
// deterministic hashes.
func (s *Store) ListIntents(ctx context.Context) ([]*Intent, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, kind, name, enabled, spec, hs_id, created_at, updated_at
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
        SELECT id, kind, name, enabled, spec, hs_id, created_at, updated_at
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
	if err := scan(&i.ID, &i.Kind, &i.Name, &enabled, &spec, &i.HSID,
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

// execer is what upsertDevice needs from *sql.DB or *sql.Tx.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// UpsertDevice records Headscale's view of a device. It does not create a
// binding: a second device carrying a node id that another device is bound
// to is refused by the unique index (ErrDuplicateBinding); only BindDevice,
// called by the enrol, moves a binding.
func (s *Store) UpsertDevice(ctx context.Context, d *Device) error {
	return asDuplicateBinding(upsertDevice(ctx, s.db, d), d.RasputinNodeID)
}

func upsertDevice(ctx context.Context, db execer, d *Device) error {
	tags, _ := json.Marshal(d.Tags)
	routes, _ := json.Marshal(d.AdvertisedRoutes)
	if d.FirstSeen.IsZero() {
		d.FirstSeen = time.Now().UTC()
	}
	// last_seen is the DEVICE's last-seen as Headscale reports it, not the
	// time of this reconcile. It used to be written as time.Now() regardless of
	// what the caller passed, which made every device — including ones that had
	// been off the tailnet for weeks — read as seen moments ago. That is the
	// same defect shape as the count this field exists to fix
	// (geekdojo/geekdojo-brain#202): a name asserting something nobody checked.
	// Fall back to now only when the caller genuinely has no value.
	lastSeen := d.LastSeen
	if lastSeen.IsZero() {
		lastSeen = time.Now().UTC()
	}
	_, err := db.ExecContext(ctx, `
        INSERT INTO mesh_devices (hs_id, user, hostname, tailnet_ip, tags, advertised_routes,
            rasputin_node_id, kind, first_seen, last_seen, online)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(hs_id) DO UPDATE SET
            user = excluded.user,
            hostname = excluded.hostname,
            tailnet_ip = excluded.tailnet_ip,
            tags = excluded.tags,
            advertised_routes = excluded.advertised_routes,
            rasputin_node_id = excluded.rasputin_node_id,
            kind = excluded.kind,
            last_seen = excluded.last_seen,
            online = excluded.online`,
		d.HSID, d.User, d.Hostname, d.TailnetIP, string(tags), string(routes),
		d.RasputinNodeID, d.Kind, ms(d.FirstSeen), ms(lastSeen), boolToInt(d.Online))
	return err
}

// ErrDuplicateBinding is wrapped by every refusal caused by more than one
// device bound to the same node.
var ErrDuplicateBinding = errors.New("more than one mesh device is bound to the node")

// DuplicateBindingError names the node and the devices bound to it.
type DuplicateBindingError struct {
	NodeID string
	HSIDs  []string
}

func (e *DuplicateBindingError) Error() string {
	return fmt.Sprintf("mesh: node %s is bound to %d devices (%s); refusing to pick one",
		e.NodeID, len(e.HSIDs), strings.Join(e.HSIDs, ", "))
}

func (e *DuplicateBindingError) Unwrap() error { return ErrDuplicateBinding }

// asDuplicateBinding turns the unique-index violation into ErrDuplicateBinding.
func asDuplicateBinding(err error, nodeID string) error {
	// SQLite names the indexed column: "UNIQUE constraint failed:
	// mesh_devices.rasputin_node_id".
	if err != nil && strings.Contains(err.Error(), "mesh_devices.rasputin_node_id") {
		return fmt.Errorf("mesh: record device for node %s: %w", nodeID, &DuplicateBindingError{NodeID: nodeID})
	}
	return err
}

// BindDevice records d as the one device bound to d.RasputinNodeID, on the
// authority of enrolJobID — the mesh.enroll_node job whose agent reported
// d.HSID. Any other device bound to that node is unbound in the same
// transaction (a re-registered node's earlier device); their ids are
// returned so the caller can say so.
func (s *Store) BindDevice(ctx context.Context, d *Device, enrolJobID string) (unbound []string, err error) {
	if d.RasputinNodeID == "" || d.HSID == "" || enrolJobID == "" {
		return nil, errors.New("mesh: BindDevice needs a node id, a device id and the enrol job id")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT hs_id FROM mesh_devices WHERE rasputin_node_id = ? AND hs_id != ?`, d.RasputinNodeID, d.HSID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		unbound = append(unbound, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE mesh_devices SET rasputin_node_id = '', enrol_job_id = ''
        WHERE rasputin_node_id = ? AND hs_id != ?`, d.RasputinNodeID, d.HSID); err != nil {
		return nil, err
	}
	if err := upsertDevice(ctx, tx, d); err != nil {
		return nil, asDuplicateBinding(err, d.RasputinNodeID)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE mesh_devices SET enrol_job_id = ? WHERE hs_id = ?`, enrolJobID, d.HSID); err != nil {
		return nil, err
	}
	return unbound, tx.Commit()
}

// UnbindDevice clears a device's binding (it stays listed, bound to no node).
func (s *Store) UnbindDevice(ctx context.Context, hsID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE mesh_devices SET rasputin_node_id = '', enrol_job_id = '' WHERE hs_id = ?`, hsID)
	return err
}

// setEnrolJob records the enrol job that proves an existing binding.
func (s *Store) setEnrolJob(ctx context.Context, hsID, jobID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE mesh_devices SET enrol_job_id = ? WHERE hs_id = ?`, jobID, hsID)
	return err
}

// ensureBindingIndex creates the one-device-per-node index.
func (s *Store) ensureBindingIndex(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, bindingIndexDDL)
	return err
}

const deviceColumns = `hs_id, user, hostname, tailnet_ip, tags, advertised_routes,
               rasputin_node_id, enrol_job_id, kind, first_seen, last_seen, online`

func scanDevice(scan func(...any) error) (*Device, error) {
	var (
		d            Device
		tags, routes string
		firstSeen    int64
		lastSeen     int64
		online       int
	)
	if err := scan(&d.HSID, &d.User, &d.Hostname, &d.TailnetIP, &tags, &routes,
		&d.RasputinNodeID, &d.EnrolJobID, &d.Kind, &firstSeen, &lastSeen, &online); err != nil {
		return nil, err
	}
	d.Online = online != 0
	_ = json.Unmarshal([]byte(tags), &d.Tags)
	_ = json.Unmarshal([]byte(routes), &d.AdvertisedRoutes)
	d.FirstSeen = fromMs(firstSeen)
	d.LastSeen = fromMs(lastSeen)
	return &d, nil
}

func (s *Store) ListDevices(ctx context.Context) ([]*Device, error) {
	return s.queryDevices(ctx, `SELECT `+deviceColumns+` FROM mesh_devices ORDER BY first_seen ASC`)
}

func (s *Store) queryDevices(ctx context.Context, q string, args ...any) ([]*Device, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Device
	for rows.Next() {
		d, err := scanDevice(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetDeviceByRasputinNodeID returns the one mesh device bound to nodeID, or
// (nil, nil) if the node is not enrolled. More than one bound device is a
// *DuplicateBindingError, never a silent pick. (Node removal does not use
// this: it removes every bound device, see DevicesBoundTo.)
func (s *Store) GetDeviceByRasputinNodeID(ctx context.Context, nodeID string) (*Device, error) {
	if nodeID == "" {
		return nil, nil
	}
	devs, err := s.queryDevices(ctx, `SELECT `+deviceColumns+` FROM mesh_devices WHERE rasputin_node_id = ? ORDER BY hs_id`, nodeID)
	if err != nil {
		return nil, err
	}
	switch len(devs) {
	case 0:
		return nil, nil
	case 1:
		return devs[0], nil
	}
	e := &DuplicateBindingError{NodeID: nodeID}
	for _, d := range devs {
		e.HSIDs = append(e.HSIDs, d.HSID)
	}
	return nil, e
}

// DevicesBoundTo returns every device bound to nodeID (normally zero or
// one). For the node-removal cascade, which removes them all.
func (s *Store) DevicesBoundTo(ctx context.Context, nodeID string) ([]*Device, error) {
	if nodeID == "" {
		return nil, nil
	}
	return s.queryDevices(ctx, `SELECT `+deviceColumns+` FROM mesh_devices WHERE rasputin_node_id = ? ORDER BY hs_id`, nodeID)
}

// BoundDevices groups bound devices by node. dup lists every node bound to
// more than one device, each with its device ids; readers refuse those
// nodes rather than pick a device.
func BoundDevices(devices []*Device) (one map[string]*Device, dup map[string][]string) {
	byNode := map[string][]*Device{}
	for _, d := range devices {
		if d != nil && d.RasputinNodeID != "" {
			byNode[d.RasputinNodeID] = append(byNode[d.RasputinNodeID], d)
		}
	}
	one = make(map[string]*Device, len(byNode))
	dup = map[string][]string{}
	for node, ds := range byNode {
		if len(ds) == 1 {
			one[node] = ds[0]
			continue
		}
		for _, d := range ds {
			dup[node] = append(dup[node], d.HSID)
		}
		sort.Strings(dup[node])
	}
	return one, dup
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
