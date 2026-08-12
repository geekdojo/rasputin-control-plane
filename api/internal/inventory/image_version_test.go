package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// SetImageVersion is the one writer of nodes.image_version that is NOT the
// agent's self-report: the updater reconciling inventory from a terminal update
// outcome (ADR-0005 Decision 4). See the updater's reconcileInventoryVersion.

func TestStore_ConfirmImageVersion(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	n := makeNode("n-ver", proto.RoleCompute, 0)
	n.ImageVersion = "2026.07.0-dev.104" // the version it was MEANT to reach
	if err := s.Insert(ctx, n); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	if err := s.ConfirmImageVersion(ctx, "n-ver", "2026.07.0-dev.101", time.Now().UTC()); err != nil {
		t.Fatalf("ConfirmImageVersion: %v", err)
	}
	got, err := s.Get(ctx, "n-ver")
	if err != nil || got == nil {
		t.Fatalf("Get: %v, %+v", err, got)
	}
	if got.ImageVersion != "2026.07.0-dev.101" {
		t.Errorf("image_version = %q, want the reconciled value", got.ImageVersion)
	}
}

// The reason this is a targeted column write and not a read-modify-Update: a
// full Update overwrites every mutable field, so anything a concurrent
// registration learned between the read and the write would be clobbered. The
// updater knows exactly one fact about the node and must write exactly that.
func TestStore_ConfirmImageVersion_LeavesEveryOtherColumnAlone(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	n := makeNode("n-only", proto.RoleCompute, 0)
	n.Architecture = "arm64"
	n.LANIP = "192.168.1.40"
	n.Storage = &proto.StorageInfo{PersistentTotalBytes: 1 << 30, Growpart: "grown"}
	if err := s.Insert(ctx, n); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	before, _ := s.Get(ctx, "n-only")

	if err := s.ConfirmImageVersion(ctx, "n-only", "2026.08.0", time.Now().UTC()); err != nil {
		t.Fatalf("ConfirmImageVersion: %v", err)
	}
	after, err := s.Get(ctx, "n-only")
	if err != nil || after == nil {
		t.Fatalf("Get: %v, %+v", err, after)
	}
	if after.ImageVersion != "2026.08.0" {
		t.Errorf("image_version = %q, want it changed", after.ImageVersion)
	}
	if after.Architecture != before.Architecture ||
		after.LANIP != before.LANIP ||
		after.Hostname != before.Hostname ||
		after.AgentVersion != before.AgentVersion ||
		after.Role != before.Role ||
		!after.LastSeen.Equal(before.LastSeen) ||
		!after.FirstSeen.Equal(before.FirstSeen) {
		t.Errorf("a column other than image_version moved:\n before %+v\n after  %+v", before, after)
	}
	if after.Storage == nil || *after.Storage != *before.Storage {
		t.Errorf("storage moved: got %+v want %+v", after.Storage, before.Storage)
	}
	if len(after.Capabilities) != len(before.Capabilities) {
		t.Errorf("capabilities moved: got %v want %v", after.Capabilities, before.Capabilities)
	}
}

// An update outcome for a node that is no longer in inventory is a reason to
// log, never a reason to fail the saga — so the caller needs to be able to tell
// "no such node" apart from a real write error.
func TestStore_ConfirmImageVersion_UnknownNodeIsErrNoRows(t *testing.T) {
	err := newStore(t).ConfirmImageVersion(context.Background(), "n-gone", "2026.08.0", time.Now().UTC())
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("ConfirmImageVersion on a missing node = %v, want sql.ErrNoRows", err)
	}
}

// ============================================================================
// image_version_confirmed_at (ADR-0005 Decision 4, second half)
// ============================================================================

func TestStore_ImageVersionConfirmedAt_RoundTrips(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	at := time.Now().UTC().Truncate(time.Millisecond)

	n := makeNode("n-rt", proto.RoleCompute, 0)
	n.ImageVersionConfirmedAt = &at
	if err := s.Insert(ctx, n); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	got, _ := s.Get(ctx, "n-rt")
	if got.ImageVersionConfirmedAt == nil || !got.ImageVersionConfirmedAt.Equal(at) {
		t.Errorf("confirmedAt = %v, want %v", got.ImageVersionConfirmedAt, at)
	}

	// nil round-trips as nil, not as the unix epoch.
	bare := makeNode("n-nil", proto.RoleCompute, 0)
	if err := s.Insert(ctx, bare); err != nil {
		t.Fatalf("Insert bare: %v", err)
	}
	gotBare, _ := s.Get(ctx, "n-nil")
	if gotBare.ImageVersionConfirmedAt != nil {
		t.Errorf("confirmedAt = %v, want nil for a never-confirmed row", gotBare.ImageVersionConfirmedAt)
	}
}

// Unconfirming keeps the version and drops only the confidence — "this is the
// last thing we were told, and we now know not to trust it."
func TestStore_UnconfirmImageVersion_KeepsTheValue(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	at := time.Now().UTC()

	n := makeNode("n-doubt", proto.RoleCompute, 0)
	n.ImageVersion = "2026.07.0-dev.104"
	n.ImageVersionConfirmedAt = &at
	if err := s.Insert(ctx, n); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	if err := s.UnconfirmImageVersion(ctx, "n-doubt"); err != nil {
		t.Fatalf("UnconfirmImageVersion: %v", err)
	}
	got, _ := s.Get(ctx, "n-doubt")
	if got.ImageVersionConfirmedAt != nil {
		t.Error("confirmation should be gone")
	}
	if got.ImageVersion != "2026.07.0-dev.104" {
		t.Errorf("image_version = %q; the last-known value must survive as the operator's clue", got.ImageVersion)
	}
}

func TestStore_UnconfirmImageVersion_UnknownNodeIsErrNoRows(t *testing.T) {
	err := newStore(t).UnconfirmImageVersion(context.Background(), "n-gone")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("UnconfirmImageVersion on a missing node = %v, want sql.ErrNoRows", err)
	}
}

// Reopening the store must NOT re-confirm a row that was deliberately
// unconfirmed. The backfill runs only in the start that first adds the column;
// if it ran every start, a stranded node's doubt would evaporate at the next
// api restart and the honest state would silently revert to the optimistic lie
// this column replaced. This is the test that keeps that property.
func TestStore_ReopenDoesNotResurrectAConfirmation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "inv.db")

	s, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	n := makeNode("n-persist", proto.RoleCompute, 0)
	n.ImageVersion = "2026.07.0-dev.104"
	at := time.Now().UTC()
	n.ImageVersionConfirmedAt = &at
	if err := s.Insert(ctx, n); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if err := s.UnconfirmImageVersion(ctx, "n-persist"); err != nil {
		t.Fatalf("UnconfirmImageVersion: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	got, _ := reopened.Get(ctx, "n-persist")
	if got == nil {
		t.Fatal("row vanished across reopen")
	}
	if got.ImageVersionConfirmedAt != nil {
		t.Error("an api restart must not re-confirm a version an update outcome doubted")
	}
}

// An existing cluster's database has no image_version_confirmed_at column at
// all, and every row in it holds a version that DID come from a registration.
// Those rows are backfilled as confirmed at last_seen — not left unconfirmed —
// because "unconfirmed" has to mean "an update outcome told us to doubt this",
// not "the api was upgraded" or "this node is switched off". A default that
// made every powered-down node poison its component's status would make the
// signal noise within a week.
func TestOpenStore_BackfillsPreExistingRowsAsConfirmed(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")

	// The nodes table exactly as it shipped before this column existed.
	const oldSchema = `
CREATE TABLE nodes (
    id            TEXT PRIMARY KEY,
    role          TEXT NOT NULL,
    hostname      TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    image_version TEXT NOT NULL DEFAULT '',
    architecture  TEXT NOT NULL DEFAULT '',
    lan_ip        TEXT NOT NULL DEFAULT '',
    capabilities  TEXT NOT NULL DEFAULT '[]',
    metadata      TEXT NOT NULL DEFAULT '{}',
    storage       TEXT NOT NULL DEFAULT '',
    first_seen    INTEGER NOT NULL,
    last_seen     INTEGER NOT NULL
);`
	db, err := dbutil.Open(ctx, path, oldSchema, "inventory-old")
	if err != nil {
		t.Fatalf("open old db: %v", err)
	}
	lastSeen := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Millisecond)
	if _, err := db.ExecContext(ctx, `
        INSERT INTO nodes (id, role, hostname, image_version, first_seen, last_seen)
        VALUES ('n-old', 'compute', 'n-old.test', '2026.07.0-dev.101', ?, ?)`,
		lastSeen.Add(-time.Hour).UnixMilli(), lastSeen.UnixMilli()); err != nil {
		t.Fatalf("seed old row: %v", err)
	}
	// A row that never reported a version has nothing to confirm.
	if _, err := db.ExecContext(ctx, `
        INSERT INTO nodes (id, role, hostname, image_version, first_seen, last_seen)
        VALUES ('n-blank', 'compute', 'n-blank.test', '', ?, ?)`,
		lastSeen.UnixMilli(), lastSeen.UnixMilli()); err != nil {
		t.Fatalf("seed blank row: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close old db: %v", err)
	}

	s, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatalf("OpenStore (migrating): %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	got, _ := s.Get(ctx, "n-old")
	if got == nil || got.ImageVersionConfirmedAt == nil {
		t.Fatalf("pre-existing row was not backfilled: %+v", got)
	}
	if !got.ImageVersionConfirmedAt.Equal(lastSeen) {
		t.Errorf("confirmedAt = %v, want last_seen %v", got.ImageVersionConfirmedAt, lastSeen)
	}

	blank, _ := s.Get(ctx, "n-blank")
	if blank == nil || blank.ImageVersionConfirmedAt != nil {
		t.Errorf("a row with no version has nothing to confirm: %+v", blank)
	}
}

// A registration IS a confirmation — the agent read the version off the rootfs
// it is running and is alive enough to say so. This is what makes an
// unconfirmed row self-healing: any node that comes back clears its own doubt,
// and the ones that never do are exactly the ones whose version should stop
// reading as agreed (ADR-0005 Decision 4).
func TestService_ReRegistrationReConfirmsADoubtedVersion(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)
	svc := NewService(store, nc)
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(svc.Stop)

	const nodeID = "n-heal"
	reg, _ := json.Marshal(proto.NodeRegisteredEvt{
		NodeID: nodeID, Role: proto.RoleCompute, Hostname: "heal.test",
		ImageVersion: "2026.07.0-dev.104", Ts: time.Now().UTC(),
	})
	if err := nc.Publish(proto.NodeRegisteredSubject(nodeID), reg); err != nil {
		t.Fatalf("publish reg: %v", err)
	}
	_ = nc.Flush()
	waitForConfirmed(t, store, nodeID, true, "first registration must confirm the version")

	// An update outcome doubts it...
	if err := store.UnconfirmImageVersion(ctx, nodeID); err != nil {
		t.Fatalf("UnconfirmImageVersion: %v", err)
	}

	// ...and the node coming back clears its own doubt.
	if err := nc.Publish(proto.NodeRegisteredSubject(nodeID), reg); err != nil {
		t.Fatalf("re-publish reg: %v", err)
	}
	_ = nc.Flush()
	waitForConfirmed(t, store, nodeID, true, "a node that re-registers re-confirms its own version")
}

func waitForConfirmed(t *testing.T, store *Store, nodeID string, want bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, _ := store.Get(context.Background(), nodeID)
		if n != nil && (n.ImageVersionConfirmedAt != nil) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s (confirmed != %v after 2s)", msg, want)
}
