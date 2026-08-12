package updater

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// This store had NO migration mechanism before the verify-gap columns; every
// schema change so far happened to be expressible as CREATE TABLE IF NOT
// EXISTS. So the migration path itself is new code, and an existing cluster's
// node_updates table is the thing it has to survive.
func TestOpenStore_MigratesAnExistingNodeUpdatesTable(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")

	// node_updates exactly as it shipped before the verify-gap columns.
	const oldSchema = `
CREATE TABLE node_updates (
    job_id          TEXT PRIMARY KEY,
    node_id         TEXT NOT NULL,
    bundle_sha256   TEXT NOT NULL,
    from_slot       TEXT NOT NULL DEFAULT 'unknown',
    to_slot         TEXT NOT NULL DEFAULT 'unknown',
    from_version    TEXT NOT NULL DEFAULT '',
    to_version      TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL,
    started_at      INTEGER NOT NULL,
    finished_at     INTEGER,
    error           TEXT NOT NULL DEFAULT ''
);`
	db, err := dbutil.Open(ctx, path, oldSchema, "updater-old")
	if err != nil {
		t.Fatalf("open old db: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
        INSERT INTO node_updates (job_id, node_id, bundle_sha256, status, started_at, to_version)
        VALUES ('old-job', 'c01', 'sha', 'committed', ?, '2026.07.0-dev.101')`,
		time.Now().UTC().UnixMilli()); err != nil {
		t.Fatalf("seed old row: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatalf("OpenStore (migrating): %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// The pre-existing row must still READ — the failure mode of a column added
	// without updating every scan is that history silently stops loading.
	row, err := s.GetNodeUpdate(ctx, "old-job")
	if err != nil {
		t.Fatalf("pre-existing row must still read: %v", err)
	}
	if row == nil || row.ToVersion != "2026.07.0-dev.101" {
		t.Fatalf("row = %+v, want the seeded history intact", row)
	}
	// Default false, not "degraded": those updates were verified by whatever
	// the contract was at the time. Claiming they were degraded would be
	// inventing history.
	if row.UnverifiedBoot || row.UnverifiedVersion {
		t.Errorf("row = %+v, want a pre-existing update to read as not-degraded", row)
	}

	// And the new writer works against the migrated table.
	if err := s.SetNodeUpdateVerifyGaps(ctx, "old-job", true, false); err != nil {
		t.Fatalf("SetNodeUpdateVerifyGaps: %v", err)
	}
	row, _ = s.GetNodeUpdate(ctx, "old-job")
	if row == nil || !row.UnverifiedBoot || row.UnverifiedVersion {
		t.Errorf("row = %+v, want only the boot gap set", row)
	}
}

// ListNodeUpdates is what the UI History renders, so it has to carry the flags
// too — a degraded row that only shows on the single-row read would be a badge
// nobody ever sees.
func TestListNodeUpdates_CarriesTheVerifyGaps(t *testing.T) {
	ctx := context.Background()
	s := newStoreFixture(t).store
	if err := s.CreateNodeUpdate(ctx, &NodeUpdate{
		JobID: "j", NodeID: "c01", BundleSHA256: "sha",
		FromSlot: proto.SlotA, ToSlot: proto.SlotB,
		Status: NodeUpdateCommitted, StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateNodeUpdate: %v", err)
	}
	if err := s.SetNodeUpdateVerifyGaps(ctx, "j", true, true); err != nil {
		t.Fatalf("SetNodeUpdateVerifyGaps: %v", err)
	}
	rows, err := s.ListNodeUpdates(ctx, "c01", 10)
	if err != nil {
		t.Fatalf("ListNodeUpdates: %v", err)
	}
	if len(rows) != 1 || !rows[0].UnverifiedBoot || !rows[0].UnverifiedVersion {
		t.Errorf("rows = %+v, want the gaps visible in the list the UI renders", rows)
	}
}
