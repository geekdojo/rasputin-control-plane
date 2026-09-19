package storage

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// oldControlplane is the bus-token state an identity archive captures: a real
// rasputin.db snapshot and the tombstone file beside it.
type oldControlplane struct {
	db, tombstones []byte
	// tokens by name: live (never revoked), revokedBefore (revoked before the
	// archive), revokedAfter (live in the archive, revoked after it was taken).
	live, revokedBefore, revokedAfter string
	revokedAfterID                    string
}

// newOldControlplane mints three tokens on a real store with a tombstone file,
// revokes one, and snapshots the database the way a backup does (VACUUM INTO).
func newOldControlplane(t *testing.T) oldControlplane {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	st, err := busauth.OpenStore(ctx, filepath.Join(dir, "rasputin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	tomb := filepath.Join(dir, "bus", busauth.TombstoneFileName)
	if _, _, err := st.UseTombstoneFile(ctx, tomb); err != nil {
		t.Fatal(err)
	}
	var o oldControlplane
	if o.live, _, err = st.MintBound(ctx, "compute", "n-live", proto.RoleCompute); err != nil {
		t.Fatal(err)
	}
	var beforeID string
	if o.revokedBefore, beforeID, err = st.MintBound(ctx, "compute", "n-before", proto.RoleCompute); err != nil {
		t.Fatal(err)
	}
	if o.revokedAfter, o.revokedAfterID, err = st.MintBound(ctx, "compute", "n-after", proto.RoleCompute); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Revoke(ctx, beforeID); err != nil {
		t.Fatal(err)
	}
	snap := filepath.Join(dir, "snapshot.db")
	raw, err := sql.Open("sqlite", filepath.Join(dir, "rasputin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	if _, err := raw.ExecContext(ctx, `VACUUM INTO ?`, snap); err != nil {
		t.Fatal(err)
	}
	if o.db, err = os.ReadFile(snap); err != nil {
		t.Fatal(err)
	}
	if o.tombstones, err = os.ReadFile(tomb); err != nil {
		t.Fatal(err)
	}
	return o
}

// restoredStore is the next api start after the apply: the store opened on the
// restored database, and the live tombstone file taken into use.
func restoredStore(t *testing.T, dataDir string) *busauth.Store {
	t.Helper()
	st, err := busauth.OpenStore(context.Background(), filepath.Join(dataDir, "rasputin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, _, err := st.UseTombstoneFile(context.Background(), filepath.Join(dataDir, "bus", busauth.TombstoneFileName)); err != nil {
		t.Fatal(err)
	}
	return st
}

func validates(t *testing.T, st *busauth.Store, token, node string) bool {
	t.Helper()
	ok, err := st.Validate(context.Background(), token, node)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// The case restore-unions exists for: a token revoked AFTER the archive was
// taken is live in the archive's database. Restoring that older archive must
// not bring it back, and the archive's own tombstones must survive the
// restore too.
func TestRestoreOfAnOlderArchiveKeepsLaterRevocations(t *testing.T) {
	old := newOldControlplane(t)
	h := newRestoreHarness(t, generationOpts{complete: true, identity: func(fx *identityFixture) {
		fx.db = old.db
		fx.busTombstones = old.tombstones
	}})
	seedFreshInstall(t, h.dataDir)

	// The live controlplane revoked n-after once the archive existed: its
	// tombstone is in the live file, and nowhere in the archive.
	liveTomb := filepath.Join(h.dataDir, "bus", busauth.TombstoneFileName)
	{
		st, err := busauth.OpenStore(context.Background(), filepath.Join(t.TempDir(), "live.db"))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := st.UseTombstoneFile(context.Background(), liveTomb); err != nil {
			t.Fatal(err)
		}
		if _, err := st.PreloadHashes(context.Background(), []busauth.PreseedToken{{Hash: old.revokedAfterID, NodeID: "n-after", Role: proto.RoleCompute}}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Revoke(context.Background(), old.revokedAfterID); err != nil {
			t.Fatal(err)
		}
		_ = st.Close()
	}

	report, err := PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	restoredTomb := false
	for _, e := range report.Restored {
		restoredTomb = restoredTomb || e.Path == "bus/"+busauth.TombstoneFileName
	}
	if !restoredTomb {
		t.Fatalf("the archive's tombstones are not among the restored entries: %+v", report.Restored)
	}
	layout := RestoreLayout{DataDir: h.dataDir, TrustDir: filepath.Join(h.dataDir, "trust"), MeshStateDir: filepath.Join(h.dataDir, "mesh")}
	if _, applied, err := ApplyPendingRestore(layout); err != nil || !applied {
		t.Fatalf("apply: %v applied=%v", err, applied)
	}

	// The live file now holds both revocations: its own and the archive's.
	set, err := busauth.ReadTombstoneFile(liveTomb)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := set[old.revokedAfterID]; !ok {
		t.Error("the live file lost the revocation made after the archive")
	}
	if len(set) != 2 {
		t.Errorf("live file holds %d tombstones, want 2 (the union)", len(set))
	}

	st := restoredStore(t, h.dataDir)
	if validates(t, st, old.revokedAfter, "n-after") {
		t.Error("restoring the older archive un-revoked a token revoked after it was taken")
	}
	if validates(t, st, old.revokedBefore, "n-before") {
		t.Error("the archive's own revocation did not survive the restore")
	}
	if !validates(t, st, old.live, "n-live") {
		t.Error("a token that was never revoked stopped validating")
	}
}

// A reflashed controlplane restoring: no live tombstone file at all. The
// archive's tombstones become the live file, and a preseed carrying a revoked
// matched-set token (firstboot stages it again from the seed) does not bring
// it back.
func TestRestoreOntoAFreshInstallTakesTheArchivesTombstones(t *testing.T) {
	old := newOldControlplane(t)
	h := newRestoreHarness(t, generationOpts{complete: true, identity: func(fx *identityFixture) {
		fx.db = old.db
		fx.busTombstones = old.tombstones
	}})
	seedFreshInstall(t, h.dataDir)
	if _, err := PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes())); err != nil {
		t.Fatal(err)
	}
	layout := RestoreLayout{DataDir: h.dataDir, TrustDir: filepath.Join(h.dataDir, "trust"), MeshStateDir: filepath.Join(h.dataDir, "mesh")}
	if _, applied, err := ApplyPendingRestore(layout); err != nil || !applied {
		t.Fatalf("apply: %v applied=%v", err, applied)
	}
	st := restoredStore(t, h.dataDir)
	if validates(t, st, old.revokedBefore, "n-before") {
		t.Error("a revoked token validates after the restore")
	}
	set, err := busauth.ReadTombstoneFile(filepath.Join(h.dataDir, "bus", busauth.TombstoneFileName))
	if err != nil || len(set) != 1 {
		t.Fatalf("live file after restore: %d tombstones, %v; want the archive's 1", len(set), err)
	}
}

// An archive from a build that wrote no tombstone file restores exactly as
// before, and the live file's revocations are still re-applied to its
// database.
func TestRestoreOfAnArchiveWithoutTombstonesStillAppliesTheLiveOnes(t *testing.T) {
	old := newOldControlplane(t)
	h := newRestoreHarness(t, generationOpts{complete: true, identity: func(fx *identityFixture) {
		fx.db = old.db // no busTombstones
	}})
	seedFreshInstall(t, h.dataDir)
	liveTomb := filepath.Join(h.dataDir, "bus", busauth.TombstoneFileName)
	if err := os.WriteFile(liveTomb, []byte(`{"version":1,"tombstones":[{"hash":"`+old.revokedAfterID+`","nodeId":"n-after","revokedAt":"2026-09-19T00:00:00Z"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareRestore(context.Background(), h.cfg, h.request(h.key.priv.Bytes())); err != nil {
		t.Fatal(err)
	}
	layout := RestoreLayout{DataDir: h.dataDir, TrustDir: filepath.Join(h.dataDir, "trust"), MeshStateDir: filepath.Join(h.dataDir, "mesh")}
	if _, applied, err := ApplyPendingRestore(layout); err != nil || !applied {
		t.Fatalf("apply: %v applied=%v", err, applied)
	}
	st := restoredStore(t, h.dataDir)
	if validates(t, st, old.revokedAfter, "n-after") {
		t.Error("the live tombstone was not re-applied to the restored database")
	}
	if !validates(t, st, old.live, "n-live") {
		t.Error("a token that was never revoked stopped validating")
	}
}
