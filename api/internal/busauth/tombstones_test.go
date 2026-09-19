package busauth

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

func tombPath(t *testing.T) string {
	return filepath.Join(t.TempDir(), "bus", TombstoneFileName)
}

func storeWithTombstones(t *testing.T, path string) *Store {
	t.Helper()
	s := newTokenStore(t)
	if _, _, err := s.UseTombstoneFile(context.Background(), path); err != nil {
		t.Fatalf("UseTombstoneFile: %v", err)
	}
	return s
}

func readTombs(t *testing.T, path string) map[string]Tombstone {
	t.Helper()
	set, err := ReadTombstoneFile(path)
	if err != nil {
		t.Fatalf("ReadTombstoneFile: %v", err)
	}
	return set
}

// Every revocation writes a tombstone — an operator revoke, node removal, and
// the api's own rotation of its agent token — owner-only, beside the preseed.
func TestTombstones_EveryRevocationWritesOne(t *testing.T) {
	ctx := context.Background()
	path := tombPath(t)
	s := storeWithTombstones(t, path)

	_, a, _ := s.MintBound(ctx, "compute", "a", proto.RoleCompute)
	_, b1, _ := s.MintBound(ctx, "compute", "b", proto.RoleCompute)
	_, b2, _ := s.MintBound(ctx, "compute", "b", proto.RoleCompute)
	if _, err := s.Revoke(ctx, a); err != nil {
		t.Fatal(err)
	}
	if n, _, err := s.RevokeByNodeID(ctx, "b"); err != nil || n != 2 {
		t.Fatalf("RevokeByNodeID = (%d, %v), want 2", n, err)
	}
	agentFile := agentTokenPath(t)
	if _, err := s.EnsureAgentToken(ctx, agentFile, "cp-1"); err != nil {
		t.Fatal(err)
	}
	oldAgent := HashToken(readTokenFile(t, agentFile))
	if err := os.Remove(agentFile); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnsureAgentToken(ctx, agentFile, "cp-1"); err != nil { // rotates, revoking the old one
		t.Fatal(err)
	}

	set := readTombs(t, path)
	for id, node := range map[string]string{a: "a", b1: "b", b2: "b", oldAgent: "cp-1"} {
		tb, ok := set[id]
		if !ok {
			t.Errorf("no tombstone for %s's revoked token", node)
			continue
		}
		if tb.NodeID != node || tb.RevokedAt.IsZero() {
			t.Errorf("tombstone %+v, want node %s and a time", tb, node)
		}
	}
	if len(set) != 4 {
		t.Errorf("%d tombstones, want 4", len(set))
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("tombstone file mode %#o, want 0600", fi.Mode().Perm())
	}
}

// A lost database: the store starts empty, the preseed is reloaded as on every
// boot, and a matched-set token revoked before the loss stays revoked; the
// others load.
func TestTombstones_PreloadSkipsATombstonedHashAfterDatabaseLoss(t *testing.T) {
	ctx := context.Background()
	path := tombPath(t)
	ptKeep, hKeep, _ := GenerateToken()
	ptGone, hGone, _ := GenerateToken()
	preseed := []PreseedToken{
		{Hash: hKeep, NodeID: "keep", Label: "compute"},
		{Hash: hGone, NodeID: "gone", Label: "compute"},
	}

	s := storeWithTombstones(t, path)
	if n, err := s.PreloadHashes(ctx, preseed); err != nil || n != 2 {
		t.Fatalf("preload = (%d, %v)", n, err)
	}
	if _, err := s.Revoke(ctx, hGone); err != nil {
		t.Fatal(err)
	}

	// The database is gone; the bus directory is not.
	fresh := storeWithTombstones(t, path)
	n, err := fresh.PreloadHashes(ctx, preseed)
	if err != nil || n != 1 {
		t.Fatalf("preload after the loss = (%d, %v), want (1, nil)", n, err)
	}
	if ok, _ := fresh.Validate(ctx, ptGone, "gone"); ok {
		t.Error("a revoked matched-set token came back after the database was lost")
	}
	if ok, _ := fresh.Validate(ctx, ptKeep, "keep"); !ok {
		t.Error("an unrevoked matched-set token was not reloaded")
	}
}

// UseTombstoneFile reconciles both ways: a tombstoned hash still live in the
// database is revoked there, and a revoked row missing from the file (a
// revocation from before tombstones existed) is added to it.
func TestTombstones_UseReconcilesFileAndDatabase(t *testing.T) {
	ctx := context.Background()
	path := tombPath(t)
	s := newTokenStore(t)
	ptLive, hLive, _ := s.MintBound(ctx, "compute", "n1", proto.RoleCompute)
	_, hOld, _ := s.MintBound(ctx, "compute", "n2", proto.RoleCompute)
	if _, err := s.Revoke(ctx, hOld); err != nil { // before any file: database only
		t.Fatal(err)
	}
	if err := writeTombstoneFile(path, map[string]Tombstone{hLive: {Hash: hLive, NodeID: "n1", RevokedAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}

	added, reapplied, err := s.UseTombstoneFile(ctx, path)
	if err != nil || added != 1 || reapplied != 1 {
		t.Fatalf("UseTombstoneFile = (%d, %d, %v), want (1, 1, nil)", added, reapplied, err)
	}
	if ok, _ := s.Validate(ctx, ptLive, "n1"); ok {
		t.Error("a tombstoned token still validates")
	}
	set := readTombs(t, path)
	if _, ok := set[hOld]; !ok || len(set) != 2 {
		t.Errorf("file = %v, want both revocations", set)
	}
	// Idempotent.
	if added, reapplied, err := s.UseTombstoneFile(ctx, path); err != nil || added != 0 || reapplied != 0 {
		t.Errorf("second UseTombstoneFile = (%d, %d, %v), want (0, 0, nil)", added, reapplied, err)
	}
}

// A file that cannot be parsed is an error, and it is never overwritten: it
// may be the only record of a revocation.
func TestTombstones_UnreadableFileIsRefusedAndKept(t *testing.T) {
	ctx := context.Background()
	path := tombPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"not json", `{"version":2,"tombstones":[]}`, `{"version":1,"tombstones":[{"nodeId":"x"}]}`} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		s := newTokenStore(t)
		if _, _, err := s.UseTombstoneFile(ctx, path); err == nil {
			t.Errorf("UseTombstoneFile(%q) succeeded; want an error", body)
		}
		_, id, _ := s.MintBound(ctx, "compute", "n1", proto.RoleCompute)
		if _, err := s.Revoke(ctx, id); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(path); string(got) != body {
			t.Errorf("the unreadable file was overwritten: %q", got)
		}
	}
}

func TestMergeTombstoneFiles_Unions(t *testing.T) {
	dir := t.TempDir()
	live, archived := filepath.Join(dir, "live.json"), filepath.Join(dir, "archived.json")
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	if err := writeTombstoneFile(live, map[string]Tombstone{
		"aa": {Hash: "aa", NodeID: "a", RevokedAt: t0.Add(time.Hour)},
		"bb": {Hash: "bb", NodeID: "b", RevokedAt: t0},
	}); err != nil {
		t.Fatal(err)
	}
	if err := writeTombstoneFile(archived, map[string]Tombstone{
		"aa": {Hash: "aa", NodeID: "a", RevokedAt: t0}, // the same revoke, recorded earlier
		"cc": {Hash: "cc", NodeID: "c", RevokedAt: t0},
	}); err != nil {
		t.Fatal(err)
	}
	added, err := MergeTombstoneFiles(live, archived)
	if err != nil || added != 1 {
		t.Fatalf("Merge = (%d, %v), want (1, nil)", added, err)
	}
	set := readTombs(t, live)
	if len(set) != 3 || !set["aa"].RevokedAt.Equal(t0) {
		t.Errorf("merged = %+v; want aa, bb, cc with aa at its earliest time", set)
	}
	// Merging into a missing file creates it.
	fresh := filepath.Join(dir, "sub", "fresh.json")
	if added, err := MergeTombstoneFiles(fresh, archived); err != nil || added != 2 {
		t.Fatalf("Merge into a missing file = (%d, %v), want (2, nil)", added, err)
	}
	// A missing archive side adds nothing.
	if added, err := MergeTombstoneFiles(live, filepath.Join(dir, "absent.json")); err != nil || added != 0 {
		t.Fatalf("Merge from a missing file = (%d, %v), want (0, nil)", added, err)
	}
}
