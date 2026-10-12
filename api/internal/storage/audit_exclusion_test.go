package storage

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-799-25: the secret store's audit log and its rotated copies, sitting in
// the data dir beside the identity set, are never in an archive, and the
// manifest says so (ADR-0010 S11: audit does not survive a restore).
func TestAssembleLeavesOutTheStoreAuditLog(t *testing.T) {
	dataDir := t.TempDir()
	trustDir := filepath.Join(dataDir, "trust")
	for _, d := range []string{"trust", "mesh/headscale", "bus", "openbao-audit"} {
		if err := os.MkdirAll(filepath.Join(dataDir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, filepath.Join(trustDir, "mesh-ca.key"), "MESH-CA-KEY")
	writeTestFile(t, filepath.Join(trustDir, "mesh-ca.pem"), "MESH-CA-PEM")
	writeTestFile(t, filepath.Join(dataDir, "mesh", "headscale", "db.sqlite"), "HEADSCALE")
	writeTestFile(t, filepath.Join(dataDir, "bus", "bus.key"), "BUS-KEY")
	for _, name := range []string{"audit.log", "audit.log.1", "audit.log.2"} {
		writeTestFile(t, filepath.Join(dataDir, "openbao-audit", name), "AUDIT-LINE")
	}
	snap := filepath.Join(dataDir, "snapshot.db")
	writeTestFile(t, snap, "SQLITE-SNAPSHOT-BYTES")

	var buf bytes.Buffer
	m, err := Assemble(&buf, AssembleOptions{
		Sources: IdentitySources{
			TrustDir:     trustDir,
			MeshStateDir: filepath.Join(dataDir, "mesh"),
			BusDir:       filepath.Join(dataDir, "bus"),
		},
		SnapshotPath: snap,
		GenerationID: "20261011T000000Z-test-full",
		ClusterID:    "home1",
		KeyID:        "key-1",
		Scope:        proto.BackupScopeFull,
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	var names []string
	tr := tar.NewReader(&buf)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read archive: %v", err)
		}
		names = append(names, h.Name)
		if strings.HasPrefix(h.Name, "openbao-audit/") || strings.Contains(h.Name, "audit.log") {
			t.Errorf("the archive holds %s", h.Name)
		}
	}
	if !slices.Contains(names, "bus/bus.key") {
		t.Fatalf("the fixture's identity set did not reach the archive (%v), so the check above proves nothing", names)
	}
	want := "the secret store's audit log (`openbao-audit/`) — S11: audit does not survive a restore"
	if !slices.Contains(m.Excluded, want) {
		t.Errorf("manifest Excluded = %q, want it to hold %q", m.Excluded, want)
	}
}
