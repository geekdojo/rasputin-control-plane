package storage

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-977-14 (geekdojo/geekdojo-brain#977): the identity CA is not an archive
// member. With identity-ca.{pem,key} in the trust dir beside the controlplane
// and store CA files, an assembled archive names no identity-ca path in its
// manifest or its tar, and still carries the controlplane and store CA
// members.
func TestAssembleCarriesNoIdentityCA(t *testing.T) {
	dir := t.TempDir()
	src := storeSources(t, dir, IdentitySources{TrustDir: filepath.Join(dir, "trust")})
	writeTestFile(t, filepath.Join(src.TrustDir, tlsca.ControlplaneKeyFile), "CONTROLPLANE-CA-KEY")
	writeTestFile(t, filepath.Join(src.TrustDir, tlsca.ControlplaneCertFile), "CONTROLPLANE-CA-CERT")
	writeTestFile(t, filepath.Join(src.TrustDir, tlsca.IdentityKeyFile), "IDENTITY-CA-KEY")
	writeTestFile(t, filepath.Join(src.TrustDir, tlsca.IdentityCertFile), "IDENTITY-CA-CERT")
	snap := filepath.Join(dir, "snap.db")
	writeTestFile(t, snap, "SNAP")

	var buf bytes.Buffer
	m, err := Assemble(&buf, AssembleOptions{
		Sources: src, SnapshotPath: snap, GenerationID: "g1", Scope: proto.BackupScopeFull,
		StoreCapture: stageStoreFixture(t, src, fixtureKeyID),
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	members := map[string]bool{}
	for _, e := range m.Entries {
		members[e.Path] = true
	}
	tr := tar.NewReader(&buf)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		members[hdr.Name] = true
	}
	for p := range members {
		if strings.Contains(p, "identity-ca") {
			t.Errorf("archive member %s is the identity CA", p)
		}
	}
	for _, want := range []string{"trust/mesh-ca.key", "trust/mesh-ca.pem", "trust/store-ca.key", "trust/store-ca.pem"} {
		if !members[want] {
			t.Errorf("archive lacks %s", want)
		}
	}
}
