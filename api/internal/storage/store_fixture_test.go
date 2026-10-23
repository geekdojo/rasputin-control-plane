package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
)

// Store fixtures for #765's tests: a store data tree, the seal files #803
// writes and a store CA pair, each with bytes a test can find again.

const (
	fixtureKeyID  = "rasputin-11111111-1111-4111-8111-111111111111"
	fixtureKeyID2 = "rasputin-22222222-2222-4222-8222-222222222222"
	fixtureBaoVer = "2.7.1"
	// fixtureDataCanary is in a store data file, for the no-content scans.
	fixtureDataCanary = "STORE-DATA-CANARY-7f3a"
)

// fixtureSealKey is a 32-byte seal key whose text a scan can find.
func fixtureSealKey(tag string) []byte {
	k := []byte(("SEALKEY-" + tag + strings.Repeat("x", 32))[:32])
	return k
}

// sealFragment is the Clean fragment #803 writes, naming keyID.
func sealFragment(keyID string) string {
	return "seal \"static\" {\n  current_key_id = \"" + keyID + "\"\n  current_key    = \"file:///run/credentials/openbao.service/seal-key\"\n}\n"
}

// writeSealFixture writes seal-key and seal.hcl in dir.
func writeSealFixture(t *testing.T, dir, keyID string, key []byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, storeSealKeyFileName), key, 0o600); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, storeSealFragmentName), sealFragment(keyID))
}

// fixtureStoreCAKey is the store CA private key's fixture text.
const fixtureStoreCAKey = "-----BEGIN PRIVATE KEY-----\nSTORE-CA-KEY-MATERIAL\n-----END PRIVATE KEY-----\n"

// writeStoreCAFixture writes store-ca.{key,pem} in trustDir.
func writeStoreCAFixture(t *testing.T, trustDir string) {
	t.Helper()
	if err := os.MkdirAll(trustDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(trustDir, tlsca.StoreKeyFile), fixtureStoreCAKey)
	writeTestFile(t, filepath.Join(trustDir, tlsca.StoreCertFile), "-----BEGIN CERTIFICATE-----\nSTORE-CA-CERT\n-----END CERTIFICATE-----\n")
}

// writeStoreDataFixture writes a nested store data tree in dir and returns
// each file's archive path and bytes.
func writeStoreDataFixture(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{
		"000001.log":                 []byte("pebble log " + fixtureDataCanary),
		"MANIFEST-000001":            []byte("pebble manifest"),
		"sub/dir/OPTIONS-000003":     []byte("pebble options"),
		"marker.format-version.0001": []byte("013"),
	}
	out := map[string][]byte{}
	for rel, b := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		out[storeDataArchivePrefix+rel] = b
	}
	return out
}

// storeSources fills src's store fields under root and writes every store
// file; it returns src.
func storeSources(t *testing.T, root string, src IdentitySources) IdentitySources {
	t.Helper()
	src.StoreDataDir = filepath.Join(root, "openbao")
	src.SealDir = filepath.Join(root, "openbao-seal")
	writeStoreDataFixture(t, src.StoreDataDir)
	writeSealFixture(t, src.SealDir, fixtureKeyID, fixtureSealKey("K1"))
	writeStoreCAFixture(t, src.TrustDir)
	return src
}

// stageStoreFixture writes the cold copy of src's store data to a temp file,
// as snapshot_store stages it, and returns the capture.
func stageStoreFixture(t *testing.T, src IdentitySources, keyID string) *StoreCapture {
	t.Helper()
	var buf bytes.Buffer
	if _, _, err := writeStoreCapture(&buf, src.StoreDataDir, fixtureBaoVer); err != nil {
		t.Fatalf("writeStoreCapture: %v", err)
	}
	p := filepath.Join(t.TempDir(), "gen.store")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return &StoreCapture{Path: p, KeyID: keyID}
}
