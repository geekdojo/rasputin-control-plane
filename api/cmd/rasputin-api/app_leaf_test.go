package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const leafTestAppID = "01J8Z3K5QW6X7Y8Z9A0B1C2D3E"

// leafFixture lays out a data dir with a leaf root holding two apps' leaf
// directories, and a marker file outside the leaf root. It returns the data
// dir and the leaf root.
func leafFixture(t *testing.T) (dataDir, root string) {
	t.Helper()
	dataDir = t.TempDir()
	root = filepath.Join(dataDir, "tls", "apps")
	for _, p := range []string{
		filepath.Join(root, leafTestAppID, "cert.pem"),
		filepath.Join(root, "01J8Z3K5QW6X7Y8Z9A0B1C2D3F", "cert.pem"),
		filepath.Join(dataDir, "tls", "other", "cert.pem"),
		filepath.Join(dataDir, "marker"),
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dataDir, root
}

func mustExist(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Stat(p); err != nil {
		t.Errorf("%s should still exist: %v", p, err)
	}
}

func TestRemoveAppLeaf_ConfinedToLeafRoot(t *testing.T) {
	for _, id := range []string{
		"",
		".",
		"..",
		"other",
		"../other",
		"x/../" + leafTestAppID,
		leafTestAppID + "/cert.pem",
		"/" + leafTestAppID,
		`..\other`,
		"01J8Z3K5QW6X7Y8Z9A0B1C/../",
		"01J8Z3K5QW6X7Y8Z9A0B1C2D..",
		strings.Repeat(".", 26),
	} {
		dataDir, root := leafFixture(t)
		if err := removeAppLeafDir(root, id); err == nil {
			t.Errorf("removeAppLeafDir accepted id %q", id)
		}
		mustExist(t, filepath.Join(root, leafTestAppID, "cert.pem"))
		mustExist(t, filepath.Join(root, "01J8Z3K5QW6X7Y8Z9A0B1C2D3F", "cert.pem"))
		mustExist(t, filepath.Join(dataDir, "tls", "other", "cert.pem"))
		mustExist(t, filepath.Join(dataDir, "marker"))
	}
}

func TestRemoveAppLeaf_RemovesOnlyThatApp(t *testing.T) {
	dataDir, root := leafFixture(t)
	// An unclean root spelling names the same directory.
	if err := removeAppLeafDir(root+string(filepath.Separator)+".", leafTestAppID); err != nil {
		t.Fatalf("removeAppLeafDir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, leafTestAppID)); !os.IsNotExist(err) {
		t.Errorf("app leaf dir should be gone, stat err = %v", err)
	}
	mustExist(t, filepath.Join(root, "01J8Z3K5QW6X7Y8Z9A0B1C2D3F", "cert.pem"))
	mustExist(t, filepath.Join(dataDir, "tls", "other", "cert.pem"))
	mustExist(t, filepath.Join(dataDir, "marker"))

	// Removing an app that has no leaf dir is not an error.
	if err := removeAppLeafDir(root, leafTestAppID); err != nil {
		t.Errorf("second removeAppLeafDir: %v", err)
	}
}
