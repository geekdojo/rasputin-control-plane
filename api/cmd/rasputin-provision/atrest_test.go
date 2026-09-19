//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestGenerate_AtRestModes pins the modes of what a matched set writes — a
// row of the api's at-rest inventory (api/internal/atrest, TestAtRestModes;
// gate geekdojo/geekdojo-brain#494). Seeds carry a join token or the bus
// private key and are 0600, including when a re-run replaces a seed an
// earlier run left at a wider mode; the preseed and manifest hold hashes and
// ids only and are 0644. Run under a zero umask, so a loose create mode shows.
func TestGenerate_AtRestModes(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	dir := filepath.Join(t.TempDir(), "set")
	nodes := nodeList{
		{Role: "controlplane", ID: "c-cp"},
		{Role: "firewall", ID: "c-fw"},
		{Role: "compute", ID: "c-n1"},
	}
	man, err := generate("c", "", dir, nodes, true, "")
	if err != nil {
		t.Fatal(err)
	}
	// Loosen every seed, as an older run (or an operator) might have, and
	// generate again into the same directory.
	for _, n := range man.Nodes {
		if err := os.Chmod(filepath.Join(dir, n.SeedFile), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if man, err = generate("c", "", dir, nodes, true, ""); err != nil {
		t.Fatal(err)
	}

	want := map[string]os.FileMode{
		".":             0o700,
		man.PreseedFile: 0o644,
		"manifest.json": 0o644,
	}
	for _, n := range man.Nodes {
		want[n.SeedFile] = 0o600
	}
	for rel, mode := range want {
		info, err := os.Stat(filepath.Join(dir, rel))
		if err != nil {
			t.Errorf("%s: %v", rel, err)
			continue
		}
		if got := info.Mode().Perm(); got != mode {
			t.Errorf("%s: mode %#o, want %#o", rel, got, mode)
		}
	}
}
