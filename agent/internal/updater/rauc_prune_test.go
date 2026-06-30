package updater

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestPruneBundles verifies the bundle store keeps only the target bundle and
// drops other .raucb files + stale partial downloads, while leaving unrelated
// files (state.json etc.) alone — so bundles don't accumulate and fill a small
// data partition.
func TestPruneBundles(t *testing.T) {
	dir := t.TempDir()
	bundles := filepath.Join(dir, "bundles")
	if err := os.MkdirAll(bundles, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{
		"keepme.raucb",      // the target — must survive
		"old1.raucb",        // prior bundle — prune
		"old2.raucb",        // prior bundle — prune
		"download-9999.tmp", // stale partial download — prune
		"state.json",        // unrelated — keep
		"notes.txt",         // unrelated — keep
	} {
		if err := os.WriteFile(filepath.Join(bundles, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	r := &RAUCBackend{stateDir: dir}
	r.pruneBundles("keepme")

	ents, err := os.ReadDir(bundles)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range ents {
		got = append(got, e.Name())
	}
	sort.Strings(got)
	want := []string{"keepme.raucb", "notes.txt", "state.json"}
	if len(got) != len(want) {
		t.Fatalf("after prune: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("after prune: got %v, want %v", got, want)
		}
	}
}
