package updater

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestOpenWrtPruneBundles verifies the OpenWrt A/B bundle store keeps only the
// target's rootfs artifact AND its .version and .sig sidecars, drops other
// bundles plus stale partial downloads, and leaves unrelated files alone — the same
// transient-cache contract RAUCBackend has (see TestPruneBundles), but for the
// OpenWrt backend, whose pruneBundles shipped with every branch NOT COVERED.
//
// Kills three CONDITIONALS_NEGATION survivors in openwrt_ab.go pruneBundles:
//   - 199:9  (`if err != nil` on ReadDir → `== nil`): a successful read would
//     return early and prune nothing, so old1.rootfs would survive.
//   - 205:11 (`name == keep` → `!=`): the kept rootfs would fall through to the
//     suffix check and be deleted.
//   - 205:27 (`name == keep+".version"` → `!=`): the kept .version sidecar would
//     be deleted.
func TestOpenWrtPruneBundles(t *testing.T) {
	dir := t.TempDir()
	bundles := filepath.Join(dir, "bundles")
	if err := os.MkdirAll(bundles, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{
		"keepme.rootfs",         // the target — must survive
		"keepme.rootfs.version", // its version sidecar — must survive
		// Its detached signature — must survive. Install reads this back off
		// disk, so pruning it would fail the update closed with "signature
		// missing", which reads like tampering rather than like housekeeping.
		"keepme.rootfs.sig",
		"old1.rootfs",         // prior bundle — prune
		"old1.rootfs.sig",     // prior signature — prune
		"old2.rootfs.version", // prior sidecar — prune
		"download-9999.tmp",   // stale partial download — prune
		"state.json",          // unrelated — keep
		"notes.txt",           // unrelated — keep
	} {
		if err := os.WriteFile(filepath.Join(bundles, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	o := &OpenWrtABBackend{stateDir: dir}
	o.pruneBundles("keepme")

	ents, err := os.ReadDir(bundles)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range ents {
		got = append(got, e.Name())
	}
	sort.Strings(got)
	want := []string{"keepme.rootfs", "keepme.rootfs.sig", "keepme.rootfs.version", "notes.txt", "state.json"}
	if len(got) != len(want) {
		t.Fatalf("after prune: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("after prune: got %v, want %v", got, want)
		}
	}
}
