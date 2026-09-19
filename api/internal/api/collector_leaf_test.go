package api

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// Removing a node deletes its collector client leaf and key
// (<collectorLeafDir>/<node-id>), and nothing else under the leaf directory.
func TestHandleDeleteNode_DeletesTheCollectorLeaf(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	seedNodeWithCascade(t, f, "node-gone")
	seedNodeWithCascade(t, f, "node-stays")

	leaves := filepath.Join(t.TempDir(), "tls", "collectors")
	for _, id := range []string{"node-gone", "node-stays"} {
		dir := filepath.Join(leaves, id)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"leaf.pem", "leaf.key"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	f.srv.SetCollectorLeafDir(leaves)

	if w := f.do(t, http.MethodDelete, "/api/nodes/node-gone", "", c); w.Code != http.StatusOK {
		t.Fatalf("DELETE = %d %s, want 200", w.Code, w.Body.String())
	}
	if _, err := os.Lstat(filepath.Join(leaves, "node-gone")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the removed node's leaf directory is still there (%v)", err)
	}
	if _, err := os.Stat(filepath.Join(leaves, "node-stays", "leaf.key")); err != nil {
		t.Errorf("another node's leaf was touched: %v", err)
	}

	// A node that never had a collector is removed without complaint.
	seedNodeWithCascade(t, f, "node-noleaf")
	if w := f.do(t, http.MethodDelete, "/api/nodes/node-noleaf", "", c); w.Code != http.StatusOK {
		t.Fatalf("DELETE of a node with no leaf = %d %s, want 200", w.Code, w.Body.String())
	}
}

// removeCollectorLeaf only ever names one directory directly under the leaf
// dir: an id that is not a valid node id deletes nothing.
func TestRemoveCollectorLeaf_RefusesAnIDThatIsNotANodeID(t *testing.T) {
	root := t.TempDir()
	leaves := filepath.Join(root, "collectors")
	sibling := filepath.Join(root, "keep")
	for _, d := range []string{leaves, sibling} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{collectorLeafDir: leaves}
	for _, id := range []string{"../keep", "..", "", "a/b", "Keep"} {
		s.removeCollectorLeaf(id)
	}
	for _, d := range []string{leaves, sibling} {
		if _, err := os.Stat(d); err != nil {
			t.Errorf("%s was removed: %v", d, err)
		}
	}
}
