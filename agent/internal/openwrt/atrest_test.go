//go:build unix

package openwrt

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The real UCI client's own state — the manifest of what Rasputin manages on
// the firewall — is 0600 in a 0700 directory like the rest of the agent's
// state tree, both on a fresh node and on one an older agent set up.
// (The firewall's /etc/config files are written by `uci`, not by this process.)
func TestAtRestModes(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	for _, existing := range []bool{false, true} {
		name := "fresh"
		if existing {
			name = "existing install"
		}
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "openwrt")
			if existing {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "managed.json"), []byte(`{"network":true}`), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			c, err := newRealClient(dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.saveManifest(managedManifest{Network: true, WANKeys: []string{"proto"}}); err != nil {
				t.Fatal(err)
			}
			for _, w := range []struct {
				path string
				mode os.FileMode
			}{
				{dir, 0o700},
				{c.manifestPath, 0o600},
			} {
				info, err := os.Lstat(w.path)
				if err != nil {
					t.Fatal(err)
				}
				if got := info.Mode().Perm(); got != w.mode {
					t.Errorf("%s: mode %#o, want %#o", w.path, got, w.mode)
				}
			}
		})
	}
}
