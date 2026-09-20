//go:build unix

package clusterdns

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The drop-in is the agent's one PUBLIC-by-design file inside systemd's own
// configuration tree, and its mode is the whole reason this package cannot be
// swept up by a unit-level UMask: systemd-resolved reads it after dropping
// privileges and ignores it SILENTLY when it cannot (bench, 2026-08-29).
//
// Both modes are asserted under umask 077 — the mask that would produce
// 0700/0600 if either were left to the umask rather than set.
func TestAtRestModes(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)

	for _, existing := range []bool{false, true} {
		name := "fresh"
		if existing {
			name = "existing install"
		}
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "resolved.conf.d")
			if existing {
				// A directory an earlier tool left owner-only, with a drop-in
				// resolved could not read.
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, fileName), []byte("[Resolve]\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cfg := Config{
				ClusterID: "rasputin",
				ServerIP:  at("10.0.0.1"),
				probe:     answering,
				Dir:       dir,
				reload:    func(context.Context) error { return nil },
			}
			if _, err := Apply(context.Background(), cfg, TriggerStart); err != nil {
				t.Fatal(err)
			}
			for _, w := range []struct {
				path string
				mode fs.FileMode
			}{
				{dir, 0o755},
				{filepath.Join(dir, fileName), 0o644},
			} {
				info, err := os.Lstat(w.path)
				if err != nil {
					t.Fatal(err)
				}
				if got := info.Mode().Perm(); got != w.mode {
					t.Errorf("%s: mode %#o, want %#o — resolved would ignore it", w.path, got, w.mode)
				}
			}
		})
	}
}
