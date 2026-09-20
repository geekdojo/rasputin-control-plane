//go:build unix

package bmc

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The persisted BMC selection carries the operator's BMC credentials, so it is
// 0600 in a 0700 directory — on a fresh node, and on one where an older agent
// left the directory world-listable.
func TestAtRestModes(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	for _, existing := range []bool{false, true} {
		name := "fresh"
		if existing {
			name = "existing install"
		}
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "bmc")
			if existing {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, hostConfigFile), []byte(`{"kind":"none"}`), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := NewHost("node-1", dir, "", Config{}); err != nil {
				t.Fatal(err)
			}
			if err := persistSelection(dir, proto.BMCConfigureCmd{Kind: "mock", Config: []byte(`{"user":"admin","password":"s3cret"}`)}); err != nil {
				t.Fatal(err)
			}
			for _, w := range []struct {
				path string
				mode os.FileMode
			}{
				{dir, 0o700},
				{filepath.Join(dir, hostConfigFile), 0o600},
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
