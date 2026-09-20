//go:build unix

package docker

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// The at-rest modes of everything the REAL compose backend writes. It sits
// here rather than in agent/internal/atrest's inventory because the backend's
// constructor requires a docker CLI on PATH and the write paths are
// unexported; the rest of the agent's inventory is in that package's
// TestAtRestModes, and this table is part of the same seed for the image-level
// gate (geekdojo/geekdojo-brain#494).

func perm(t *testing.T, path string) fs.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}

func TestAtRestModes(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	for _, existing := range []bool{false, true} {
		name := "fresh"
		if existing {
			name = "existing install"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			c := &ComposeBackend{dir: root}
			if existing {
				// What an agent before this change left on disk.
				appDir := filepath.Join(root, "app1")
				if err := os.MkdirAll(appDir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(appDir, 0o755); err != nil {
					t.Fatal(err)
				}
				for _, f := range []string{composeFileName, volumeRecordFile} {
					if err := os.WriteFile(filepath.Join(appDir, f), []byte("old"), 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := c.writeCompose("app1", "services:\n  a:\n    image: x\n"); err != nil {
				t.Fatal(err)
			}
			rec := &volumeRecord{AppID: "app1", Anonymous: []recordedVolume{{Name: "v1", FirstSeen: time.Now().UTC()}}}
			if err := c.saveRecord("app1", rec); err != nil {
				t.Fatal(err)
			}
			for _, w := range []struct {
				rel  string
				mode fs.FileMode
			}{
				{"app1", 0o700},
				{"app1/" + composeFileName, 0o600},
				{"app1/" + volumeRecordFile, 0o600},
			} {
				if got := perm(t, filepath.Join(root, w.rel)); got != w.mode {
					t.Errorf("%s: mode %#o, want %#o", w.rel, got, w.mode)
				}
			}
		})
	}
}

// TightenAppState is what brings an install made by an older agent to the rule
// without redeploying every app: the compose files on disk are 0644 until
// something rewrites them, and nothing does until the api pushes the app again.
func TestTightenAppState_ExistingInstall(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	root := t.TempDir()
	appDir := filepath.Join(root, "app1")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	compose := filepath.Join(appDir, composeFileName)
	if err := os.WriteFile(compose, []byte("services: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(appDir, volumeRecordFile)
	if err := os.WriteFile(record, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A tile's own bind-mount target under the project directory. It belongs
	// to the container — which may run as another uid — so it is left exactly
	// as it is.
	appData := filepath.Join(appDir, "config")
	if err := os.Mkdir(appData, 0o755); err != nil {
		t.Fatal(err)
	}
	appFile := filepath.Join(appData, "settings.yaml")
	if err := os.WriteFile(appFile, []byte("theme: dark\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A loose file directly in the app directory that the agent did not write.
	strayFile := filepath.Join(appDir, ".env")
	if err := os.WriteFile(strayFile, []byte("A=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	TightenAppState(root)

	if got := perm(t, appDir); got != 0o700 {
		t.Errorf("app dir: mode %#o, want 0700", got)
	}
	for _, p := range []string{compose, record} {
		if got := perm(t, p); got != 0o600 {
			t.Errorf("%s: mode %#o, want 0600", filepath.Base(p), got)
		}
	}
	if b, _ := os.ReadFile(compose); string(b) != "services: {}\n" {
		t.Errorf("contents rewritten: %q", b)
	}
	for _, p := range []string{appData, appFile, strayFile} {
		if got := perm(t, p); got != 0o755 && got != 0o644 {
			t.Errorf("%s: mode %#o — the tile's own content was chmodded", p, got)
		}
	}
}

// A staged compose (docker.pull, docker.volumes.check) carries the same
// content as the live one, so it gets the same mode — and gets it explicitly,
// because os.CreateTemp's 0600 is a request the umask can only narrow, never a
// guarantee it was set.
func TestStageComposeIsOwnerOnly(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	c := &ComposeBackend{dir: t.TempDir()}
	staged, cleanup, err := c.stageCompose("app1", stagedPullPattern, "services: {}\n")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got := perm(t, staged); got != 0o600 {
		t.Errorf("staged compose: mode %#o, want 0600", got)
	}
	if got := perm(t, filepath.Dir(staged)); got != 0o700 {
		t.Errorf("app dir: mode %#o, want 0700", got)
	}
}
