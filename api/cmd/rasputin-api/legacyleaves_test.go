package main

import (
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// TC-516-14: the start-up cleanup removes tls/collectors and nothing beside
// it, with one INFO record; an absent directory writes nothing; a directory
// it cannot remove is one WARN and a return.
func TestRemoveLegacyCollectorLeaves(t *testing.T) {
	tlsDir := filepath.Join(t.TempDir(), "tls")
	collectors := filepath.Join(tlsDir, "collectors")
	for _, p := range []string{
		filepath.Join(collectors, "n1", "leaf.key"),
		filepath.Join(collectors, "n2", "leaf.key"),
		filepath.Join(tlsDir, "api", "leaf.pem"),
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	logger, rec := logkittest.New()
	removeLegacyCollectorLeaves(logger, collectors)
	if _, err := os.Stat(collectors); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("tls/collectors still exists (stat: %v)", err)
	}
	if _, err := os.Stat(filepath.Join(tlsDir, "api", "leaf.pem")); err != nil {
		t.Errorf("tls/api was touched: %v", err)
	}
	if len(rec.Records()) != 1 {
		t.Fatalf("records:\n%s", rec.Text())
	}
	info := rec.AtLevel(slog.LevelInfo)
	if len(info) != 1 {
		t.Fatalf("INFO records:\n%s", rec.Text())
	}
	for k, want := range map[string]string{"dir": collectors, "removed": "2"} {
		if v, ok := logkittest.Attr(info[0], k); !ok || v != want {
			t.Errorf("%s = %q (present %v), want %q", k, v, ok, want)
		}
	}

	// Absent: the steady state, and silent.
	logger, rec = logkittest.New()
	removeLegacyCollectorLeaves(logger, collectors)
	if n := len(rec.Records()); n != 0 {
		t.Errorf("an absent directory wrote %d record(s):\n%s", n, rec.Text())
	}

	// A read-only parent: the directory cannot be removed.
	if os.Geteuid() == 0 {
		t.Skip("running as root: a read-only parent does not stop the removal, so the WARN case cannot be produced")
	}
	if err := os.MkdirAll(filepath.Join(collectors, "n3"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tlsDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(tlsDir, 0o700) })
	logger, rec = logkittest.New()
	removeLegacyCollectorLeaves(logger, collectors)
	warns := rec.AtLevel(slog.LevelWarn)
	if len(warns) != 1 || len(rec.Records()) != 1 {
		t.Fatalf("read-only parent records:\n%s", rec.Text())
	}
	if v, _ := logkittest.Attr(warns[0], "dir"); v != collectors {
		t.Errorf("dir = %q, want %q", v, collectors)
	}
	if v, ok := logkittest.Attr(warns[0], "err"); !ok || v == "" {
		t.Error("the WARN carries no err")
	}
}
