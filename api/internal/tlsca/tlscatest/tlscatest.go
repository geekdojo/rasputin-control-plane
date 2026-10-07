// Package tlscatest builds tlsca instances for tests in other packages: the
// production collaborators (wall clock, crypto/rand) with a logger that
// discards, so a test that needs "a CA" does not restate the Deps.
package tlscatest

import (
	"crypto/rand"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
)

// Deps is the production Deps with a discarding logger.
func Deps() tlsca.Deps {
	return tlsca.Deps{Now: time.Now, Rand: rand.Reader, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// Controlplane ensures a controlplane CA in dir (a fresh temp dir when dir is
// ""), failing the test on error.
func Controlplane(t testing.TB, dir string) *tlsca.CA {
	t.Helper()
	return ensure(t, tlsca.ControlplaneConfig(), dir, Deps())
}

// ControlplaneWith is Controlplane with explicit Deps.
func ControlplaneWith(t testing.TB, dir string, d tlsca.Deps) *tlsca.CA {
	t.Helper()
	return ensure(t, tlsca.ControlplaneConfig(), dir, d)
}

func ensure(t testing.TB, cfg tlsca.Config, dir string, d tlsca.Deps) *tlsca.CA {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	ca, err := tlsca.Ensure(cfg, dir, "test", d)
	if err != nil {
		t.Fatalf("tlsca.Ensure(%s): %v", cfg.Name, err)
	}
	return ca
}
