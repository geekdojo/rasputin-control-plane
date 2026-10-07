package tailscale

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/nodetrust"
)

// testTrust is a node trust bundle in a fresh temp dir.
func testTrust(t *testing.T) *nodetrust.Store {
	t.Helper()
	return nodetrust.NewStore(filepath.Join(t.TempDir(), "mesh", "tailscaled-ca.pem"))
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
