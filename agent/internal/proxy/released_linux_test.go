//go:build linux

package proxy

import (
	"net"
	"path/filepath"
	"testing"
)

// TestCaddyReleased_HeldPortIsNotReleased guards the race test's cleanup
// predicate. It models the state that made TC-831-05 to TC-831-07 fail: no
// Caddy that caddyPIDs counts as live, yet the address still bound. "No caddy
// process" alone must not read as released. Once the port is free, it does.
// It needs neither root nor a caddy binary, so it runs in the ordinary test job.
func TestCaddyReleased_HeldPortIsNotReleased(t *testing.T) {
	// A caddy binary that does not exist: caddyPIDs finds no process for it.
	noCaddy := filepath.Join(t.TempDir(), "no-such-caddy")
	if pids := caddyPIDs(noCaddy); len(pids) != 0 {
		t.Fatalf("caddyPIDs(%s) = %v, want none", noCaddy, pids)
	}

	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := held.Addr().String()
	if caddyReleased(noCaddy, addr) {
		_ = held.Close()
		t.Fatalf("caddyReleased(%s) = true with %s still bound, want false", noCaddy, addr)
	}

	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	if !caddyReleased(noCaddy, addr) {
		t.Fatalf("caddyReleased(%s) = false with no caddy and %s closed, want true", noCaddy, addr)
	}
}
