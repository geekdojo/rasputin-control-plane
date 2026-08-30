package mesh

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// loopbackLoginServer takes the name out of the control plane's own control
// URL. Without it the CP resolves <cluster>.local to reach Headscale on itself,
// mDNS answers with every address the box has — docker bridges and link-locals
// included — and dialling an fe80:: without a zone index fails outright, taking
// the control plane off its own mesh for ~2m20s after every reboot.
func TestLoopbackLoginServer(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
	}{
		{"host and port", "https://e3bench.local:18080", "https://127.0.0.1:18080"},
		{"no port keeps scheme", "https://e3bench.local", "https://127.0.0.1"},
		{"http dev", "http://localhost:8080", "http://127.0.0.1:8080"},
		{"already loopback is a no-op", "https://127.0.0.1:18080", "https://127.0.0.1:18080"},
		{"path is preserved", "https://e3bench.local:18080/base", "https://127.0.0.1:18080/base"},
		// Anything unparseable falls through unchanged: the cluster name works,
		// it is only slow for the control plane, so there is nothing to gain by
		// inventing a URL we are not sure about.
		{"empty", "", ""},
		{"no host", "not-a-url", "not-a-url"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := loopbackLoginServer(tc.in); got != tc.want {
				t.Errorf("loopbackLoginServer(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// The rewrite must apply to the control plane and NOTHING else — a compute node
// pointed at its own loopback would find no Headscale there at all, which is
// far worse than the delay being fixed.
func TestIsControlPlaneNode(t *testing.T) {
	ctx := context.Background()
	inv, err := inventory.OpenStore(ctx, filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatalf("inventory.OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = inv.Close() })

	now := time.Now().UTC()
	for id, role := range map[string]proto.NodeRole{
		"cp-1":      proto.RoleControlPlane,
		"compute-1": proto.RoleCompute,
	} {
		if err := inv.Insert(ctx, &proto.Node{
			ID: id, Role: role, Hostname: id, FirstSeen: now, LastSeen: now,
		}); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}

	for _, tc := range []struct {
		name, nodeID string
		want         bool
	}{
		{"the control plane", "cp-1", true},
		{"a compute node", "compute-1", false},
		{"a node we have never seen", "ghost", false},
		{"empty id", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isControlPlaneNode(ctx, inv, tc.nodeID); got != tc.want {
				t.Errorf("isControlPlaneNode(%q) = %v, want %v", tc.nodeID, got, tc.want)
			}
		})
	}

	// A nil store must not panic and must not claim control-plane-ness.
	if isControlPlaneNode(ctx, nil, "cp-1") {
		t.Error("nil inventory store reported a control plane")
	}
}
