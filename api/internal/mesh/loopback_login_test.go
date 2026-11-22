package mesh

import (
	"strings"
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

// TC-984-04: the role the dispatch step derives the login server and the
// settings from is read from the node registry, and every way of not having
// one is an error rather than a default. That the loopback rewrite applies to
// the control plane and NOTHING else is asserted on the real dispatch in
// TestEnrollDispatch_CommandPerRole.
func TestEnrolTargetRole(t *testing.T) {
	f := newConvergeFixture(t)
	now := time.Now().UTC()
	f.addNode(t, "cp-1", proto.RoleControlPlane, now)
	f.addNode(t, "compute-1", proto.RoleCompute, now)

	for _, tc := range []struct {
		name, nodeID string
		inv          *inventory.Store
		want         proto.NodeRole
		wantErr      string
	}{
		{"the control plane", "cp-1", f.inv, proto.RoleControlPlane, ""},
		{"a compute node", "compute-1", f.inv, proto.RoleCompute, ""},
		{"a node we have never seen", "ghost", f.inv, "", "node ghost is not registered"},
		{"empty id", "", f.inv, "", "is not registered"},
		{"nil inventory", "cp-1", nil, "", "inventory unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := enrolTargetRole(tc.inv, tc.nodeID)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("enrolTargetRole(%q) = %q, %v; want an error containing %q", tc.nodeID, got, err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Errorf("enrolTargetRole(%q) = %q, %v; want %q", tc.nodeID, got, err, tc.want)
			}
		})
	}
}
