package main

import (
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/host"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TestClusterDNSServerIP_ControlPlaneUsesItsOwnLANIP is the regression for the
// bug this function exists to fix. The control plane was excluded from
// clusterdns entirely, on the reasoning that it "is the nameserver". It still
// has to resolve <cluster>.local for its own tailscaled to reach Headscale, and
// on e3bench it resolved that name by mDNS to a link-local address it could not
// dial — so the control plane fell off its own mesh and nothing repaired it.
//
// It must now get a drop-in like every other role, and it must point at its LAN
// address: the CP nameserver binds the LAN IP, so the bus peer address the
// other roles use (127.0.0.1 on the control plane, which dials its own bus over
// loopback) would aim every cluster-name query at a closed port.
func TestClusterDNSServerIP_ControlPlaneUsesItsOwnLANIP(t *testing.T) {
	lan := host.PrimaryLANIP()
	if lan == "" {
		t.Skip("no LAN IPv4 on this host; nothing to compare against")
	}
	// nil bus connection on purpose: the control plane must not consult it.
	got, why := clusterDNSServerIP(proto.RoleControlPlane, nil)
	if got == "" {
		t.Fatalf("control plane got no address (%s) — it would be left off the mesh with nothing to repair it", why)
	}
	if got != lan {
		t.Errorf("control plane address = %q, want its LAN IP %q", got, lan)
	}
	if got == "127.0.0.1" || strings.HasPrefix(got, "127.") {
		t.Errorf("control plane pointed at loopback %q; the CP nameserver binds the LAN address", got)
	}
}

// A control plane with no LAN IPv4 has nowhere to point. It must decline with a
// reason rather than emit an empty or loopback DNS= line, which would silently
// break name resolution for the whole node rather than just leave it unrepaired.
func TestClusterDNSServerIP_ControlPlaneWithoutLANDeclines(t *testing.T) {
	// Exercised through the real helper only when the host genuinely has no
	// LAN IP; otherwise assert the contract shape holds for the other roles.
	if host.PrimaryLANIP() != "" {
		t.Skip("host has a LAN IP; the no-LAN branch is not reachable here")
	}
	got, why := clusterDNSServerIP(proto.RoleControlPlane, nil)
	if got != "" {
		t.Errorf("expected no address, got %q", got)
	}
	if why == "" {
		t.Error("declined without saying why")
	}
}

// Non-control-plane roles must never fall back to a local address: they have to
// point at the control plane, and the only trustworthy source is the socket
// they are already connected on. With no bus connection they decline.
func TestClusterDNSServerIP_NonControlPlaneNeedsTheBus(t *testing.T) {
	for _, role := range []proto.NodeRole{proto.RoleCompute, proto.RoleFirewall} {
		t.Run(string(role), func(t *testing.T) {
			got, why := clusterDNSServerIP(role, nil)
			if got != "" {
				t.Errorf("%s: got address %q with no bus connection — it cannot know the control plane", role, got)
			}
			if why == "" {
				t.Errorf("%s: declined without saying why", role)
			}
		})
	}
}
