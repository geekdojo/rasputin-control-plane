package main

import (
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

func fixed(v string) func() string { return func() string { return v } }

// never must not be called; a role that consults the wrong source is a bug even
// when the value it gets back happens to work.
func never(t *testing.T, what string) func() string {
	t.Helper()
	return func() string {
		t.Errorf("consulted %s for a role that must not use it", what)
		return "10.255.255.255:1"
	}
}

// TestClusterDNSServerIP is the regression for the gap this function closes.
// The control plane was excluded from clusterdns entirely, on the reasoning
// that it "is the nameserver". It still has to resolve <cluster>.local for its
// own tailscaled to reach Headscale, and on e3bench it resolved that name by
// mDNS to a link-local address it could not dial, taking the control plane off
// its own mesh for 2m20s on reboot.
//
// The control plane must point at its LAN address specifically: the CP
// nameserver binds the LAN IP, while the CP's agent dials its own bus over
// loopback. Reusing the bus-peer source would aim every cluster-name query at
// 127.0.0.1 — a closed port — which breaks name resolution outright rather than
// leaving it unrepaired, and is worse than the fault being fixed.
func TestClusterDNSServerIP(t *testing.T) {
	for _, tc := range []struct {
		name    string
		role    proto.NodeRole
		lan     func() string
		peer    func() string
		wantIP  string
		wantWhy bool
	}{
		{
			name:   "control plane uses its own LAN IP",
			role:   proto.RoleControlPlane,
			lan:    fixed("192.168.1.182"),
			peer:   never(t, "the bus peer"),
			wantIP: "192.168.1.182",
		},
		{
			// The bug in miniature: loopback is what the bus peer would have
			// given us, and it is where the CP nameserver is NOT listening.
			name:   "control plane ignores the bus peer even when set",
			role:   proto.RoleControlPlane,
			lan:    fixed("10.0.0.5"),
			peer:   never(t, "the bus peer"),
			wantIP: "10.0.0.5",
		},
		{
			name:    "control plane with no LAN IP declines with a reason",
			role:    proto.RoleControlPlane,
			lan:     fixed(""),
			peer:    never(t, "the bus peer"),
			wantIP:  "",
			wantWhy: true,
		},
		{
			name:   "compute uses the bus peer host",
			role:   proto.RoleCompute,
			lan:    never(t, "the local LAN IP"),
			peer:   fixed("192.168.1.182:4222"),
			wantIP: "192.168.1.182",
		},
		{
			name:    "compute with no bus connection declines",
			role:    proto.RoleCompute,
			lan:     never(t, "the local LAN IP"),
			peer:    fixed(""),
			wantIP:  "",
			wantWhy: true,
		},
		{
			name:    "compute with an unparseable peer declines",
			role:    proto.RoleCompute,
			lan:     never(t, "the local LAN IP"),
			peer:    fixed("not-a-host-port"),
			wantIP:  "",
			wantWhy: true,
		},
		{
			name:   "firewall follows the compute path",
			role:   proto.RoleFirewall,
			lan:    never(t, "the local LAN IP"),
			peer:   fixed("10.1.2.3:4222"),
			wantIP: "10.1.2.3",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotIP, why := clusterDNSServerIP(tc.role, tc.lan, tc.peer)
			if gotIP != tc.wantIP {
				t.Errorf("ip = %q, want %q (why=%q)", gotIP, tc.wantIP, why)
			}
			if tc.wantWhy && why == "" {
				t.Error("declined without saying why")
			}
			if !tc.wantWhy && why != "" {
				t.Errorf("succeeded but also gave a reason: %q", why)
			}
		})
	}
}
