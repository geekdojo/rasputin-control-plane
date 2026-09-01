package health

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/nameguard"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// fakeRun returns a runner that yields per-command canned (output, err), keyed
// by the command name.
func fakeRun(out map[string]string, fail map[string]bool) cmdRunner {
	return func(ctx context.Context, name string, args ...string) (string, error) {
		if fail[name] {
			return out[name], errors.New("exit 1")
		}
		return out[name], nil
	}
}

func byName(a proto.DiagHealthAck) map[string]proto.HealthCheck {
	m := map[string]proto.HealthCheck{}
	for _, c := range a.Checks {
		m[c.Name] = c
	}
	return m
}

// A firewall with a loaded ruleset + dnsmasq running is healthy, even if the WAN
// route isn't up yet (non-critical).
func TestFirewallHealthy(t *testing.T) {
	fw := writeFWConfig(t)
	run := fakeRun(map[string]string{
		"nft": "table inet fw4 {\n}\n",
		// dnsmasq pgrep ok, ip route empty (WAN still acquiring)
	}, map[string]bool{"ip": true})
	ack := check(context.Background(), proto.RoleFirewall, run, fw)
	if !ack.OK {
		t.Fatalf("expected healthy, got %+v", ack)
	}
	if c := byName(ack)["wan-route"]; c.OK || c.Critical {
		t.Errorf("wan-route should be failing + non-critical: %+v", c)
	}
}

// A wiped nftables ruleset (critical) rolls back.
func TestFirewallEmptyRulesetUnhealthy(t *testing.T) {
	fw := writeFWConfig(t)
	run := fakeRun(map[string]string{
		"nft": "", // empty ruleset
		"ip":  "default via 10.0.0.1 dev eth1",
	}, nil)
	ack := check(context.Background(), proto.RoleFirewall, run, fw)
	if ack.OK {
		t.Fatalf("expected unhealthy on empty ruleset, got %+v", ack)
	}
	if c := byName(ack)["nft-ruleset"]; c.OK {
		t.Errorf("nft-ruleset should fail: %+v", c)
	}
}

// A dead dnsmasq (critical) rolls back.
func TestFirewallDnsmasqDownUnhealthy(t *testing.T) {
	fw := writeFWConfig(t)
	run := fakeRun(map[string]string{
		"nft": "table inet fw4 {}",
		"ip":  "default via 10.0.0.1 dev eth1",
	}, map[string]bool{"pgrep": true}) // dnsmasq not found
	ack := check(context.Background(), proto.RoleFirewall, run, fw)
	if ack.OK {
		t.Fatalf("expected unhealthy on dnsmasq down, got %+v", ack)
	}
}

// THE FAIL-OPEN. A firewall-role node with no firewall configuration and no
// explicit opt-in used to answer ok:true off the baseline liveness check — the
// node in the worst possible state (no firewall config at all) reporting the
// verdict the update saga COMMITS on. It must fail, and the detail must say
// why: an operator reading "failed critical checks: firewall-config" without
// the path has to go read source to act.
func TestFirewallRoleWithoutConfigIsUnhealthy(t *testing.T) {
	t.Setenv(uciBackendEnv, "")
	absent := filepath.Join(t.TempDir(), "absent")
	run := fakeRun(nil, map[string]bool{"nft": true, "pgrep": true, "ip": true})
	ack := check(context.Background(), proto.RoleFirewall, run, absent)
	if ack.OK {
		t.Fatalf("a firewall with no firewall config must not report healthy, got %+v", ack)
	}
	c, ok := byName(ack)["firewall-config"]
	if !ok {
		t.Fatalf("expected a firewall-config check, got %+v", ack.Checks)
	}
	if c.OK || !c.Critical {
		t.Errorf("firewall-config must be failing + critical: %+v", c)
	}
	if !strings.Contains(c.Detail, absent) {
		t.Errorf("detail should name the absent path, got %q", c.Detail)
	}
	if !strings.Contains(c.Detail, uciBackendEnv) {
		t.Errorf("detail should name the opt-out variable, got %q", c.Detail)
	}
	if !strings.Contains(ack.Detail, "firewall-config") {
		t.Errorf("ack detail should name the failed check, got %q", ack.Detail)
	}
}

// An operator who pinned RASPUTIN_UCI_BACKEND=uci is claiming a real OpenWrt
// root. If the config is not there, they are wrong about the machine, and that
// is exactly the case that must not be papered over.
func TestFirewallRoleExplicitRealBackendWithoutConfigIsUnhealthy(t *testing.T) {
	t.Setenv(uciBackendEnv, "uci")
	ack := check(context.Background(), proto.RoleFirewall, fakeRun(nil, nil), filepath.Join(t.TempDir(), "absent"))
	if ack.OK {
		t.Fatalf("an explicit uci pin with no config present must not report healthy, got %+v", ack)
	}
}

// The dev/CI path, and the ONLY way to reach the degraded gate: the mock
// backend #220 already requires a firewall-role agent to name explicitly. It
// still passes — a local run or a fleet-sim must not spuriously roll back — but
// the degradation is stated in the check detail rather than being invisible.
func TestFirewallRoleWithExplicitMockDegradesToLiveness(t *testing.T) {
	t.Setenv(uciBackendEnv, "mock")
	run := fakeRun(nil, map[string]bool{"nft": true, "pgrep": true, "ip": true})
	ack := check(context.Background(), proto.RoleFirewall, run, filepath.Join(t.TempDir(), "absent"))
	if !ack.OK || len(ack.Checks) != 1 || ack.Checks[0].Name != "agent" {
		t.Fatalf("an explicit mock firewall should pass baseline liveness, got %+v", ack)
	}
	if d := ack.Checks[0].Detail; !strings.Contains(d, uciBackendEnv) {
		t.Errorf("the degraded gate must say it is degraded and why, got %q", d)
	}
}

// The opt-in is the mock backend by name — not "any value", and not the empty
// set-but-unset form node.env produces, which #220 treats as unavailable.
func TestOnlyTheMockBackendOptsIntoTheDegradedGate(t *testing.T) {
	for _, v := range []string{"", "uci", "Mock", "mock ", "unavailable", "yes"} {
		t.Setenv(uciBackendEnv, v)
		ack := check(context.Background(), proto.RoleFirewall, fakeRun(nil, nil), filepath.Join(t.TempDir(), "absent"))
		if ack.OK {
			t.Errorf("%s=%q must not opt into the degraded gate: %+v", uciBackendEnv, v, ack)
		}
	}
}

// A real OpenWrt firewall runs the real battery regardless of the env var: the
// config file is present, so there IS a data plane to probe and the operator's
// dev-box hint does not get to suppress it.
func TestFirewallWithConfigRunsRealChecksEvenWithMockSet(t *testing.T) {
	t.Setenv(uciBackendEnv, "mock")
	fw := writeFWConfig(t)
	run := fakeRun(map[string]string{"nft": "table inet fw4 {}", "ip": "default via 10.0.0.1 dev eth1"}, nil)
	ack := check(context.Background(), proto.RoleFirewall, run, fw)
	for _, name := range []string{"nft-ruleset", "dnsmasq", "wan-route"} {
		if _, ok := byName(ack)[name]; !ok {
			t.Errorf("expected the real %s check to run, got %+v", name, ack.Checks)
		}
	}
	if !ack.OK {
		t.Errorf("a healthy real firewall should pass, got %+v", ack)
	}
}

// Every non-firewall role passes the baseline liveness check, with or without
// the firewall config and whatever the UCI backend says — a compute node has no
// firewall data plane, so none of this may change its verdict.
func TestNonFirewallLiveness(t *testing.T) {
	for _, backend := range []string{"", "mock", "uci"} {
		for _, role := range []proto.NodeRole{proto.RoleCompute, proto.RoleControlPlane, proto.RoleStorage} {
			t.Setenv(uciBackendEnv, backend)
			ack := check(context.Background(), role, fakeRun(nil, nil), "/nonexistent")
			if !ack.OK || len(ack.Checks) != 1 || ack.Checks[0].Name != "agent" {
				t.Errorf("role %s (%s=%q) should pass liveness, got %+v", role, uciBackendEnv, backend, ack)
			}
			if c := ack.Checks[0]; c.Detail != "agent responding" {
				t.Errorf("role %s baseline detail changed: %q", role, c.Detail)
			}
		}
	}
}

func writeFWConfig(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "firewall")
	if err := os.WriteFile(p, []byte("config defaults\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// --- mDNS name check (controlplane) ------------------------------------------

func withNameStatus(t *testing.T, s nameguard.Status) {
	t.Helper()
	prev := nameStatus
	nameStatus = func() nameguard.Status { return s }
	t.Cleanup(func() { nameStatus = prev })
}

// A name conflict must be REPORTED but must not fail the ack. This check gates
// the node.update saga's post-reboot commit, and a conflict is a pre-existing
// network condition the update neither caused nor can fix — rolling back would
// strand the operator on an older image with the same conflict.
func TestControlPlaneNameConflictIsReportedNotCritical(t *testing.T) {
	withNameStatus(t, nameguard.Status{
		State:   nameguard.StateConflict,
		Name:    "rasputin.local",
		OwnerIP: "192.168.207.245",
	})
	ack := check(context.Background(), proto.RoleControlPlane, fakeRun(nil, nil), "")
	if !ack.OK {
		t.Fatalf("a name conflict must not fail the health ack (it would roll back an unrelated update): %+v", ack)
	}
	c, ok := byName(ack)["mdns-name"]
	if !ok {
		t.Fatal("expected an mdns-name check on the controlplane")
	}
	if c.OK || c.Critical {
		t.Errorf("mdns-name should be failing + non-critical: %+v", c)
	}
	if !strings.Contains(c.Detail, "192.168.207.245") {
		t.Errorf("detail should name the host that owns the name, got %q", c.Detail)
	}
}

func TestControlPlaneNameUnpublishedIsReported(t *testing.T) {
	withNameStatus(t, nameguard.Status{State: nameguard.StateUnpublished, Name: "rasputin.local"})
	ack := check(context.Background(), proto.RoleControlPlane, fakeRun(nil, nil), "")
	c, ok := byName(ack)["mdns-name"]
	if !ok {
		t.Fatal("expected an mdns-name check on the controlplane")
	}
	if c.OK {
		t.Errorf("unpublished name should report not-OK: %+v", c)
	}
	if !ack.OK {
		t.Errorf("unpublished name must stay non-critical: %+v", ack)
	}
}

func TestControlPlaneNameHealthy(t *testing.T) {
	withNameStatus(t, nameguard.Status{State: nameguard.StateOK, Name: "rasputin.local"})
	ack := check(context.Background(), proto.RoleControlPlane, fakeRun(nil, nil), "")
	if c := byName(ack)["mdns-name"]; !c.OK {
		t.Errorf("expected a passing mdns-name check, got %+v", c)
	}
}

// A guard that never ran (dev box, or before the first probe) must produce NO
// check at all — reporting unknown as a pass would show green on a node that
// never looked.
func TestUnknownNameStateEmitsNoCheck(t *testing.T) {
	withNameStatus(t, nameguard.Status{})
	ack := check(context.Background(), proto.RoleControlPlane, fakeRun(nil, nil), "")
	if _, ok := byName(ack)["mdns-name"]; ok {
		t.Error("an unknown name state must not emit a check")
	}
	if !ack.OK {
		t.Errorf("baseline ack should still be healthy: %+v", ack)
	}
}

// Non-controlplane roles never publish the shared name, so they must not carry
// the check.
func TestNonControlPlaneHasNoNameCheck(t *testing.T) {
	withNameStatus(t, nameguard.Status{State: nameguard.StateConflict, Name: "rasputin.local", OwnerIP: "1.2.3.4"})
	for _, role := range []proto.NodeRole{proto.RoleCompute, proto.RoleStorage} {
		ack := check(context.Background(), role, fakeRun(nil, nil), "")
		if _, ok := byName(ack)["mdns-name"]; ok {
			t.Errorf("role %s should not carry an mdns-name check", role)
		}
	}
}

// The healthy detail must carry the address and the signal — this is the only
// way to read current state WITHOUT waiting for a transition, since the guard
// logs on change only. On the bench a long-healthy node printed nothing and
// the live state had to be inferred from the absence of log lines.
func TestControlPlaneNameHealthyDetailCarriesAddressAndSource(t *testing.T) {
	withNameStatus(t, nameguard.Status{
		State:   nameguard.StateOK,
		Name:    "rasputin.local",
		OwnerIP: "192.168.207.31",
		Source:  nameguard.SourceResolver,
	})
	ack := check(context.Background(), proto.RoleControlPlane, fakeRun(nil, nil), "")
	c := byName(ack)["mdns-name"]
	if !c.OK {
		t.Fatalf("expected a passing check, got %+v", c)
	}
	if !strings.Contains(c.Detail, "192.168.207.31") {
		t.Errorf("detail should name the answering address, got %q", c.Detail)
	}
	if !strings.Contains(c.Detail, "resolver") {
		t.Errorf("detail should name the signal, so a fallback-only OK is visible, got %q", c.Detail)
	}
}
