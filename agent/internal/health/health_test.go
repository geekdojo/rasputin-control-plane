package health

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

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

// A firewall-role agent on a dev box (no /etc/config/firewall) degrades to the
// baseline liveness check so CI/dev don't spuriously roll back.
func TestFirewallRoleOnDevBoxDegradesToLiveness(t *testing.T) {
	run := fakeRun(nil, map[string]bool{"nft": true, "pgrep": true, "ip": true})
	ack := check(context.Background(), proto.RoleFirewall, run, filepath.Join(t.TempDir(), "absent"))
	if !ack.OK || len(ack.Checks) != 1 || ack.Checks[0].Name != "agent" {
		t.Fatalf("dev firewall should pass baseline liveness, got %+v", ack)
	}
}

// Every non-firewall role passes the baseline liveness check.
func TestNonFirewallLiveness(t *testing.T) {
	for _, role := range []proto.NodeRole{proto.RoleCompute, proto.RoleControlPlane, proto.RoleStorage} {
		ack := check(context.Background(), role, fakeRun(nil, nil), "/nonexistent")
		if !ack.OK || len(ack.Checks) != 1 || ack.Checks[0].Name != "agent" {
			t.Errorf("role %s should pass liveness, got %+v", role, ack)
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
