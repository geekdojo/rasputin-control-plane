// Package health runs role-aware health checks for the diag.health command.
//
// diag.ping only proves the agent process is up and reachable. The node.update
// saga's post-reboot gate needs more for the firewall: an OS update can boot the
// agent fine yet break the data plane (a wiped nftables ruleset, a dead dnsmasq)
// — committing that is worse than useless. So the firewall verifies what it
// actually must do; every other role uses the baseline liveness check (reaching
// here means the agent answered). New role-specific checks slot in the same way.
package health

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// cmdRunner runs a command and returns its combined output. Injected so the
// pure check logic is unit-tested without shelling out.
type cmdRunner func(ctx context.Context, name string, args ...string) (string, error)

func execRunner(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// firewallConfigPath gates the firewall data-plane checks on being a REAL
// OpenWrt firewall (the same signal the agent's UCI-backend autodetect uses). On
// a dev/mock box it's absent and Check degrades to the baseline liveness gate,
// so CI and local runs don't spuriously roll back an update. Package var so
// tests can point it elsewhere.
var firewallConfigPath = "/etc/config/firewall"

// Check runs the checks appropriate to role and returns the verdict the saga
// commits / rolls back on.
func Check(ctx context.Context, role proto.NodeRole) proto.DiagHealthAck {
	return check(ctx, role, execRunner, firewallConfigPath)
}

func check(ctx context.Context, role proto.NodeRole, run cmdRunner, fwConfig string) proto.DiagHealthAck {
	var checks []proto.HealthCheck
	if role == proto.RoleFirewall && fileExists(fwConfig) {
		checks = firewallChecks(ctx, run)
	} else {
		// Baseline: reaching here means the agent process is up and answering.
		checks = []proto.HealthCheck{{Name: "agent", OK: true, Critical: true, Detail: "agent responding"}}
	}
	ack := proto.DiagHealthAck{Role: string(role), OK: true, Checks: checks, Ts: time.Now().UTC()}
	var failed []string
	for _, c := range checks {
		if c.Critical && !c.OK {
			ack.OK = false
			failed = append(failed, c.Name)
		}
	}
	if !ack.OK {
		ack.Detail = "failed critical checks: " + strings.Join(failed, ", ")
	}
	return ack
}

// firewallChecks probes the firewall data plane. nft-ruleset and dnsmasq are
// CRITICAL (a broken firewall/DHCP must roll back); wan-route is non-critical
// because the WAN may still be re-acquiring a DHCP lease within the post-reboot
// health window, and a false rollback there would be worse than reporting it.
func firewallChecks(ctx context.Context, run cmdRunner) []proto.HealthCheck {
	return []proto.HealthCheck{
		nftRulesetCheck(ctx, run),
		dnsmasqCheck(ctx, run),
		wanRouteCheck(ctx, run),
	}
}

func nftRulesetCheck(ctx context.Context, run cmdRunner) proto.HealthCheck {
	out, err := run(ctx, "nft", "list", "ruleset")
	// A live firewall's ruleset contains at least one `table` (OpenWrt fw4 ships
	// `table inet fw4`). Empty output or a non-zero exit means it didn't load.
	ok := err == nil && strings.Contains(out, "table ")
	detail := "nftables ruleset loaded"
	if !ok {
		detail = "nftables ruleset empty or unreadable"
	}
	return proto.HealthCheck{Name: "nft-ruleset", OK: ok, Critical: true, Detail: detail}
}

func dnsmasqCheck(ctx context.Context, run cmdRunner) proto.HealthCheck {
	// pgrep exits 0 with the pids if the process is running, 1 if not.
	_, err := run(ctx, "pgrep", "dnsmasq")
	ok := err == nil
	detail := "dnsmasq running"
	if !ok {
		detail = "dnsmasq not running (LAN DHCP/DNS down)"
	}
	return proto.HealthCheck{Name: "dnsmasq", OK: ok, Critical: true, Detail: detail}
}

func wanRouteCheck(ctx context.Context, run cmdRunner) proto.HealthCheck {
	out, err := run(ctx, "ip", "route", "show", "default")
	ok := err == nil && strings.Contains(out, "default")
	detail := "default route present"
	if !ok {
		detail = "no default route yet (WAN may still be acquiring a lease)"
	}
	return proto.HealthCheck{Name: "wan-route", OK: ok, Critical: false, Detail: detail}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
