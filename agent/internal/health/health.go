// Package health runs role-aware health checks for the diag.health command.
//
// diag.ping only proves the agent process is up and reachable. The node.update
// saga's post-reboot gate needs more for the firewall: an OS update can boot the
// agent fine yet break the data plane (a wiped nftables ruleset, a dead dnsmasq)
// — committing that is worse than useless. So the firewall verifies what it
// actually must do; every other role uses the baseline liveness check (reaching
// here means the agent answered). New role-specific checks slot in the same way.
//
// A firewall that cannot be verified is not healthy. A firewall-role node with
// no /etc/config/firewall fails the gate rather than falling back to liveness —
// the degraded gate is opt-in (RASPUTIN_UCI_BACKEND=mock), never inferred from
// a missing file, on the same principle as #220.
package health

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/nameguard"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// cmdRunner runs a command and returns its combined output. Injected so the
// pure check logic is unit-tested without shelling out.
type cmdRunner func(ctx context.Context, name string, args ...string) (string, error)

func execRunner(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// firewallConfigPath is the OpenWrt firewall configuration every firewall-role
// node must have — the same signal the agent's UCI-backend and updater-backend
// autodetects use. It ships inside the read-only squashfs rootfs, so on a real
// firewall it is present from the moment / is mounted, before any service (the
// agent included) starts. Package var so tests can point it elsewhere.
//
// It used to be an INFERENCE: absent meant "dev box", and Check degraded to the
// baseline liveness gate. That is a fail-open on the one node where it hurts
// most — a firewall with no firewall configuration at all answered ok:true and
// the node.update saga committed. Absence is now a FAILING CHECK, and a dev box
// says so out loud with the variable #220 already created for exactly this.
var firewallConfigPath = "/etc/config/firewall"

// uciBackendEnv is the operator's explicit "this box is not a real OpenWrt
// firewall and I know it" signal. #220 made mock opt-in and never inferred; a
// firewall-role agent on a dev box already needs RASPUTIN_UCI_BACKEND=mock to
// get a firewall subsystem at all, so the health gate reads the same signal
// rather than inventing a second one.
const uciBackendEnv = "RASPUTIN_UCI_BACKEND"

// Check runs the checks appropriate to role and returns the verdict the saga
// commits / rolls back on.
func Check(ctx context.Context, role proto.NodeRole) proto.DiagHealthAck {
	return check(ctx, role, execRunner, firewallConfigPath)
}

func check(ctx context.Context, role proto.NodeRole, run cmdRunner, fwConfig string) proto.DiagHealthAck {
	var checks []proto.HealthCheck
	switch {
	case role == proto.RoleFirewall && fileExists(fwConfig):
		checks = firewallChecks(ctx, run)
	case role == proto.RoleFirewall && os.Getenv(uciBackendEnv) == "mock":
		// Explicitly opted into a mock firewall: there is no data plane to
		// probe and the operator said so, so the baseline liveness gate is the
		// honest answer. Named in the detail — a degraded gate that does not
		// say it is degraded is how this bug got written the first time.
		checks = []proto.HealthCheck{{Name: "agent", OK: true, Critical: true,
			Detail: "agent responding; firewall data-plane checks skipped (" + uciBackendEnv + "=mock)"}}
	case role == proto.RoleFirewall:
		// Firewall role, no firewall configuration, nothing opted into. This is
		// the state that must fail hardest, not the one that passes by default.
		checks = []proto.HealthCheck{missingFirewallConfigCheck(fwConfig)}
	default:
		// Baseline: reaching here means the agent process is up and answering.
		// Correct for every non-firewall role — a compute node has no firewall
		// data plane to check.
		checks = []proto.HealthCheck{{Name: "agent", OK: true, Critical: true, Detail: "agent responding"}}
	}
	if role == proto.RoleControlPlane {
		if c, ok := mdnsNameCheck(nameStatus()); ok {
			checks = append(checks, c)
		}
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

// missingFirewallConfigCheck is the verdict for a firewall-role node with no
// firewall configuration and no explicit opt-in. CRITICAL, and deliberately so:
// the fan-out orders the firewall LAST (planTargets' roleRank) precisely because
// losing it mid-update is the worst case, and a node whose data plane cannot be
// verified at all is not a node whose update should be committed. The detail
// names the absent path and the one way to opt a dev box out, so the fix does
// not require reading source.
func missingFirewallConfigCheck(fwConfig string) proto.HealthCheck {
	return proto.HealthCheck{
		Name: "firewall-config", OK: false, Critical: true,
		Detail: fwConfig + " is not present, so this firewall-role node is not running OpenWrt — " +
			"its data plane cannot be verified (a dev box must set " + uciBackendEnv + "=mock)",
	}
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

// nameStatus reads the mDNS name guard's latest verdict. Package var, in the
// same style as firewallConfigPath, so tests can point it at a fixed Status
// without running a guard.
var nameStatus = nameguard.Snapshot

// mdnsNameCheck maps the name guard's state onto a health check, returning
// ok=false when there is nothing to report (the guard isn't running, e.g. on a
// dev box or before its first probe completes). An unknown state must never be
// reported as a passing check — that would show green on a node that never
// looked.
//
// It is deliberately NON-critical. This gates the node.update saga's
// post-reboot commit, and a name conflict is a pre-existing network condition
// that an OS update neither caused nor can fix — rolling the update back would
// leave the operator on an older image with the same conflict, which is
// strictly worse. It is reported so the cause is visible, not enforced.
func mdnsNameCheck(s nameguard.Status) (proto.HealthCheck, bool) {
	switch s.State {
	case nameguard.StateOK:
		// Carry the address and the signal, not just "it's fine". This is the
		// only way to read current state WITHOUT waiting for a transition —
		// the guard logs on change only, so a long-healthy node prints
		// nothing, and on the bench that meant inferring the live state from
		// the absence of log lines.
		detail := s.Name + " resolves to this node"
		if s.OwnerIP != "" {
			detail += " (" + s.OwnerIP + " via " + string(s.Source) + ")"
		}
		return proto.HealthCheck{Name: "mdns-name", OK: true, Critical: false, Detail: detail}, true
	case nameguard.StateConflict:
		return proto.HealthCheck{
			Name: "mdns-name", OK: false, Critical: false,
			Detail: s.Name + " is answered by " + s.OwnerIP + ", not this node — another Rasputin cluster owns the name",
		}, true
	case nameguard.StateUnpublished:
		return proto.HealthCheck{
			Name: "mdns-name", OK: false, Critical: false,
			Detail: s.Name + " is not published by anyone — the mDNS responder has backed off",
		}, true
	default:
		return proto.HealthCheck{}, false
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
