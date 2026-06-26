package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Compile turns a list of intents into the canonical UCI representation the
// agent's UCIClient applies. Disabled firewall intents are skipped (their
// presence is preserved in storage so users can re-enable later). Output
// shape:
//
//	{
//	  "firewall": {
//	    "redirect": [ { "name": "...", "src": "wan", ... }, ... ],
//	    "rule":     [ { "name": "...", "src": "iot", ... }, ... ]
//	  },
//	  "network": {            // present only when ≥1 wan_config row exists
//	    "wan": { "proto": ..., ... }
//	  }
//	}
//
// The "firewall" key is always present (even with empty slices) so the
// canonical-empty hash is stable across the rule/port-forward intent kinds.
// The "network" key is present **only when the user has at least one
// wan_config row** — its absence is the signal "Rasputin doesn't manage WAN
// here, leave OpenWrt's stock config alone." See firewall-integration.md
// §13 for the full state model.
//
// The returned hash is SHA-256 over json.Marshal(state). Map encoding in Go's
// encoding/json sorts keys alphabetically, so the hash is deterministic for
// any equivalent state — provided the ordering of slice elements is itself
// deterministic, which is why ListIntents enforces a stable ORDER BY.
func Compile(intents []*Intent) (map[string]any, string, error) {
	redirects := make([]map[string]any, 0, len(intents))
	rules := make([]map[string]any, 0, len(intents))

	var wanConfigSeen int
	var enabledWAN *Intent

	for _, in := range intents {
		kind := proto.FirewallIntentKind(in.Kind)
		switch kind {
		case proto.IntentPortForward:
			if !in.Enabled {
				continue
			}
			r, err := compilePortForward(in)
			if err != nil {
				return nil, "", fmt.Errorf("intent %s (%s): %w", in.ID, in.Name, err)
			}
			redirects = append(redirects, r)
		case proto.IntentFirewallRule:
			if !in.Enabled {
				continue
			}
			r, err := compileFirewallRule(in)
			if err != nil {
				return nil, "", fmt.Errorf("intent %s (%s): %w", in.ID, in.Name, err)
			}
			rules = append(rules, r)
		case proto.IntentWANConfig:
			// Count every wan_config row (enabled or not) — the existence of
			// ≥1 row is what signals "Rasputin manages WAN here." The api
			// validation layer enforces ≤1 enabled, but compile defends
			// against an inconsistent store anyway.
			wanConfigSeen++
			if in.Enabled {
				if enabledWAN != nil {
					return nil, "", fmt.Errorf("more than one wan_config is enabled (%s and %s) — at most one allowed", enabledWAN.ID, in.ID)
				}
				enabledWAN = in
			}
		default:
			return nil, "", fmt.Errorf("intent %s: unsupported kind %q", in.ID, in.Kind)
		}
	}

	state := map[string]any{
		"firewall": map[string]any{
			"redirect": redirects,
			"rule":     rules,
		},
	}

	if wanConfigSeen > 0 {
		wan, err := compileWANConfig(enabledWAN)
		if err != nil {
			return nil, "", err
		}
		state["network"] = map[string]any{"wan": wan}
	}

	h, err := Hash(state)
	if err != nil {
		return nil, "", err
	}
	return state, h, nil
}

// compileWANConfig produces the OpenWrt `network.wan` UCI section. A nil
// intent means "the user has wan_config rows but none enabled" — that's the
// explicit kill-outbound case, rendered as `proto = "none"` (OpenWrt's idiom
// for an administratively-down interface).
//
// ifname is intentionally NOT emitted — it lives in the agent's preconfigured
// `wan` section and is hardware-role-specific. We only override the proto
// and proto-specific option keys. (For a real ubus backend this implies a
// merge into /etc/config/network, not a full replace — see §6 of the doc.)
func compileWANConfig(in *Intent) (map[string]any, error) {
	if in == nil {
		return map[string]any{"proto": "none"}, nil
	}
	var spec proto.WANConfigSpec
	if err := json.Unmarshal(in.Spec, &spec); err != nil {
		return nil, fmt.Errorf("invalid wan_config spec: %w", err)
	}
	r := map[string]any{}
	switch spec.Proto {
	case proto.WANProtoDHCP:
		r["proto"] = "dhcp"
		if spec.Hostname != "" {
			r["hostname"] = spec.Hostname
		}
	case proto.WANProtoStatic:
		if spec.IP == "" {
			return nil, fmt.Errorf("static wan_config %s: ip is required", in.ID)
		}
		if spec.Gateway == "" {
			return nil, fmt.Errorf("static wan_config %s: gateway is required", in.ID)
		}
		r["proto"] = "static"
		r["ipaddr"] = spec.IP
		r["gateway"] = spec.Gateway
		if len(spec.DNS) > 0 {
			// UCI dns is a space-separated list in option form.
			r["dns"] = strings.Join(spec.DNS, " ")
		}
	case proto.WANProtoPppoe:
		if spec.Username == "" {
			return nil, fmt.Errorf("pppoe wan_config %s: username is required", in.ID)
		}
		if spec.Secret == "" {
			return nil, fmt.Errorf("pppoe wan_config %s: secret is required", in.ID)
		}
		r["proto"] = "pppoe"
		r["username"] = spec.Username
		r["password"] = spec.Secret
		if spec.Service != "" {
			r["service"] = spec.Service
		}
	case "":
		return nil, fmt.Errorf("wan_config %s: proto is required", in.ID)
	default:
		return nil, fmt.Errorf("wan_config %s: unsupported proto %q", in.ID, spec.Proto)
	}
	if spec.Comment != "" {
		r["_comment"] = spec.Comment
	}
	return r, nil
}

func compilePortForward(in *Intent) (map[string]any, error) {
	var spec proto.PortForwardSpec
	if err := json.Unmarshal(in.Spec, &spec); err != nil {
		return nil, fmt.Errorf("invalid port_forward spec: %w", err)
	}
	if spec.WanPort < 1 || spec.WanPort > 65535 {
		return nil, fmt.Errorf("wanPort out of range: %d", spec.WanPort)
	}
	if spec.LanPort < 1 || spec.LanPort > 65535 {
		return nil, fmt.Errorf("lanPort out of range: %d", spec.LanPort)
	}
	if spec.LanHost == "" {
		return nil, fmt.Errorf("lanHost is required")
	}
	if err := rejectIPv6("lanHost", spec.LanHost); err != nil {
		return nil, err
	}
	if spec.Protocol == "" {
		spec.Protocol = proto.ProtoTCP
	}
	switch spec.Protocol {
	case proto.ProtoTCP, proto.ProtoUDP, proto.ProtoTCPUDP:
	default:
		return nil, fmt.Errorf("unsupported protocol %q", spec.Protocol)
	}
	r := map[string]any{
		"name":      in.Name,
		"src":       "wan",
		"src_dport": strconv.Itoa(spec.WanPort),
		"dest":      "lan",
		"dest_ip":   spec.LanHost,
		"dest_port": strconv.Itoa(spec.LanPort),
		"proto":     ucProto(spec.Protocol),
		"target":    "DNAT",
	}
	if spec.Comment != "" {
		r["_comment"] = spec.Comment
	}
	return r, nil
}

// rejectIPv6 enforces LOCKED decision #9 (Rasputin is IPv4-only): an explicit
// IPv6 literal or IPv6 CIDR in a firewall intent's address field is rejected at
// compile time so it can never reach the firewall. IPv4 values and non-IP
// strings (a LAN hostname the firewall resolves itself) pass through — this
// guard only catches an address the user pinned to IPv6.
func rejectIPv6(field, val string) error {
	if val == "" {
		return nil
	}
	ip := net.ParseIP(val)
	if ip == nil {
		if _, ipnet, err := net.ParseCIDR(val); err == nil {
			ip = ipnet.IP
		}
	}
	if ip != nil && ip.To4() == nil {
		return fmt.Errorf("%s %q is IPv6; Rasputin is IPv4-only (decision #9)", field, val)
	}
	return nil
}

// ucProto translates the api's protocol enum into the value OpenWrt's UCI
// expects. UCI uses a space-separated list, so tcpudp becomes "tcp udp".
func ucProto(p proto.PortForwardProto) string {
	switch p {
	case proto.ProtoTCPUDP:
		return "tcp udp"
	default:
		return string(p)
	}
}

func compileFirewallRule(in *Intent) (map[string]any, error) {
	var spec proto.FirewallRuleSpec
	if err := json.Unmarshal(in.Spec, &spec); err != nil {
		return nil, fmt.Errorf("invalid firewall_rule spec: %w", err)
	}
	if spec.Src == "" {
		return nil, fmt.Errorf("src zone is required")
	}
	switch spec.Target {
	case proto.RuleTargetAccept, proto.RuleTargetReject, proto.RuleTargetDrop:
	case "":
		return nil, fmt.Errorf("target is required")
	default:
		return nil, fmt.Errorf("unsupported target %q", spec.Target)
	}

	r := map[string]any{
		"name":   in.Name,
		"src":    spec.Src,
		"target": strings.ToUpper(string(spec.Target)),
	}
	if spec.Dest != "" {
		r["dest"] = spec.Dest
	}
	if spec.SrcIP != "" {
		if err := rejectIPv6("srcIp", spec.SrcIP); err != nil {
			return nil, err
		}
		r["src_ip"] = spec.SrcIP
	}
	if spec.SrcPort != "" {
		r["src_port"] = spec.SrcPort
	}
	if spec.DestIP != "" {
		if err := rejectIPv6("destIp", spec.DestIP); err != nil {
			return nil, err
		}
		r["dest_ip"] = spec.DestIP
	}
	if spec.DestPort != "" {
		r["dest_port"] = spec.DestPort
	}
	r["proto"] = ucRuleProto(spec.Proto)
	if spec.Log {
		r["log"] = "1"
	}
	if spec.Comment != "" {
		r["_comment"] = spec.Comment
	}
	return r, nil
}

// ucRuleProto picks the UCI proto value. "any" / unset → "all" (UCI's
// wildcard); "tcpudp" → "tcp udp" (UCI's space-separated form); "icmp" and
// "igmp" pass straight through as the matching UCI proto name.
func ucRuleProto(p proto.FirewallRuleProto) string {
	switch p {
	case "", proto.RuleProtoAny:
		return "all"
	case proto.RuleProtoTCPUDP:
		return "tcp udp"
	case proto.RuleProtoIGMP:
		return "igmp"
	default:
		return string(p)
	}
}

// Hash returns the deterministic SHA-256 of the canonicalized state. Map keys
// are sorted alphabetically by encoding/json; slice ordering is the caller's
// responsibility.
func Hash(state map[string]any) (string, error) {
	b, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
