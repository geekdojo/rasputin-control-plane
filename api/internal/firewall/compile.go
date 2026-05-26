package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Compile turns a list of intents into the canonical UCI representation the
// agent's UCIClient applies. Disabled intents are skipped. Output shape:
//
//	{
//	  "firewall": {
//	    "redirect": [ { "name": "...", "src": "wan", ... }, ... ]
//	  }
//	}
//
// The returned hash is SHA-256 over json.Marshal(state). Map encoding in Go's
// encoding/json sorts keys alphabetically, so the hash is deterministic for
// any equivalent state — provided the ordering of slice elements is itself
// deterministic, which is why ListIntents enforces a stable ORDER BY.
func Compile(intents []*Intent) (map[string]any, string, error) {
	redirects := make([]map[string]any, 0, len(intents))

	for _, in := range intents {
		if !in.Enabled {
			continue
		}
		kind := proto.FirewallIntentKind(in.Kind)
		switch kind {
		case proto.IntentPortForward:
			r, err := compilePortForward(in)
			if err != nil {
				return nil, "", fmt.Errorf("intent %s (%s): %w", in.ID, in.Name, err)
			}
			redirects = append(redirects, r)
		default:
			return nil, "", fmt.Errorf("intent %s: unsupported kind %q", in.ID, in.Kind)
		}
	}

	state := map[string]any{
		"firewall": map[string]any{
			"redirect": redirects,
		},
	}
	h, err := Hash(state)
	if err != nil {
		return nil, "", err
	}
	return state, h, nil
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
