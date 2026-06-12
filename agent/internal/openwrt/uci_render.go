package openwrt

import (
	"fmt"
	"sort"
)

// applyPlan is the validated, normalized form of a compiled state map.
// wan == nil means the state had no `network` key (Rasputin doesn't manage
// WAN here); a non-nil empty map is impossible — Compile always emits at
// least `proto`.
type applyPlan struct {
	redirects []map[string]string
	rules     []map[string]string
	wan       map[string]string
}

// planFromState validates the compiled state map and normalizes it into an
// applyPlan. Strictness is deliberate: Apply returns hashState(input) as
// the applied hash, so anything in the input that the renderer would
// silently skip (an unknown section type, a non-string value) would break
// the api's exact-hash-match contract — better to hard-error here.
//
// Accepts both []map[string]any (in-process, e.g. straight from Compile in
// tests) and []any (what a NATS JSON round-trip produces) for the section
// slices. All leaf values must already be strings — Compile's contract —
// so a float64 smuggled in by a hand-built state is rejected, never
// re-rendered.
func planFromState(state map[string]any) (applyPlan, error) {
	var plan applyPlan
	for k := range state {
		if k != "firewall" && k != "network" {
			return plan, fmt.Errorf("unexpected top-level key %q in compiled state", k)
		}
	}

	fwRaw, ok := state["firewall"]
	if !ok {
		return plan, fmt.Errorf("compiled state missing required %q key", "firewall")
	}
	fw, ok := fwRaw.(map[string]any)
	if !ok {
		return plan, fmt.Errorf("firewall key is %T, want map", fwRaw)
	}
	for k := range fw {
		if k != "redirect" && k != "rule" {
			return plan, fmt.Errorf("unexpected firewall section type %q in compiled state", k)
		}
	}
	var err error
	if plan.redirects, err = sectionList(fw["redirect"]); err != nil {
		return plan, fmt.Errorf("firewall.redirect: %w", err)
	}
	if plan.rules, err = sectionList(fw["rule"]); err != nil {
		return plan, fmt.Errorf("firewall.rule: %w", err)
	}

	if netRaw, ok := state["network"]; ok {
		net, ok := netRaw.(map[string]any)
		if !ok {
			return plan, fmt.Errorf("network key is %T, want map", netRaw)
		}
		for k := range net {
			if k != "wan" {
				return plan, fmt.Errorf("unexpected network section %q in compiled state", k)
			}
		}
		wanRaw, ok := net["wan"]
		if !ok {
			return plan, fmt.Errorf("network key present but missing wan section")
		}
		wanMap, ok := wanRaw.(map[string]any)
		if !ok {
			return plan, fmt.Errorf("network.wan is %T, want map", wanRaw)
		}
		if plan.wan, err = stringMap(wanMap); err != nil {
			return plan, fmt.Errorf("network.wan: %w", err)
		}
	}
	return plan, nil
}

// sectionList normalizes a compiled section slice. nil → empty (Compile
// always emits both slices, but be lenient about an explicit empty).
func sectionList(v any) ([]map[string]string, error) {
	switch s := v.(type) {
	case nil:
		return []map[string]string{}, nil
	case []map[string]any:
		out := make([]map[string]string, 0, len(s))
		for i, m := range s {
			sm, err := stringMap(m)
			if err != nil {
				return nil, fmt.Errorf("entry %d: %w", i, err)
			}
			out = append(out, sm)
		}
		return out, nil
	case []any:
		out := make([]map[string]string, 0, len(s))
		for i, e := range s {
			m, ok := e.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("entry %d is %T, want map", i, e)
			}
			sm, err := stringMap(m)
			if err != nil {
				return nil, fmt.Errorf("entry %d: %w", i, err)
			}
			out = append(out, sm)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("section list is %T, want slice", v)
	}
}

// stringMap asserts every value is a string. Compile emits only strings
// (ports through strconv.Itoa, log as "1") precisely so JSON round-trips
// can't produce float64s; anything else is a contract violation.
func stringMap(m map[string]any) (map[string]string, error) {
	out := make(map[string]string, len(m))
	for k, v := range m {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("value for %q is %T, want string (compiled state must be all strings)", k, v)
		}
		out[k] = s
	}
	return out, nil
}

// renderFirewallCommands produces the deterministic uci argv sequence that
// replaces the managed firewall section types:
//
//  1. Delete every existing redirect, then every existing rule, last-first
//     (`uci -q delete firewall.@redirect[-1]` × count observed just
//     before rendering). Count-bounded rather than delete-until-error so
//     a real uci failure mid-apply can't masquerade as "done".
//  2. Recreate each section in slice order (`uci add` + `uci set` per
//     option, option keys sorted for a stable sequence).
//  3. `uci commit firewall`.
//
// Idempotent: re-running the same state deletes what step 2 created last
// time and recreates it identically.
func renderFirewallCommands(nRedirect, nRule int, redirects, rules []map[string]string) [][]string {
	var cmds [][]string
	for i := 0; i < nRedirect; i++ {
		cmds = append(cmds, []string{"uci", "-q", "delete", "firewall.@redirect[-1]"})
	}
	for i := 0; i < nRule; i++ {
		cmds = append(cmds, []string{"uci", "-q", "delete", "firewall.@rule[-1]"})
	}
	for _, r := range redirects {
		cmds = append(cmds, []string{"uci", "add", "firewall", "redirect"})
		for _, k := range sortedKeys(r) {
			cmds = append(cmds, []string{"uci", "set", "firewall.@redirect[-1]." + k + "=" + r[k]})
		}
	}
	for _, r := range rules {
		cmds = append(cmds, []string{"uci", "add", "firewall", "rule"})
		for _, k := range sortedKeys(r) {
			cmds = append(cmds, []string{"uci", "set", "firewall.@rule[-1]." + k + "=" + r[k]})
		}
	}
	cmds = append(cmds, []string{"uci", "commit", "firewall"})
	return cmds
}

// renderNetworkCommands produces the section-merge sequence for
// network.wan. deletes removes previously-Rasputin-set option keys
// (prevKeys, from the manifest) that the new state no longer carries —
// e.g. switching static→dhcp removes ipaddr/gateway/dns. sets writes
// `proto` first (reads naturally in a uci changelog), then the remaining
// keys sorted. The caller commits.
func renderNetworkCommands(prevKeys []string, wan map[string]string) (deletes, sets [][]string) {
	for _, k := range prevKeys {
		if _, still := wan[k]; !still {
			deletes = append(deletes, []string{"uci", "-q", "delete", "network.wan." + k})
		}
	}
	if v, ok := wan["proto"]; ok {
		sets = append(sets, []string{"uci", "set", "network.wan.proto=" + v})
	}
	for _, k := range sortedKeys(wan) {
		if k == "proto" {
			continue
		}
		sets = append(sets, []string{"uci", "set", "network.wan." + k + "=" + wan[k]})
	}
	return deletes, sets
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
