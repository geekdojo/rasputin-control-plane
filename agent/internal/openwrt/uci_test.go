package openwrt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// ----- simulated UCI store ---------------------------------------------------

// simSection is one /etc/config/firewall section in the simulator. Option
// values are string (UCI `option`) or []string (UCI `list` — ubus returns
// those as JSON arrays).
type simSection struct {
	typ  string
	opts map[string]any
}

// simUCI is a CmdRunner that interprets the exact uci / ubus / init.d
// commands UCIRealClient emits against an in-memory model of an OpenWrt
// box. It records every call so tests can golden the command sequence,
// and its state can be hand-mutated between calls to simulate operator
// drift (the real-hardware analog of editing the mock's firewall.json).
type simUCI struct {
	calls   [][]string
	fw      []simSection
	hasFW   bool
	wan     map[string]any // nil = no network.wan section
	reloads []string
}

// stockSim models a Node N fresh from the firewall image's uci-defaults:
// unmanaged firewall sections (defaults/zones/forwarding) and a seeded
// network.wan with the hardware-role device assignment.
func stockSim() *simUCI {
	return &simUCI{
		hasFW: true,
		fw: []simSection{
			{typ: "defaults", opts: map[string]any{"input": "REJECT", "synflood_protect": "1"}},
			{typ: "zone", opts: map[string]any{"name": "lan", "input": "ACCEPT", "output": "ACCEPT", "forward": "ACCEPT"}},
			{typ: "zone", opts: map[string]any{"name": "wan", "input": "REJECT", "output": "ACCEPT", "forward": "REJECT", "masq": "1"}},
			{typ: "forwarding", opts: map[string]any{"src": "lan", "dest": "wan"}},
		},
		wan: map[string]any{"device": "eth1", "proto": "dhcp"},
	}
}

func (s *simUCI) Run(_ context.Context, name string, args ...string) (string, error) {
	s.calls = append(s.calls, append([]string{name}, args...))
	switch name {
	case "uci":
		return s.uci(args)
	case "ubus":
		return s.ubus(args)
	case "/etc/init.d/firewall":
		s.reloads = append(s.reloads, "firewall")
		return "", nil
	case "/etc/init.d/network":
		s.reloads = append(s.reloads, "network")
		return "", nil
	}
	return "", fmt.Errorf("sim: unknown binary %q", name)
}

func (s *simUCI) uci(args []string) (string, error) {
	if len(args) > 0 && args[0] == "-q" {
		args = args[1:]
	}
	if len(args) == 0 {
		return "", errors.New("sim: empty uci invocation")
	}
	switch args[0] {
	case "revert", "commit":
		return "", nil
	case "add":
		if len(args) != 3 || args[1] != "firewall" {
			return "", fmt.Errorf("sim: unsupported uci add %v", args)
		}
		s.fw = append(s.fw, simSection{typ: args[2], opts: map[string]any{}})
		s.hasFW = true
		return "", nil
	case "delete":
		return "", s.uciDelete(args[1])
	case "set":
		return "", s.uciSet(args[1])
	}
	return "", fmt.Errorf("sim: unsupported uci verb %q", args[0])
}

func (s *simUCI) uciDelete(target string) error {
	if typ, ok := strings.CutPrefix(target, "firewall.@"); ok {
		typ = strings.TrimSuffix(typ, "[-1]")
		for i := len(s.fw) - 1; i >= 0; i-- {
			if s.fw[i].typ == typ {
				s.fw = append(s.fw[:i], s.fw[i+1:]...)
				return nil
			}
		}
		return errors.New("uci: Entry not found")
	}
	if key, ok := strings.CutPrefix(target, "network.wan."); ok {
		if s.wan == nil {
			return errors.New("uci: Entry not found")
		}
		if _, exists := s.wan[key]; !exists {
			return errors.New("uci: Entry not found")
		}
		delete(s.wan, key)
		return nil
	}
	return fmt.Errorf("sim: unsupported delete target %q", target)
}

func (s *simUCI) uciSet(expr string) error {
	path, value, ok := strings.Cut(expr, "=")
	if !ok {
		return fmt.Errorf("sim: malformed set %q", expr)
	}
	if rest, found := strings.CutPrefix(path, "firewall.@"); found {
		typ, key, ok := strings.Cut(rest, "[-1].")
		if !ok {
			return fmt.Errorf("sim: malformed firewall set path %q", path)
		}
		for i := len(s.fw) - 1; i >= 0; i-- {
			if s.fw[i].typ == typ {
				s.fw[i].opts[key] = value
				return nil
			}
		}
		return errors.New("uci: Entry not found")
	}
	if key, found := strings.CutPrefix(path, "network.wan."); found {
		if s.wan == nil {
			return errors.New("uci: Entry not found")
		}
		s.wan[key] = value
		return nil
	}
	return fmt.Errorf("sim: unsupported set path %q", path)
}

func (s *simUCI) ubus(args []string) (string, error) {
	if len(args) != 4 || args[0] != "call" || args[1] != "uci" || args[2] != "get" {
		return "", fmt.Errorf("sim: unsupported ubus invocation %v", args)
	}
	var req struct {
		Config  string `json:"config"`
		Section string `json:"section"`
	}
	if err := json.Unmarshal([]byte(args[3]), &req); err != nil {
		return "", fmt.Errorf("sim: bad ubus payload: %w", err)
	}
	switch {
	case req.Config == "firewall" && req.Section == "":
		if !s.hasFW {
			return "", errors.New("Command failed: Not found")
		}
		values := map[string]any{}
		for i, sec := range s.fw {
			name := fmt.Sprintf("cfg%02d", i)
			entry := map[string]any{
				".anonymous": true,
				".type":      sec.typ,
				".name":      name,
				".index":     i,
			}
			for k, v := range sec.opts {
				entry[k] = v
			}
			values[name] = entry
		}
		b, err := json.Marshal(map[string]any{"values": values})
		return string(b), err
	case req.Config == "network" && req.Section == "wan":
		if s.wan == nil {
			return "", errors.New("Command failed: Not found")
		}
		entry := map[string]any{
			".anonymous": false,
			".type":      "interface",
			".name":      "wan",
		}
		for k, v := range s.wan {
			entry[k] = v
		}
		b, err := json.Marshal(map[string]any{"values": entry})
		return string(b), err
	}
	return "", errors.New("Command failed: Not found")
}

func (s *simUCI) sectionsOfType(typ string) []simSection {
	var out []simSection
	for _, sec := range s.fw {
		if sec.typ == typ {
			out = append(out, sec)
		}
	}
	return out
}

// ----- helpers ---------------------------------------------------------------

func newSimClient(t *testing.T, sim *simUCI) (*UCIRealClient, string) {
	t.Helper()
	dir := t.TempDir()
	c, err := newRealClient(dir, sim)
	if err != nil {
		t.Fatalf("newRealClient: %v", err)
	}
	return c, dir
}

func mustHash(t *testing.T, state map[string]any) string {
	t.Helper()
	h, err := hashState(state)
	if err != nil {
		t.Fatalf("hashState: %v", err)
	}
	return h
}

// jsonRoundTrip simulates the NATS boundary: the api marshals the compiled
// state, the agent's handler unmarshals it into map[string]any (slices
// become []any, but all values stay strings by Compile's contract).
func jsonRoundTrip(t *testing.T, state map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

func redirectMinecraft() map[string]any {
	return map[string]any{
		"name": "minecraft", "src": "wan", "src_dport": "25565",
		"dest": "lan", "dest_ip": "10.0.0.50", "dest_port": "25565",
		"proto": "tcp", "target": "DNAT",
	}
}

func ruleBlockIot() map[string]any {
	return map[string]any{
		"name": "block-iot-out", "src": "iot", "dest": "wan",
		"proto": "tcp udp", "target": "REJECT", "log": "1",
	}
}

func stateWith(redirects, rules []map[string]any, wan map[string]any) map[string]any {
	if redirects == nil {
		redirects = []map[string]any{}
	}
	if rules == nil {
		rules = []map[string]any{}
	}
	s := map[string]any{
		"firewall": map[string]any{"redirect": redirects, "rule": rules},
	}
	if wan != nil {
		s["network"] = map[string]any{"wan": wan}
	}
	return s
}

func loadManifestFile(t *testing.T, dir string) managedManifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "managed.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m managedManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	return m
}

// ----- 1. render golden --------------------------------------------------------

func TestUCIRealClient_ApplyCommandSequenceGolden(t *testing.T) {
	sim := stockSim()
	// Pre-existing managed sections (e.g. a previous apply, or LuCI drift):
	// 1 redirect + 2 rules. Apply must delete exactly those, never the
	// stock defaults/zone/forwarding sections.
	sim.fw = append(sim.fw,
		simSection{typ: "redirect", opts: map[string]any{"name": "stale"}},
		simSection{typ: "rule", opts: map[string]any{"name": "stale-1"}},
		simSection{typ: "rule", opts: map[string]any{"name": "stale-2"}},
	)
	c, _ := newSimClient(t, sim)

	state := stateWith(
		[]map[string]any{redirectMinecraft()},
		[]map[string]any{ruleBlockIot()},
		map[string]any{
			"proto": "static", "ipaddr": "203.0.113.5/24",
			"gateway": "203.0.113.1", "dns": "1.1.1.1 8.8.8.8",
		},
	)
	if _, err := c.Apply(context.Background(), state); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	want := [][]string{
		{"uci", "-q", "revert", "firewall"},
		{"ubus", "call", "uci", "get", `{"config":"firewall"}`},
		{"uci", "-q", "delete", "firewall.@redirect[-1]"},
		{"uci", "-q", "delete", "firewall.@rule[-1]"},
		{"uci", "-q", "delete", "firewall.@rule[-1]"},
		{"uci", "add", "firewall", "redirect"},
		{"uci", "set", "firewall.@redirect[-1].dest=lan"},
		{"uci", "set", "firewall.@redirect[-1].dest_ip=10.0.0.50"},
		{"uci", "set", "firewall.@redirect[-1].dest_port=25565"},
		{"uci", "set", "firewall.@redirect[-1].name=minecraft"},
		{"uci", "set", "firewall.@redirect[-1].proto=tcp"},
		{"uci", "set", "firewall.@redirect[-1].src=wan"},
		{"uci", "set", "firewall.@redirect[-1].src_dport=25565"},
		{"uci", "set", "firewall.@redirect[-1].target=DNAT"},
		{"uci", "add", "firewall", "rule"},
		{"uci", "set", "firewall.@rule[-1].dest=wan"},
		{"uci", "set", "firewall.@rule[-1].log=1"},
		{"uci", "set", "firewall.@rule[-1].name=block-iot-out"},
		{"uci", "set", "firewall.@rule[-1].proto=tcp udp"},
		{"uci", "set", "firewall.@rule[-1].src=iot"},
		{"uci", "set", "firewall.@rule[-1].target=REJECT"},
		{"uci", "commit", "firewall"},
		{"uci", "-q", "revert", "network"},
		{"uci", "set", "network.wan.proto=static"},
		{"uci", "set", "network.wan.dns=1.1.1.1 8.8.8.8"},
		{"uci", "set", "network.wan.gateway=203.0.113.1"},
		{"uci", "set", "network.wan.ipaddr=203.0.113.5/24"},
		{"uci", "commit", "network"},
		{"/etc/init.d/firewall", "reload"},
		{"/etc/init.d/network", "reload"},
	}
	if !reflect.DeepEqual(sim.calls, want) {
		t.Errorf("command sequence mismatch:\ngot:\n%s\nwant:\n%s",
			fmtCalls(sim.calls), fmtCalls(want))
	}

	// Unmanaged firewall sections survive untouched, in order.
	if got := len(sim.sectionsOfType("zone")); got != 2 {
		t.Errorf("zones touched: got %d, want 2", got)
	}
	if got := len(sim.sectionsOfType("defaults")); got != 1 {
		t.Errorf("defaults touched: got %d, want 1", got)
	}
	if got := len(sim.sectionsOfType("forwarding")); got != 1 {
		t.Errorf("forwarding touched: got %d, want 1", got)
	}
	// network.wan device (image-seeded, hardware-role-specific) untouched.
	if sim.wan["device"] != "eth1" {
		t.Errorf("network.wan.device touched: %v", sim.wan["device"])
	}
}

func fmtCalls(calls [][]string) string {
	var b strings.Builder
	for _, c := range calls {
		fmt.Fprintf(&b, "  %s\n", strings.Join(c, " "))
	}
	return b.String()
}

// ----- 2. round-trip hash agreement -------------------------------------------

func TestUCIRealClient_RoundTripHashAgreement(t *testing.T) {
	cases := []struct {
		name  string
		state map[string]any
	}{
		{"empty", emptyState()},
		{"redirects only", stateWith([]map[string]any{redirectMinecraft()}, nil, nil)},
		{"redirects and rules", stateWith(
			[]map[string]any{redirectMinecraft(), {
				"name": "ssh", "src": "wan", "src_dport": "2222",
				"dest": "lan", "dest_ip": "10.0.0.5", "dest_port": "22",
				"proto": "tcp", "target": "DNAT",
			}},
			[]map[string]any{ruleBlockIot()},
			nil)},
		{"with wan dhcp", stateWith(
			[]map[string]any{redirectMinecraft()},
			[]map[string]any{ruleBlockIot()},
			map[string]any{"proto": "dhcp", "hostname": "rasputin-fw"})},
		{"with wan static", stateWith(
			nil,
			[]map[string]any{ruleBlockIot()},
			map[string]any{
				"proto": "static", "ipaddr": "203.0.113.5/24",
				"gateway": "203.0.113.1", "dns": "1.1.1.1 8.8.8.8",
				"_comment": "ISP A",
			})},
		{"wan proto none (kill outbound)", stateWith(nil, nil, map[string]any{"proto": "none"})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sim := stockSim()
			// Pre-existing managed drift the apply must clear.
			sim.fw = append(sim.fw, simSection{typ: "rule", opts: map[string]any{"name": "stale"}})
			c, _ := newSimClient(t, sim)

			// Cross the simulated NATS boundary like production does.
			wire := jsonRoundTrip(t, tc.state)
			applied, err := c.Apply(context.Background(), wire)
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			// The agent's applied hash must equal what the api computed
			// over its own compiled map (firewall.Hash mirrors hashState).
			if want := mustHash(t, tc.state); applied != want {
				t.Errorf("applied hash %s != api-side hash %s", applied, want)
			}

			got, gotHash, err := c.Get(context.Background())
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if gotHash != applied {
				t.Errorf("in-sync system hashes differ: applied=%s observed=%s\nobserved state: %#v",
					applied, gotHash, got)
			}
		})
	}
}

func TestUCIRealClient_GetRejoinsUCIListsWithSpaces(t *testing.T) {
	// A multi-value option (UCI `list`) comes back from ubus as a JSON
	// array; Get must re-join with spaces to match Compile's emission.
	sim := stockSim()
	c, _ := newSimClient(t, sim)
	state := stateWith(nil, []map[string]any{ruleBlockIot()}, nil) // proto "tcp udp"
	applied, err := c.Apply(context.Background(), state)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Mutate the sim so the stored option becomes a list, as if the
	// section had been written with `uci add_list`.
	rules := sim.sectionsOfType("rule")
	if len(rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(rules))
	}
	for i := range sim.fw {
		if sim.fw[i].typ == "rule" {
			sim.fw[i].opts["proto"] = []string{"tcp", "udp"}
		}
	}
	_, gotHash, err := c.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotHash != applied {
		t.Errorf("list re-join failed: applied=%s observed=%s", applied, gotHash)
	}
}

func TestUCIRealClient_GetFreshBoxHashesToCanonicalEmpty(t *testing.T) {
	// No /etc/config/firewall, no manifest — must hash like the mock's
	// fresh install (== api Compile with zero intents).
	sim := &simUCI{hasFW: false}
	c, _ := newSimClient(t, sim)
	state, hash, err := c.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if want := mustHash(t, emptyState()); hash != want {
		t.Errorf("fresh box hash %s != canonical empty %s (state %#v)", hash, want, state)
	}
	if _, hasNet := state["network"]; hasNet {
		t.Errorf("fresh box must omit network key: %#v", state)
	}
}

func TestUCIRealClient_EmptyApplyDeletesAllManagedSections(t *testing.T) {
	sim := stockSim()
	sim.fw = append(sim.fw,
		simSection{typ: "redirect", opts: map[string]any{"name": "r1"}},
		simSection{typ: "redirect", opts: map[string]any{"name": "r2"}},
		simSection{typ: "rule", opts: map[string]any{"name": "x"}},
	)
	c, _ := newSimClient(t, sim)
	applied, err := c.Apply(context.Background(), emptyState())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if n := len(sim.sectionsOfType("redirect")) + len(sim.sectionsOfType("rule")); n != 0 {
		t.Errorf("managed sections remain after empty apply: %d", n)
	}
	if len(sim.fw) != 4 { // defaults + 2 zones + forwarding
		t.Errorf("unmanaged sections disturbed: %d sections left, want 4", len(sim.fw))
	}
	if want := []string{"firewall"}; !reflect.DeepEqual(sim.reloads, want) {
		t.Errorf("reloads: got %v, want %v (no network reload without network key)", sim.reloads, want)
	}
	_, gotHash, err := c.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotHash != applied {
		t.Errorf("empty state round-trip: applied=%s observed=%s", applied, gotHash)
	}
}

// ----- 3. network section-merge + manifest --------------------------------------

func TestUCIRealClient_NetworkMerge_StaticToDhcpCleansOptions(t *testing.T) {
	sim := stockSim()
	c, dir := newSimClient(t, sim)
	ctx := context.Background()

	static := stateWith(nil, nil, map[string]any{
		"proto": "static", "ipaddr": "203.0.113.5/24",
		"gateway": "203.0.113.1", "dns": "1.1.1.1 8.8.8.8",
	})
	if _, err := c.Apply(ctx, static); err != nil {
		t.Fatalf("Apply static: %v", err)
	}
	m := loadManifestFile(t, dir)
	if !m.Network {
		t.Error("manifest.Network should be true after wan apply")
	}
	if want := []string{"dns", "gateway", "ipaddr", "proto"}; !reflect.DeepEqual(m.WANKeys, want) {
		t.Errorf("manifest wanKeys: got %v, want %v", m.WANKeys, want)
	}

	sim.calls = nil
	dhcp := stateWith(nil, nil, map[string]any{"proto": "dhcp", "hostname": "rasputin-fw"})
	applied, err := c.Apply(ctx, dhcp)
	if err != nil {
		t.Fatalf("Apply dhcp: %v", err)
	}
	// Stale static options must be deleted.
	for _, k := range []string{"dns", "gateway", "ipaddr"} {
		want := []string{"uci", "-q", "delete", "network.wan." + k}
		if !containsCall(sim.calls, want) {
			t.Errorf("missing cleanup delete: %v", want)
		}
		if _, still := sim.wan[k]; still {
			t.Errorf("stale option %q survived static→dhcp", k)
		}
	}
	wantWan := map[string]any{"device": "eth1", "proto": "dhcp", "hostname": "rasputin-fw"}
	if !reflect.DeepEqual(sim.wan, wantWan) {
		t.Errorf("network.wan after transition: got %v, want %v", sim.wan, wantWan)
	}
	m = loadManifestFile(t, dir)
	if want := []string{"hostname", "proto"}; !reflect.DeepEqual(m.WANKeys, want) {
		t.Errorf("manifest wanKeys after dhcp: got %v, want %v", m.WANKeys, want)
	}
	_, gotHash, err := c.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotHash != applied {
		t.Errorf("post-transition round-trip: applied=%s observed=%s", applied, gotHash)
	}
}

func TestUCIRealClient_NetworkAbsentLeavesNetworkAlone(t *testing.T) {
	sim := stockSim()
	c, dir := newSimClient(t, sim)
	ctx := context.Background()

	withWan := stateWith(nil, nil, map[string]any{
		"proto": "static", "ipaddr": "203.0.113.5/24", "gateway": "203.0.113.1",
	})
	if _, err := c.Apply(ctx, withWan); err != nil {
		t.Fatalf("Apply with wan: %v", err)
	}
	wanBefore := map[string]any{}
	for k, v := range sim.wan {
		wanBefore[k] = v
	}

	// Apply without the network key: /etc/config/network untouched —
	// no deletes, no sets, no commit, no reload.
	sim.calls = nil
	sim.reloads = nil
	fwOnly := stateWith([]map[string]any{redirectMinecraft()}, nil, nil)
	applied, err := c.Apply(ctx, fwOnly)
	if err != nil {
		t.Fatalf("Apply without network: %v", err)
	}
	for _, call := range sim.calls {
		joined := strings.Join(call, " ")
		if strings.Contains(joined, "network") {
			t.Errorf("network touched by network-absent apply: %q", joined)
		}
	}
	if !reflect.DeepEqual(sim.wan, wanBefore) {
		t.Errorf("network.wan mutated: got %v, want %v", sim.wan, wanBefore)
	}
	if want := []string{"firewall"}; !reflect.DeepEqual(sim.reloads, want) {
		t.Errorf("reloads: got %v, want %v", sim.reloads, want)
	}

	// Manifest: network unmanaged, but the previously-set keys are
	// retained for the NEXT managed apply's cleanup.
	m := loadManifestFile(t, dir)
	if m.Network {
		t.Error("manifest.Network should be false after network-absent apply")
	}
	if want := []string{"gateway", "ipaddr", "proto"}; !reflect.DeepEqual(m.WANKeys, want) {
		t.Errorf("manifest wanKeys retained: got %v, want %v", m.WANKeys, want)
	}

	// Get now omits network entirely and agrees with the applied hash.
	got, gotHash, err := c.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, hasNet := got["network"]; hasNet {
		t.Errorf("Get emitted network while unmanaged: %#v", got)
	}
	if gotHash != applied {
		t.Errorf("round-trip: applied=%s observed=%s", applied, gotHash)
	}

	// Re-managing WAN later still cleans up the options set two applies
	// ago — this is why WANKeys survives the absent apply.
	sim.calls = nil
	dhcp := stateWith(nil, nil, map[string]any{"proto": "dhcp"})
	if _, err := c.Apply(ctx, dhcp); err != nil {
		t.Fatalf("Apply dhcp: %v", err)
	}
	for _, k := range []string{"gateway", "ipaddr"} {
		if _, still := sim.wan[k]; still {
			t.Errorf("option %q from two applies ago not cleaned up", k)
		}
	}
}

func TestUCIRealClient_NetworkCleanupDeleteIsIdempotent(t *testing.T) {
	// Operator hand-deleted an option we set; the cleanup delete fails on
	// the box but must not fail the apply.
	sim := stockSim()
	c, _ := newSimClient(t, sim)
	ctx := context.Background()
	static := stateWith(nil, nil, map[string]any{
		"proto": "static", "ipaddr": "203.0.113.5/24", "gateway": "203.0.113.1",
	})
	if _, err := c.Apply(ctx, static); err != nil {
		t.Fatalf("Apply static: %v", err)
	}
	delete(sim.wan, "ipaddr") // out-of-band operator edit
	dhcp := stateWith(nil, nil, map[string]any{"proto": "dhcp"})
	if _, err := c.Apply(ctx, dhcp); err != nil {
		t.Fatalf("Apply dhcp after operator delete: %v", err)
	}
	if sim.wan["proto"] != "dhcp" {
		t.Errorf("proto not applied: %v", sim.wan)
	}
}

// ----- 4. operator drift visibility ---------------------------------------------

func TestUCIRealClient_LuCIAddedRedirectShowsAsDrift(t *testing.T) {
	sim := stockSim()
	c, _ := newSimClient(t, sim)
	state := stateWith([]map[string]any{redirectMinecraft()}, nil, nil)
	applied, err := c.Apply(context.Background(), state)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Operator adds a redirect via LuCI behind our back.
	sim.fw = append(sim.fw, simSection{typ: "redirect", opts: map[string]any{
		"name": "luci-added", "src": "wan", "src_dport": "8080",
		"dest": "lan", "dest_ip": "10.0.0.9", "dest_port": "80",
		"proto": "tcp", "target": "DNAT",
	}})
	_, gotHash, err := c.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotHash == applied {
		t.Error("LuCI-added redirect did not change the observed hash")
	}
}

func TestUCIRealClient_HandEditedWanProtoShowsAsDrift(t *testing.T) {
	sim := stockSim()
	c, _ := newSimClient(t, sim)
	state := stateWith(nil, nil, map[string]any{"proto": "dhcp"})
	applied, err := c.Apply(context.Background(), state)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Operator flips the managed wan to static by hand.
	sim.wan["proto"] = "static"
	sim.wan["ipaddr"] = "192.0.2.10/24"
	got, gotHash, err := c.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotHash == applied {
		t.Error("hand-edited wan proto did not change the observed hash")
	}
	// The observed-proto rule surfaces the actual edit, not a stale view.
	wan := got["network"].(map[string]any)["wan"].(map[string]any)
	if wan["proto"] != "static" || wan["ipaddr"] != "192.0.2.10/24" {
		t.Errorf("observed wan should reflect the hand edit: %#v", wan)
	}
}

// ----- input validation -----------------------------------------------------------

func TestUCIRealClient_ApplyRejectsNonStringValues(t *testing.T) {
	sim := stockSim()
	c, _ := newSimClient(t, sim)
	bad := stateWith([]map[string]any{{
		"name": "oops", "src_dport": float64(25565), // number smuggled in
	}}, nil, nil)
	if _, err := c.Apply(context.Background(), bad); err == nil {
		t.Error("expected error for non-string value in compiled state")
	}
}

func TestUCIRealClient_ApplyRejectsUnknownShapes(t *testing.T) {
	cases := []struct {
		name  string
		state map[string]any
	}{
		{"unknown top-level key", map[string]any{
			"firewall": map[string]any{"redirect": []any{}, "rule": []any{}},
			"dhcp":     map[string]any{},
		}},
		{"unknown firewall section type", map[string]any{
			"firewall": map[string]any{"redirect": []any{}, "rule": []any{}, "zone": []any{}},
		}},
		{"missing firewall key", map[string]any{
			"network": map[string]any{"wan": map[string]any{"proto": "dhcp"}},
		}},
		{"network without wan", map[string]any{
			"firewall": map[string]any{"redirect": []any{}, "rule": []any{}},
			"network":  map[string]any{},
		}},
		{"network with extra section", map[string]any{
			"firewall": map[string]any{"redirect": []any{}, "rule": []any{}},
			"network": map[string]any{
				"wan": map[string]any{"proto": "dhcp"},
				"lan": map[string]any{"proto": "static"},
			},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sim := stockSim()
			c, _ := newSimClient(t, sim)
			if _, err := c.Apply(context.Background(), tc.state); err == nil {
				t.Errorf("expected validation error, got nil")
			}
		})
	}
}

func TestUCIRealClient_ApplyNilStateBehavesLikeEmpty(t *testing.T) {
	sim := stockSim()
	c, _ := newSimClient(t, sim)
	hash, err := c.Apply(context.Background(), nil)
	if err != nil {
		t.Fatalf("Apply(nil): %v", err)
	}
	if want := mustHash(t, emptyState()); hash != want {
		t.Errorf("nil state hash %s != empty-state hash %s", hash, want)
	}
}

// ----- realRunner ------------------------------------------------------------------

func TestRealRunner_CapturesStdoutAndStderr(t *testing.T) {
	out, err := realRunner{}.Run(context.Background(), "echo", "tcp udp")
	if err != nil {
		t.Fatalf("Run echo: %v", err)
	}
	if strings.TrimSpace(out) != "tcp udp" {
		t.Errorf("stdout: got %q, want %q (argv must pass spaces unquoted)", out, "tcp udp")
	}
	_, err = realRunner{}.Run(context.Background(), "sh", "-c", "echo oops >&2; exit 3")
	if err == nil {
		t.Fatal("expected error from failing command")
	}
	if !strings.Contains(err.Error(), "oops") {
		t.Errorf("error should carry stderr: %v", err)
	}
}

func containsCall(calls [][]string, want []string) bool {
	for _, c := range calls {
		if reflect.DeepEqual(c, want) {
			return true
		}
	}
	return false
}
