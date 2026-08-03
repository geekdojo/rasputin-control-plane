package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
)

// End-to-end: generate a matched set, then prove the controlplane half (the
// preseed) accepts exactly the per-node tokens, each bound to its own node.
func TestGenerate_MatchedSetRoundTrips(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	nodes := nodeList{
		{Role: "controlplane", ID: "home1-cp"},
		{Role: "firewall", ID: "home1-fw"},
		{Role: "compute", ID: "home1-n1"},
		{Role: "compute"}, // id auto-assigned
	}
	man, err := generate("home1", "", dir, nodes, true, "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !man.Enforce {
		t.Error("manifest should record enforce=true")
	}
	if len(man.Nodes) != 4 {
		t.Fatalf("manifest has %d nodes, want 4", len(man.Nodes))
	}

	// Load the controlplane preseed into a fresh store (what firstboot + api do).
	store, err := busauth.OpenStore(ctx, filepath.Join(dir, "bus.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	preseedRaw, err := os.ReadFile(filepath.Join(dir, "controlplane-bus-tokens.json"))
	if err != nil {
		t.Fatalf("read preseed: %v", err)
	}
	var preseed []busauth.PreseedToken
	if err := json.Unmarshal(preseedRaw, &preseed); err != nil {
		t.Fatalf("unmarshal preseed: %v", err)
	}
	if len(preseed) != 3 { // controlplane has no token
		t.Fatalf("preseed has %d entries, want 3", len(preseed))
	}
	if _, err := store.PreloadHashes(ctx, preseed); err != nil {
		t.Fatalf("PreloadHashes: %v", err)
	}

	// For each token-bearing node, the token in its seed validates ONLY for it.
	var someToken, someID, otherID string
	for _, mn := range man.Nodes {
		if mn.Role == "controlplane" {
			// Controlplane seed carries no token, dials loopback.
			seed := readSeed(t, dir, mn.SeedFile)
			if strings.Contains(seed, "RASPUTIN_CP_JOIN_TOKEN") {
				t.Errorf("controlplane seed must not carry a join token:\n%s", seed)
			}
			if !strings.Contains(seed, "RASPUTIN_NATS_URL="+loopbackNATSURL) {
				t.Errorf("controlplane should dial loopback NATS:\n%s", seed)
			}
			if !strings.Contains(seed, "RASPUTIN_BUS_AUTH=enforce") {
				t.Errorf("controlplane seed should ship enforce on:\n%s", seed)
			}
			continue
		}
		seed := readSeed(t, dir, mn.SeedFile)
		token := seedValue(seed, "RASPUTIN_CP_JOIN_TOKEN")
		if token == "" {
			t.Fatalf("node %s seed missing token:\n%s", mn.ID, seed)
		}
		if seedValue(seed, "RASPUTIN_NODE_ID") != mn.ID {
			t.Errorf("node %s seed has wrong RASPUTIN_NODE_ID", mn.ID)
		}
		ok, err := store.Validate(ctx, token, mn.ID)
		if err != nil || !ok {
			t.Errorf("token for %s should validate as itself: ok=%v err=%v", mn.ID, ok, err)
		}
		someToken, someID = token, mn.ID
		if mn.ID != someID {
			otherID = mn.ID
		}
	}

	// A token must NOT validate as a different node (binding holds).
	for _, mn := range man.Nodes {
		if mn.Role != "controlplane" && mn.ID != someID {
			otherID = mn.ID
			break
		}
	}
	if otherID == "" {
		t.Fatal("test needs a second token-bearing node")
	}
	if ok, _ := store.Validate(ctx, someToken, otherID); ok {
		t.Errorf("token bound to %s must NOT validate as %s", someID, otherID)
	}
}

func TestGenerate_RequiresExactlyOneControlplane(t *testing.T) {
	dir := t.TempDir()
	if _, err := generate("c", "", dir, nodeList{{Role: "compute", ID: "n1"}}, true, ""); err == nil {
		t.Error("zero controlplanes should error")
	}
	if _, err := generate("c", "", dir, nodeList{
		{Role: "controlplane", ID: "cp1"}, {Role: "controlplane", ID: "cp2"},
	}, true, ""); err == nil {
		t.Error("two controlplanes should error")
	}
}

func TestGenerate_RejectsDuplicateIDs(t *testing.T) {
	dir := t.TempDir()
	_, err := generate("c", "", dir, nodeList{
		{Role: "controlplane", ID: "x"}, {Role: "compute", ID: "x"},
	}, true, "")
	if err == nil {
		t.Error("duplicate node ids should error")
	}
}

// Every seed — controlplane, firewall, compute — carries the operator key,
// double-quoted (the seed is sourced by sh; the value has spaces). Images
// bake no key, so this line is the only network-SSH path (dog food: the
// bench provisions the same way end users do).
func TestGenerate_SSHKeyInEverySeed(t *testing.T) {
	dir := t.TempDir()
	const key = "ssh-ed25519 AAAATestKey bryce@geekdojo.com"

	nodes := nodeList{
		{Role: "controlplane", ID: "c-cp"},
		{Role: "firewall", ID: "c-fw"},
		{Role: "compute", ID: "c-n1"},
	}
	man, err := generate("c", "", dir, nodes, true, key)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !man.SSHKey {
		t.Error("manifest should record sshAuthorizedKey=true")
	}
	for _, mn := range man.Nodes {
		seed := readSeed(t, dir, mn.SeedFile)
		want := `RASPUTIN_SSH_AUTHORIZED_KEY="` + key + `"`
		if !strings.Contains(seed, want+"\n") {
			t.Errorf("%s (%s) seed missing quoted ssh key line %q:\n%s", mn.ID, mn.Role, want, seed)
		}
	}

	// And with no key: no line, manifest records false.
	dir2 := t.TempDir()
	man2, err := generate("c", "", dir2, nodeList{{Role: "controlplane", ID: "c-cp"}}, true, "")
	if err != nil {
		t.Fatalf("generate (no key): %v", err)
	}
	if man2.SSHKey {
		t.Error("manifest should record sshAuthorizedKey=false")
	}
	if seed := readSeed(t, dir2, man2.Nodes[0].SeedFile); strings.Contains(seed, "RASPUTIN_SSH_AUTHORIZED_KEY") {
		t.Errorf("keyless seed must not carry an ssh-key line:\n%s", seed)
	}
}

func TestResolveSSHKey(t *testing.T) {
	const good = "ssh-ed25519 AAAATestKey bryce@geekdojo.com"

	if got, err := resolveSSHKey("  "+good+"\n", ""); err != nil || got != good {
		t.Errorf("literal key should trim + pass: got %q err %v", got, err)
	}
	if got, err := resolveSSHKey("", ""); err != nil || got != "" {
		t.Errorf("no key is valid (console/UI-only): got %q err %v", got, err)
	}

	keyFile := filepath.Join(t.TempDir(), "id.pub")
	if err := os.WriteFile(keyFile, []byte(good+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveSSHKey("", keyFile); err != nil || got != good {
		t.Errorf("file key should pass: got %q err %v", got, err)
	}

	for name, in := range map[string]string{
		"both flags":   "", // handled below
		"multi-line":   good + "\n" + good,
		"double quote": `ssh-ed25519 AAAA "cmt"`,
		"dollar":       "ssh-ed25519 AAAA $HOME",
		"not a key":    "hunter2",
		"private key":  "-----BEGIN OPENSSH PRIVATE KEY----- x",
	} {
		var err error
		if name == "both flags" {
			_, err = resolveSSHKey(good, keyFile)
		} else {
			_, err = resolveSSHKey(in, "")
		}
		if err == nil {
			t.Errorf("%s should be rejected", name)
		}
	}
}

func TestNodeList_Set(t *testing.T) {
	var n nodeList
	if err := n.Set("compute:n1"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if n[0].Role != "compute" || n[0].ID != "n1" {
		t.Errorf("parsed %+v", n[0])
	}
	if err := n.Set("bogus:x"); err == nil {
		t.Error("unknown role should error")
	}
}

func readSeed(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read seed %s: %v", name, err)
	}
	return string(b)
}

func seedValue(seed, key string) string {
	for _, line := range strings.Split(seed, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && k == key {
			return v
		}
	}
	return ""
}

// Every seed must carry the cluster id. It exists today only in the manifest —
// an operator-facing audit record that no node ever reads — so the name a
// cluster was provisioned under reaches nothing on the box. ADR-0003 makes the
// cluster id the source of the node's identity (mDNS hostname, NATS URL,
// Headscale server_url, leaf SANs, RP ID), and none of that is reachable until
// the value is in the seed.
func TestGenerate_ClusterIDInEverySeed(t *testing.T) {
	dir := t.TempDir()
	man, err := generate("home1", "nats://rasputin.local:4222", dir, nodeList{
		{Role: "controlplane"}, {Role: "firewall"}, {Role: "compute"},
	}, true, "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if man.ClusterID != "home1" {
		t.Fatalf("manifest cluster id = %q, want home1", man.ClusterID)
	}
	for _, n := range man.Nodes {
		b, err := os.ReadFile(filepath.Join(dir, n.SeedFile))
		if err != nil {
			t.Fatalf("read seed for %s: %v", n.ID, err)
		}
		if !strings.Contains(string(b), "RASPUTIN_CLUSTER_ID=home1\n") {
			t.Errorf("%s seed (%s) is missing RASPUTIN_CLUSTER_ID=home1:\n%s", n.Role, n.ID, b)
		}
	}
}

// The seed is sourced by sh, so the cluster id must render as a bare, unquoted
// token. A value needing quotes would break every field after it — the same
// class of defect that shipped a truncated recovery command in the agent unit.
func TestBuildrootSeed_ClusterIDIsBareToken(t *testing.T) {
	seed := buildrootSeed("controlplane", "cp1", "home1", "nats://127.0.0.1:4222", "", "")
	if !strings.Contains(seed, "\nRASPUTIN_CLUSTER_ID=home1\n") {
		t.Errorf("cluster id should render bare and unquoted, got:\n%s", seed)
	}
	fw := openwrtSeed("fw1", "home1", "nats://rasputin.local:4222", "tok", "")
	if !strings.Contains(fw, "\nRASPUTIN_CLUSTER_ID=home1\n") {
		t.Errorf("firewall seed should carry the cluster id, got:\n%s", fw)
	}
}

// The seeded bus address must follow the cluster's name, not a shared literal
// — otherwise a cluster named home1 would seed its nodes to dial
// rasputin.local, which is either nothing or, worse, SOMEONE ELSE'S control
// plane on the same LAN.
func TestGenerate_NATSURLDerivesFromClusterID(t *testing.T) {
	dir := t.TempDir()
	man, err := generate("home1", "", dir, nodeList{{Role: "controlplane"}, {Role: "compute"}}, true, "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if man.NATSURL != "nats://home1.local:4222" {
		t.Fatalf("manifest natsUrl = %q, want nats://home1.local:4222", man.NATSURL)
	}
	var compute manifestNode
	for _, n := range man.Nodes {
		if n.Role == "compute" {
			compute = n
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, compute.SeedFile))
	if err != nil {
		t.Fatalf("read compute seed: %v", err)
	}
	if !strings.Contains(string(b), "RASPUTIN_NATS_URL=nats://home1.local:4222\n") {
		t.Errorf("compute seed should dial the cluster's own name:\n%s", b)
	}
	// The controlplane always dials its own loopback so it is trusted without a
	// token — that must NOT follow the cluster name.
	var cp manifestNode
	for _, n := range man.Nodes {
		if n.Role == "controlplane" {
			cp = n
		}
	}
	cpSeed, err := os.ReadFile(filepath.Join(dir, cp.SeedFile))
	if err != nil {
		t.Fatalf("read controlplane seed: %v", err)
	}
	if !strings.Contains(string(cpSeed), "RASPUTIN_NATS_URL=nats://127.0.0.1:4222\n") {
		t.Errorf("controlplane must still dial loopback, not the cluster name:\n%s", cpSeed)
	}
}

// The no-migration promise again: the default cluster id must derive exactly
// the constant this replaced.
func TestDefaultClusterIDDerivesTodaysNATSURL(t *testing.T) {
	if got := defaultNATSURLFor("rasputin"); got != "nats://rasputin.local:4222" {
		t.Errorf("defaultNATSURLFor(rasputin) = %q, want the literal it replaced", got)
	}
}

// An explicit --nats-url still wins — a cluster reached over a tailnet host
// does not want a .local name.
func TestExplicitNATSURLWins(t *testing.T) {
	dir := t.TempDir()
	man, err := generate("home1", "nats://cp.tail1234.ts.net:4222", dir, nodeList{{Role: "controlplane"}}, true, "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if man.NATSURL != "nats://cp.tail1234.ts.net:4222" {
		t.Errorf("explicit --nats-url should win, got %q", man.NATSURL)
	}
}

// --- DNS-label validation (ADR-0003) -----------------------------------------

// The cluster id becomes the controlplane's mDNS hostname, its TLS leaf
// CN/SAN, its WebAuthn RP ID, and the host every node dials. Catch a bad one
// at the operator's keyboard — rasputin-hostname.sh can only fall back to
// "rasputin" and log, at boot, on a headless box, three layers from the typo.
func TestNormalizeDNSLabel(t *testing.T) {
	ok := []struct{ in, want string }{
		{"home1", "home1"},
		{"Home1", "home1"},     // case-insensitive, normalized not rejected
		{"  home1  ", "home1"}, // stray whitespace from a shell paste
		{"my-cluster", "my-cluster"},
		{"r2", "r2"},
		{strings.Repeat("x", 63), strings.Repeat("x", 63)}, // exactly at the limit
	}
	for _, tc := range ok {
		got, err := normalizeDNSLabel("cluster id", tc.in)
		if err != nil {
			t.Errorf("normalizeDNSLabel(%q) errored: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("normalizeDNSLabel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	bad := []string{
		"", "   ",
		"-home1", "home1-",
		"has_underscore",
		"has space",
		"UPPER_BAD",
		strings.Repeat("x", 64), // one past the limit
	}
	for _, in := range bad {
		if got, err := normalizeDNSLabel("cluster id", in); err == nil {
			t.Errorf("normalizeDNSLabel(%q) = %q, want an error", in, got)
		}
	}
}

// A dotted id is the failure worth naming: it looks perfectly reasonable, and
// it is the one form ADR-0003 rules out — systemd-resolved publishes only a
// single-label <hostname>.local, so "home.lab" yields a name nothing can
// advertise. The error must say so rather than just "invalid character".
func TestDottedClusterIDExplainsWhy(t *testing.T) {
	_, err := normalizeDNSLabel("cluster id", "home.lab")
	if err == nil {
		t.Fatal("a dotted cluster id must be rejected")
	}
	if !strings.Contains(err.Error(), "multi-label") {
		t.Errorf("error should explain the mDNS consequence, got: %v", err)
	}
}

func TestGenerate_RejectsInvalidClusterID(t *testing.T) {
	_, err := generate("my_cluster", "", t.TempDir(), nodeList{{Role: "controlplane"}}, true, "")
	if err == nil {
		t.Fatal("generate should reject a cluster id that cannot be a hostname")
	}
}

// An operator-supplied node id becomes THAT node's hostname, so it faces the
// same constraint. Auto-assigned ids are valid by construction; these are not.
func TestGenerate_RejectsInvalidNodeID(t *testing.T) {
	_, err := generate("home1", "", t.TempDir(), nodeList{
		{Role: "controlplane"}, {Role: "compute", ID: "bad_node"},
	}, true, "")
	if err == nil {
		t.Fatal("generate should reject a node id that cannot be a hostname")
	}
}

// Normalization must reach the artifacts, not just the validation gate: the
// seed, the node ids derived from the cluster id, and the manifest.
func TestGenerate_NormalizesIntoArtifacts(t *testing.T) {
	dir := t.TempDir()
	man, err := generate("Home1", "", dir, nodeList{{Role: "controlplane"}, {Role: "compute"}}, true, "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if man.ClusterID != "home1" {
		t.Errorf("manifest cluster id = %q, want the lowercased form", man.ClusterID)
	}
	if man.NATSURL != "nats://home1.local:4222" {
		t.Errorf("natsUrl = %q, want the lowercased name", man.NATSURL)
	}
	for _, n := range man.Nodes {
		if strings.ToLower(n.ID) != n.ID {
			t.Errorf("node id %q should be lowercase", n.ID)
		}
		b, err := os.ReadFile(filepath.Join(dir, n.SeedFile))
		if err != nil {
			t.Fatalf("read seed: %v", err)
		}
		if !strings.Contains(string(b), "RASPUTIN_CLUSTER_ID=home1\n") {
			t.Errorf("%s seed should carry the normalized cluster id:\n%s", n.ID, b)
		}
	}
}
