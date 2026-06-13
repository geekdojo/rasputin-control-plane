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
	man, err := generate("home1", defaultNATSURL, dir, nodes)
	if err != nil {
		t.Fatalf("generate: %v", err)
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
	if _, err := generate("c", defaultNATSURL, dir, nodeList{{Role: "compute", ID: "n1"}}); err == nil {
		t.Error("zero controlplanes should error")
	}
	if _, err := generate("c", defaultNATSURL, dir, nodeList{
		{Role: "controlplane", ID: "cp1"}, {Role: "controlplane", ID: "cp2"},
	}); err == nil {
		t.Error("two controlplanes should error")
	}
}

func TestGenerate_RejectsDuplicateIDs(t *testing.T) {
	dir := t.TempDir()
	_, err := generate("c", defaultNATSURL, dir, nodeList{
		{Role: "controlplane", ID: "x"}, {Role: "compute", ID: "x"},
	})
	if err == nil {
		t.Error("duplicate node ids should error")
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
