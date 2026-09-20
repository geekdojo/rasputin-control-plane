package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// seedValues parses a generated seed the way firstboot's `.` does for these
// keys: KEY=VALUE lines, comments skipped.
// seedValues reads a seed the way the images do — through the one parser
// (proto.ParseSeed), not a second hand-rolled scan that could disagree with
// the renderer about quoting.
func seedValues(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	seed, err := proto.ParseSeed(f)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	out := map[string]string{}
	for k, v := range seed.Extra {
		out[k] = v
	}
	for k, v := range map[string]string{
		proto.SeedKeyRole:      string(seed.Role),
		proto.SeedKeyNodeID:    seed.NodeID,
		proto.SeedKeyClusterID: seed.ClusterID,
		proto.SeedKeyNATSURL:   seed.NATSURL,
		proto.SeedKeyJoinToken: seed.JoinToken,
		proto.SeedKeyBusPin:    seed.BusPin,
		proto.SeedKeySSHKey:    seed.SSHAuthorizedKey,
		proto.SeedKeyBusAuth:   seed.BusAuth,
		proto.SeedKeyBusKey:    seed.BusKey,
	} {
		if v != "" {
			out[k] = v
		}
	}
	return out
}

// A matched set is one bus key: the controlplane seed carries it, every seed
// carries its pin, and the seed-consumer contract — write RASPUTIN_BUS_KEY
// verbatim to /var/lib/rasputin/bus/bus.key — yields an api key with exactly
// that pin. The private key appears nowhere else in the output directory.
func TestGenerate_OneBusKeyPinnedByEverySeed(t *testing.T) {
	dir := t.TempDir()
	man, err := generate("home1", "", dir, nodeList{
		{Role: "controlplane", ID: "home1-cp"},
		{Role: "firewall", ID: "home1-fw"},
		{Role: "compute", ID: "home1-n1"},
	}, true, "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := proto.ParseBusPin(man.BusPin); err != nil {
		t.Fatalf("manifest busPin %q: %v", man.BusPin, err)
	}

	var keyLine string
	for _, mn := range man.Nodes {
		vals := seedValues(t, filepath.Join(dir, mn.SeedFile))
		if got := vals["RASPUTIN_BUS_PIN"]; got != man.BusPin {
			t.Errorf("%s: RASPUTIN_BUS_PIN = %q, want the set's pin %q", mn.ID, got, man.BusPin)
		}
		key, has := vals["RASPUTIN_BUS_KEY"]
		switch {
		case mn.Role == "controlplane" && !has:
			t.Errorf("%s: the controlplane seed carries no RASPUTIN_BUS_KEY", mn.ID)
		case mn.Role != "controlplane" && has:
			t.Errorf("%s: a %s seed carries the bus PRIVATE key", mn.ID, mn.Role)
		case has:
			keyLine = key
		}
	}
	if keyLine == "" {
		t.Fatal("no bus key found in any seed")
	}

	// The seed consumer's whole job, then the api's first start.
	busDir := filepath.Join(t.TempDir(), "bus")
	if err := os.MkdirAll(busDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(busDir, bustls.KeyFileName), []byte(keyLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k, generated, err := bustls.EnsureKey(busDir)
	if err != nil {
		t.Fatalf("EnsureKey on the seeded key: %v", err)
	}
	if generated {
		t.Fatal("EnsureKey generated a key although the seed provided one")
	}
	if k.Pin() != man.BusPin {
		t.Fatalf("the api's pin from the seeded key is %q, the seeds pin %q", k.Pin(), man.BusPin)
	}

	// The private key must not leak into the audit record or the preseed.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "seed-") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), keyLine) {
			t.Errorf("%s contains the bus private key", e.Name())
		}
	}
}

// Two sets never share a key: a pin identifies one cluster.
func TestGenerate_EachSetHasItsOwnBusKey(t *testing.T) {
	a, err := generate("c", "", t.TempDir(), nodeList{{Role: "controlplane"}}, true, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := generate("c", "", t.TempDir(), nodeList{{Role: "controlplane"}}, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if a.BusPin == b.BusPin {
		t.Fatalf("two matched sets share bus pin %s", a.BusPin)
	}
}
