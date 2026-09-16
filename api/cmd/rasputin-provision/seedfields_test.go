package main

import (
	"strings"
	"testing"
)

// testPin is a well-formed pin (sha256/ + base64 of 32 zero bytes).
const testPin = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// The UI mints seeds too (ui/lib/enroll.ts), and enroll.ts claims to be
// byte-compatible with these renderers. Nothing enforces that across the
// Go/TS boundary, and the gap has now bitten twice on the same function:
// RASPUTIN_NATS_URL was hardcoded to rasputin.local (control-plane #70) and
// RASPUTIN_CLUSTER_ID was omitted entirely — which silently pinned a
// UI-enrolled firewall to the wrong cluster name, since apply-seed defaults
// the key to "rasputin" when the seed omits it.
//
// This test pins the canonical field set so a future field added here fails
// loudly and sends the author looking for the other renderer.
func TestSeedRenderers_CarryTheCanonicalFieldSet(t *testing.T) {
	want := []string{
		"RASPUTIN_NODE_ROLE=",
		"RASPUTIN_NODE_ID=",
		"RASPUTIN_CLUSTER_ID=",
		"RASPUTIN_NATS_URL=",
		"RASPUTIN_CP_JOIN_TOKEN=",
		"RASPUTIN_SSH_AUTHORIZED_KEY=",
		"RASPUTIN_BUS_PIN=",
	}
	seeds := map[string]string{
		"buildrootSeed": buildrootSeed("compute", "n1", "home1", "nats://home1.local:4222", "tok", "ssh-ed25519 AAAA me@laptop", testPin),
		"openwrtSeed":   openwrtSeed("fw1", "home1", "nats://home1.local:4222", "tok", "ssh-ed25519 AAAA me@laptop", testPin),
	}
	for name, seed := range seeds {
		for _, key := range want {
			if !strings.Contains(seed, key) {
				t.Errorf("%s: missing %s\nIf you added or removed a seed field, update ui/lib/enroll.ts to match.\ngot:\n%s", name, key, seed)
			}
		}
	}
}

// A seed whose cluster id is wrong fails SILENTLY: firstboot and apply-seed
// both default to "rasputin", so the node comes up bound to a cluster name
// nothing on this LAN answers to, and never reaches the bus or Headscale.
func TestSeedRenderers_ClusterIDIsTheGivenOne(t *testing.T) {
	for name, seed := range map[string]string{
		"buildrootSeed": buildrootSeed("compute", "n1", "home1", "nats://home1.local:4222", "tok", "", ""),
		"openwrtSeed":   openwrtSeed("fw1", "home1", "nats://home1.local:4222", "tok", "", ""),
	} {
		if !strings.Contains(seed, "RASPUTIN_CLUSTER_ID=home1\n") {
			t.Errorf("%s: cluster id is not the one passed in:\n%s", name, seed)
		}
	}
}

// The pin line sits right after the join token in both renderers, and the UI
// renderers (ui/lib/enroll.ts, pinned by ui/lib/enroll.test.ts with the same
// inputs) emit the same field lines below their own comment header.
func TestSeedRenderers_BusPinLinePosition(t *testing.T) {
	got := buildrootSeed("compute", "home1-n1", "home1", "nats://home1.local:4222", "tok", "ssh-ed25519 AAAA me@laptop", testPin)
	want := "RASPUTIN_NODE_ROLE=compute\n" +
		"RASPUTIN_NODE_ID=home1-n1\n" +
		"RASPUTIN_CLUSTER_ID=home1\n" +
		"RASPUTIN_NATS_URL=nats://home1.local:4222\n" +
		"RASPUTIN_CP_JOIN_TOKEN=tok\n" +
		"RASPUTIN_BUS_PIN=" + testPin + "\n" +
		"RASPUTIN_SSH_AUTHORIZED_KEY=\"ssh-ed25519 AAAA me@laptop\"\n"
	_, body, _ := strings.Cut(got, "\n") // drop the renderer's own comment header
	if body != want {
		t.Errorf("buildrootSeed field lines:\n%s\nwant:\n%s", body, want)
	}
	fw := openwrtSeed("home1-fw", "home1", "nats://home1.local:4222", "tok", "", testPin)
	if !strings.HasSuffix(fw, "RASPUTIN_CP_JOIN_TOKEN=tok\nRASPUTIN_BUS_PIN="+testPin+"\n") {
		t.Errorf("openwrtSeed: pin line not right after the join token:\n%s", fw)
	}
	for name, seed := range map[string]string{
		"buildrootSeed": buildrootSeed("compute", "n1", "h", "nats://h.local:4222", "tok", "", ""),
		"openwrtSeed":   openwrtSeed("fw1", "h", "nats://h.local:4222", "tok", "", ""),
	} {
		if strings.Contains(seed, "RASPUTIN_BUS_PIN") {
			t.Errorf("%s: an empty pin still rendered a line:\n%s", name, seed)
		}
	}
}
