package main

import (
	"strings"
	"testing"
)

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
	}
	seeds := map[string]string{
		"buildrootSeed": buildrootSeed("compute", "n1", "home1", "nats://home1.local:4222", "tok", "ssh-ed25519 AAAA me@laptop"),
		"openwrtSeed":   openwrtSeed("fw1", "home1", "nats://home1.local:4222", "tok", "ssh-ed25519 AAAA me@laptop"),
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
		"buildrootSeed": buildrootSeed("compute", "n1", "home1", "nats://home1.local:4222", "tok", ""),
		"openwrtSeed":   openwrtSeed("fw1", "home1", "nats://home1.local:4222", "tok", ""),
	} {
		if !strings.Contains(seed, "RASPUTIN_CLUSTER_ID=home1\n") {
			t.Errorf("%s: cluster id is not the one passed in:\n%s", name, seed)
		}
	}
}
