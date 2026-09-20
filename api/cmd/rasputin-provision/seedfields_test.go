package main

import (
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// testPin is a well-formed pin (sha256/ + base64 of 32 zero bytes).
const testPin = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// This file used to guard a drift class that no longer exists.
//
// There were four seed renderers — buildrootSeed and openwrtSeed here,
// renderNodeSeed and renderFirewallSeed in the UI — and the tests below
// checked that the two in this package carried the same field set as the two
// in TypeScript, because nothing across that boundary could. The gap bit
// twice on the same function: RASPUTIN_NATS_URL hardcoded to rasputin.local
// (control-plane #70), and RASPUTIN_CLUSTER_ID omitted entirely, which pinned
// a UI-enrolled firewall to the wrong cluster name silently, since apply-seed
// defaults that key to "rasputin".
//
// There is now one renderer, proto.RenderSeed, and the UI renders nothing —
// it shows the seed the api returned from the same function. So these tests
// check what is still this tool's own: that it passes the right fields in,
// that a controlplane seed and a node seed differ in the ways they should,
// and that a bad value fails provisioning here rather than on a headless box.
// The renderer's own contract (quoting, ordering, refusals) is tested in
// proto.

func TestRenderSeed_CarriesTheCanonicalFieldSet(t *testing.T) {
	want := []string{
		proto.SeedKeyRole,
		proto.SeedKeyNodeID,
		proto.SeedKeyClusterID,
		proto.SeedKeyNATSURL,
		proto.SeedKeyJoinToken,
		proto.SeedKeySSHKey,
		proto.SeedKeyBusPin,
	}
	for _, role := range []proto.NodeRole{proto.RoleCompute, proto.RoleFirewall} {
		seed, err := renderSeed(proto.Seed{
			Role: role, NodeID: "n1", ClusterID: "home1",
			NATSURL: "nats://home1.local:4222", JoinToken: "tok",
			SSHAuthorizedKey: "ssh-ed25519 AAAA me@laptop", BusPin: testPin,
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range want {
			if !strings.Contains(seed, key+"=") {
				t.Errorf("%s: missing %s\ngot:\n%s", role, key, seed)
			}
		}
		if !strings.Contains(seed, "rasputin-provision") {
			t.Errorf("%s: the seed does not say what generated it:\n%s", role, seed)
		}
	}
}

// A seed whose cluster id is wrong fails SILENTLY: firstboot and apply-seed
// both default to "rasputin", so the node comes up bound to a cluster name
// nothing on this LAN answers to, and never reaches the bus or Headscale.
func TestRenderSeed_ClusterIDIsTheGivenOne(t *testing.T) {
	for _, role := range []proto.NodeRole{proto.RoleCompute, proto.RoleFirewall} {
		seed, err := renderSeed(proto.Seed{
			Role: role, NodeID: "n1", ClusterID: "home1",
			NATSURL: "nats://home1.local:4222", JoinToken: "tok",
		})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(seed, proto.SeedKeyClusterID+"='home1'\n") {
			t.Errorf("%s: cluster id is not the one passed in:\n%s", role, seed)
		}
	}
}

// The field lines, in full, for the shape this tool writes most often.
func TestRenderSeed_FieldLines(t *testing.T) {
	got, err := renderSeed(proto.Seed{
		Role: proto.RoleCompute, NodeID: "home1-n1", ClusterID: "home1",
		NATSURL: "nats://home1.local:4222", JoinToken: "tok",
		BusPin: testPin, SSHAuthorizedKey: "ssh-ed25519 AAAA me@laptop",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "RASPUTIN_NODE_ROLE='compute'\n" +
		"RASPUTIN_NODE_ID='home1-n1'\n" +
		"RASPUTIN_CLUSTER_ID='home1'\n" +
		"RASPUTIN_NATS_URL='nats://home1.local:4222'\n" +
		"RASPUTIN_CP_JOIN_TOKEN='tok'\n" +
		"RASPUTIN_BUS_PIN='" + testPin + "'\n" +
		"RASPUTIN_SSH_AUTHORIZED_KEY='ssh-ed25519 AAAA me@laptop'\n"
	_, body, _ := strings.Cut(got, "\n") // drop the comment header
	if body != want {
		t.Errorf("field lines:\n%s\nwant:\n%s", body, want)
	}
}

// An empty pin renders no line at all: the node then dials plaintext until
// the control plane delivers one, which is a different state from a pin set
// to nothing.
func TestRenderSeed_EmptyPinRendersNoLine(t *testing.T) {
	for _, role := range []proto.NodeRole{proto.RoleCompute, proto.RoleFirewall} {
		seed, err := renderSeed(proto.Seed{
			Role: role, NodeID: "n1", ClusterID: "h",
			NATSURL: "nats://h.local:4222", JoinToken: "tok",
		})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(seed, proto.SeedKeyBusPin) {
			t.Errorf("%s: an empty pin still rendered a line:\n%s", role, seed)
		}
	}
}

// A value this tool cannot write is a provisioning failure, not a seed a node
// discovers it cannot read.
func TestRenderSeed_BadValueFailsProvisioning(t *testing.T) {
	if _, err := renderSeed(proto.Seed{Role: proto.RoleCompute, NodeID: "Bad_Id"}); err == nil {
		t.Error("an invalid node id rendered without error")
	}
	if _, err := renderSeed(proto.Seed{Role: "router", NodeID: "n1"}); err == nil {
		t.Error("an unknown role rendered without error")
	}
}
