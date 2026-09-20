package obs

import (
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"gopkg.in/yaml.v3"
)

const testBusCert = "-----BEGIN CERTIFICATE-----\nMIIBbusCertLine1\nbGluZVR3bw==\n-----END CERTIFICATE-----\n"

func nodeKeyCollectorSpec() CollectorSpec {
	return CollectorSpec{
		NodeID:          "c02",
		IngressBaseURL:  "https://rasputin.local:8443",
		ServerName:      "rasputin-bus",
		BusCertPEM:      testBusCert,
		NodeKeyCertPath: proto.NodeCertPath(proto.NodeKeyCollector),
		NodeKeyPath:     proto.NodeKeyPath(proto.NodeKeyCollector),
	}
}

// The whole point of the shape: the node's private key is NOT in the compose
// file. It is bind-mounted read-only from where the agent wrote it, 0600.
func TestBuildCollectorCompose_NodeKeyShapeCarriesNoKey(t *testing.T) {
	out, err := BuildCollectorCompose(nodeKeyCollectorSpec())
	if err != nil {
		t.Fatalf("BuildCollectorCompose: %v", err)
	}
	var cf composeFile
	if err := yaml.Unmarshal([]byte(out), &cf); err != nil {
		t.Fatalf("generated compose is not valid YAML: %v\n---\n%s", err, out)
	}
	if strings.Contains(out, "PRIVATE KEY") {
		t.Fatal("the compose file contains a private key")
	}
	svc := cf.Services["alloy"]
	wantMounts := []string{
		proto.NodeCertPath(proto.NodeKeyCollector) + ":/etc/alloy/certs/node.crt:ro",
		proto.NodeKeyPath(proto.NodeKeyCollector) + ":/etc/alloy/certs/node.key:ro",
	}
	for _, want := range wantMounts {
		found := false
		for _, v := range svc.Volumes {
			if v == want {
				found = true
			}
		}
		if !found {
			t.Errorf("volume %q not mounted; got %v", want, svc.Volumes)
		}
	}
	// No leaf/key/CA configs at all in this shape.
	for _, c := range svc.Configs {
		if c.Source != "alloy_config" {
			t.Errorf("unexpected config %q in the node-key shape", c.Source)
		}
	}
	for name := range cf.Configs {
		if name != "alloy_config" {
			t.Errorf("unexpected top-level config %q in the node-key shape", name)
		}
	}
}

// Alloy is pointed at the mounted paths, trusts the bus certificate's EXACT
// bytes as its only CA, and asks for the name that certificate answers to.
func TestBuildCollectorCompose_NodeKeyAlloyConfig(t *testing.T) {
	out, err := BuildCollectorCompose(nodeKeyCollectorSpec())
	if err != nil {
		t.Fatalf("BuildCollectorCompose: %v", err)
	}
	var cf composeFile
	if err := yaml.Unmarshal([]byte(out), &cf); err != nil {
		t.Fatal(err)
	}
	alloy := cf.Configs["alloy_config"].Content
	for _, want := range []string{
		`cert_file   = "/etc/alloy/certs/node.crt"`,
		`key_file    = "/etc/alloy/certs/node.key"`,
		`server_name = "rasputin-bus"`,
	} {
		if !strings.Contains(alloy, want) {
			t.Errorf("alloy config missing %q\n---\n%s", want, alloy)
		}
	}
	if strings.Contains(alloy, "ca_file") {
		t.Error("the node-key shape must not point Alloy at a CA file")
	}
	// Both endpoints — metrics and logs — pin it, not just one.
	if n := strings.Count(alloy, "ca_pem      ="); n != 2 {
		t.Errorf("ca_pem appears %d time(s), want 2 (remote_write and loki.write)", n)
	}
	// The value is the certificate's exact bytes, as a single quoted Alloy
	// string with escaped newlines — the config language has no heredoc.
	wantLiteral := `ca_pem      = "` + strings.ReplaceAll(testBusCert, "\n", `\n`) + `"`
	if !strings.Contains(alloy, wantLiteral) {
		t.Errorf("ca_pem is not the certificate's exact bytes\nwant to contain: %s\n---\n%s", wantLiteral, alloy)
	}
}

// A node-key collector with no trust anchor is refused rather than rendered:
// Alloy would fall back to the system roots, which trust nothing the control
// plane presents.
func TestBuildCollectorCompose_NodeKeyNeedsTheBusCertificate(t *testing.T) {
	spec := nodeKeyCollectorSpec()
	spec.BusCertPEM = ""
	if _, err := BuildCollectorCompose(spec); err == nil {
		t.Fatal("a node-key collector rendered with no CA")
	}
}

// A spec naming no node key is still the legacy shape, unchanged: the mesh
// leaf, its key and the CA inline, and ca_file rather than ca_pem.
func TestBuildCollectorCompose_LegacyShapeUnchanged(t *testing.T) {
	out, err := BuildCollectorCompose(validCollectorSpec())
	if err != nil {
		t.Fatalf("BuildCollectorCompose: %v", err)
	}
	var cf composeFile
	if err := yaml.Unmarshal([]byte(out), &cf); err != nil {
		t.Fatal(err)
	}
	alloy := cf.Configs["alloy_config"].Content
	if !strings.Contains(alloy, `ca_file     = "/etc/alloy/certs/mesh-ca.pem"`) {
		t.Errorf("legacy alloy config lost its ca_file\n---\n%s", alloy)
	}
	if strings.Contains(alloy, "ca_pem") {
		t.Error("the legacy shape must not carry an inline CA")
	}
	if got := cf.Configs["leaf_key"].Content; strings.TrimSpace(got) != testLeafKey {
		t.Errorf("legacy leaf key content = %q", got)
	}
	for _, v := range cf.Services["alloy"].Volumes {
		if strings.Contains(v, "/etc/alloy/certs/node.") {
			t.Errorf("the legacy shape bind-mounted node key material: %q", v)
		}
	}
}

// A node whose registered collector key is not the one its collector is
// carrying is redeployed AT ONCE, inside the self-heal window that used to
// hold it back for up to six hours.
func TestDecideCollectorActions_RedeploysOnAChangedFact(t *testing.T) {
	now := time.Now().UTC()
	nodes := []*proto.Node{{ID: "c02", Role: proto.RoleCompute, LastSeen: now}}
	deployed := collectorWant{key: "sha256/old", trust: "busfp"}
	depState := map[string]*nodeJobState{
		"c02": {lastSuccess: now.Add(-time.Minute), deployed: deployed},
	}

	same := func(string) collectorWant { return deployed }
	act := decideCollectorActions(nodes, depState, nil, true, now, same)
	if len(act.deploy) != 0 || act.skipped["fresh"] != 1 {
		t.Fatalf("a current collector was redeployed: %+v", act)
	}

	for name, want := range map[string]collectorWant{
		"the node registered a new key":       {key: "sha256/new", trust: "busfp"},
		"the trust anchor changed":            {key: "sha256/old", trust: "othertrust"},
		"the node moved off the legacy shape": {key: "sha256/first", trust: "busfp"},
	} {
		t.Run(name, func(t *testing.T) {
			act := decideCollectorActions(nodes, depState, nil, true, now,
				func(string) collectorWant { return want })
			if len(act.deploy) != 1 || act.deploy[0] != "c02" {
				t.Fatalf("not redeployed: %+v", act)
			}
		})
	}
}

// A deploy from a release that recorded nothing reads as current, not as
// stale: otherwise the first tick after an upgrade redeploys the whole fleet
// at once. It is picked up by the safety-net interval instead.
func TestDecideCollectorActions_UnrecordedDeployIsNotStale(t *testing.T) {
	now := time.Now().UTC()
	nodes := []*proto.Node{{ID: "c02", Role: proto.RoleCompute, LastSeen: now}}
	depState := map[string]*nodeJobState{"c02": {lastSuccess: now.Add(-time.Minute)}}
	act := decideCollectorActions(nodes, depState, nil, true, now,
		func(string) collectorWant { return collectorWant{key: "sha256/new", trust: "busfp"} })
	if len(act.deploy) != 0 || act.skipped["fresh"] != 1 {
		t.Fatalf("an unrecorded deploy was treated as stale: %+v", act)
	}
	// And the safety net still picks it up.
	act = decideCollectorActions(nodes,
		map[string]*nodeJobState{"c02": {lastSuccess: now.Add(-7 * time.Hour)}}, nil, true, now,
		func(string) collectorWant { return collectorWant{} })
	if len(act.deploy) != 1 {
		t.Fatalf("the safety net did not redeploy: %+v", act)
	}
}

// wantFor is the one derivation both the reconcile and the deploy use. A node
// with a registered collector key and a configured bus certificate gets the
// node-key shape; anything missing falls back to legacy.
func TestCollectorDeployDeps_WantFor(t *testing.T) {
	full := CollectorDeployDeps{NodeKeyServerName: "rasputin-bus", BusCertPEM: testBusCert}
	keys := proto.NodeKeys{proto.NodeKeyCollector: "sha256/k", proto.NodeKeyAgent: "sha256/a"}
	got := full.wantFor(keys, testMeshCA)
	if got.key != "sha256/k" || got.trust != proto.MeshCAFingerprint([]byte(testBusCert)) {
		t.Errorf("node-key want = %+v", got)
	}
	// The AGENT key alone is not a collector key.
	got = full.wantFor(proto.NodeKeys{proto.NodeKeyAgent: "sha256/a"}, testMeshCA)
	if got.key != "" || got.trust != proto.MeshCAFingerprint([]byte(testMeshCA)) {
		t.Errorf("agent-key-only want = %+v, want the legacy shape", got)
	}
	// No bus certificate (the bus key did not load): legacy, whatever the
	// node registered.
	got = CollectorDeployDeps{}.wantFor(keys, testMeshCA)
	if got.key != "" {
		t.Errorf("want with no bus certificate = %+v, want the legacy shape", got)
	}
}
