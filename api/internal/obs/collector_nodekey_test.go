package obs

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"gopkg.in/yaml.v3"
)

// testBusCert stands in for the bus certificate a previous release pinned as
// a keyed collector's ca_pem. Only its fingerprint matters here: it is what a
// collector deployed by that release has recorded as its trust.
const testBusCert = "-----BEGIN CERTIFICATE-----\nMIIBbusCertLine1\nbGluZVR3bw==\n-----END CERTIFICATE-----\n"

func nodeKeyCollectorSpec() CollectorSpec {
	return CollectorSpec{
		NodeID:          "c02",
		IngressBaseURL:  "https://home1.local:8443",
		ServerName:      "home1.local",
		MeshCAPEM:       testMeshCA,
		NodeKeyCertPath: proto.NodeCertPath(proto.NodeKeyCollector),
		NodeKeyPath:     proto.NodeKeyPath(proto.NodeKeyCollector),
	}
}

func renderCompose(t *testing.T, spec CollectorSpec) (string, composeFile) {
	t.Helper()
	out, err := BuildCollectorCompose(spec)
	if err != nil {
		t.Fatalf("BuildCollectorCompose: %v", err)
	}
	var cf composeFile
	if err := yaml.Unmarshal([]byte(out), &cf); err != nil {
		t.Fatalf("generated compose is not valid YAML: %v\n---\n%s", err, out)
	}
	return out, cf
}

// TC-672-01: a keyed collector trusts the api by the Mesh chain under the
// cluster name, on both endpoints, presents the node's own key from read-only
// binds, and carries no private key and nothing of the bus certificate.
func TestBuildCollectorCompose_NodeKeyShapeTrustsTheMeshChain(t *testing.T) {
	out, cf := renderCompose(t, nodeKeyCollectorSpec())
	alloy := cf.Configs["alloy_config"].Content

	if n := strings.Count(alloy, `ca_file     = "/etc/alloy/certs/mesh-ca.pem"`); n != 2 {
		t.Errorf("ca_file trust line appears %d time(s), want 2 (remote_write and loki.write)\n---\n%s", n, alloy)
	}
	if n := strings.Count(alloy, `server_name = "home1.local"`); n != 2 {
		t.Errorf("server_name = home1.local appears %d time(s), want 2", n)
	}
	for _, want := range []string{
		`cert_file   = "/etc/alloy/certs/node.crt"`,
		`key_file    = "/etc/alloy/certs/node.key"`,
	} {
		if n := strings.Count(alloy, want); n != 2 {
			t.Errorf("%s appears %d time(s), want 2", want, n)
		}
	}

	if got := strings.TrimRight(cf.Configs["mesh_ca"].Content, "\n"); got != testMeshCA {
		t.Errorf("mesh_ca config content = %q, want the Mesh CA", got)
	}
	svc := cf.Services["alloy"]
	mounted := false
	for _, c := range svc.Configs {
		if c.Source == "mesh_ca" && c.Target == collectorMeshCAPath {
			mounted = true
		}
		if c.Source == "leaf_cert" || c.Source == "leaf_key" {
			t.Errorf("the node-key shape carries legacy config %q", c.Source)
		}
	}
	if !mounted {
		t.Errorf("mesh_ca is not mounted at %s; configs = %+v", collectorMeshCAPath, svc.Configs)
	}
	for _, want := range []string{
		proto.NodeCertPath(proto.NodeKeyCollector) + ":/etc/alloy/certs/node.crt:ro",
		proto.NodeKeyPath(proto.NodeKeyCollector) + ":/etc/alloy/certs/node.key:ro",
	} {
		if !containsStr(svc.Volumes, want) {
			t.Errorf("volume %q not mounted; got %v", want, svc.Volumes)
		}
	}
	if strings.Contains(out, "PRIVATE KEY") {
		t.Error("the compose file contains a private key")
	}
	if strings.Contains(out, "rasputin-bus") {
		t.Error("the compose file still names the bus certificate")
	}
}

// TC-672-02: no exact-bytes ca_pem on any path.
func TestBuildCollectorCompose_NoCAPEMOnAnyPath(t *testing.T) {
	for name, spec := range map[string]CollectorSpec{
		"keyed":  nodeKeyCollectorSpec(),
		"legacy": validCollectorSpec(),
	} {
		out, _ := renderCompose(t, spec)
		if strings.Contains(out, "ca_pem") {
			t.Errorf("%s: the compose renders ca_pem", name)
		}
	}
}

// TC-672-03: a missing or blank Mesh CA is refused for either shape, with no
// compose rendered, so Alloy never falls back to the system roots.
func TestBuildCollectorCompose_RefusesWithNoMeshCA(t *testing.T) {
	for name, spec := range map[string]CollectorSpec{
		"keyed":  nodeKeyCollectorSpec(),
		"legacy": validCollectorSpec(),
	} {
		for _, ca := range []string{"", "  \n"} {
			spec.MeshCAPEM = ca
			out, err := BuildCollectorCompose(spec)
			if out != "" || err == nil || !strings.Contains(err.Error(), "MeshCAPEM required") {
				t.Errorf("%s, MeshCAPEM %q = (%d bytes, %v), want (\"\", MeshCAPEM required)", name, ca, len(out), err)
			}
		}
	}
}

// TC-672-04: the legacy shape is otherwise unchanged: leaf and key inline,
// the same trust line, the spec's server_name, no node-key bind, and an
// empty leaf or key still refused.
func TestBuildCollectorCompose_LegacyShapeUnchanged(t *testing.T) {
	_, cf := renderCompose(t, validCollectorSpec())
	alloy := cf.Configs["alloy_config"].Content
	if n := strings.Count(alloy, collectorTrustLine); n != 2 {
		t.Errorf("legacy trust line appears %d time(s), want 2\n---\n%s", n, alloy)
	}
	if !strings.Contains(alloy, `server_name = "rasputin.local"`) {
		t.Errorf("legacy server_name is not the spec's\n---\n%s", alloy)
	}
	if got := strings.TrimRight(cf.Configs["leaf_cert"].Content, "\n"); got != testLeafCert {
		t.Errorf("legacy leaf cert content = %q", got)
	}
	if got := strings.TrimRight(cf.Configs["leaf_key"].Content, "\n"); got != testLeafKey {
		t.Errorf("legacy leaf key content = %q", got)
	}
	for _, v := range cf.Services["alloy"].Volumes {
		if strings.Contains(v, "/etc/alloy/certs/node.") {
			t.Errorf("the legacy shape bind-mounted node key material: %q", v)
		}
	}
	for _, blank := range []func(*CollectorSpec){
		func(s *CollectorSpec) { s.LeafCertPEM = "" },
		func(s *CollectorSpec) { s.LeafKeyPEM = "" },
	} {
		spec := validCollectorSpec()
		blank(&spec)
		if _, err := BuildCollectorCompose(spec); err == nil {
			t.Error("a legacy collector rendered with no leaf cert or key")
		}
	}
}

// TC-672-05: one TLS block for every caller. collectorTLSConfig carries the
// given paths and name plus collectorTrustLine, and both endpoints of a
// rendered collector contain it byte for byte.
func TestCollectorTLSConfig_IsTheRenderedBlock(t *testing.T) {
	got := collectorTLSConfig("/c.pem", "/k.pem", "probe.rasputin.test")
	for _, want := range []string{
		`cert_file   = "/c.pem"`,
		`key_file    = "/k.pem"`,
		collectorTrustLine,
		`server_name = "probe.rasputin.test"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("collectorTLSConfig missing %q:\n%s", want, got)
		}
	}
	if collectorTrustLine != `ca_file     = "/etc/alloy/certs/mesh-ca.pem"` {
		t.Errorf("collectorTrustLine = %q", collectorTrustLine)
	}
	for name, spec := range map[string]CollectorSpec{
		"keyed":  nodeKeyCollectorSpec(),
		"legacy": validCollectorSpec(),
	} {
		cert, key := collectorNodeKeyCertPath, collectorNodeKeyPath
		if spec.Legacy() {
			cert, key = collectorLeafCertPath, collectorLeafKeyPath
		}
		_, cf := renderCompose(t, spec)
		block := collectorTLSConfig(cert, key, spec.ServerName)
		if n := strings.Count(cf.Configs["alloy_config"].Content, block); n != 2 {
			t.Errorf("%s: collectorTLSConfig output appears %d time(s) in the alloy config, want 2", name, n)
		}
	}
}

// TC-672-06: wantFor is the registered collector key (or none) and the Mesh
// CA's fingerprint, whatever the shape; no CA gives no trust fingerprint.
func TestCollectorDeployDeps_WantFor(t *testing.T) {
	d := CollectorDeployDeps{MeshCAPEM: testMeshCA}
	caFP := proto.MeshCAFingerprint([]byte(testMeshCA))
	keys := proto.NodeKeys{proto.NodeKeyCollector: "sha256/k", proto.NodeKeyAgent: "sha256/a"}
	if got := d.wantFor(keys); got != (collectorWant{key: "sha256/k", trust: caFP}) {
		t.Errorf("keyed want = %+v", got)
	}
	// The AGENT key alone is not a collector key.
	if got := d.wantFor(proto.NodeKeys{proto.NodeKeyAgent: "sha256/a"}); got != (collectorWant{trust: caFP}) {
		t.Errorf("no-collector-key want = %+v", got)
	}
	if got := (CollectorDeployDeps{}).wantFor(keys); got.trust != "" {
		t.Errorf("want with no Mesh CA has trust %q, want empty", got.trust)
	}
}

// TC-672-07: upgrade from the release that pinned the bus certificate. A keyed
// collector recorded with the bus fingerprint is redeployed at once; legacy
// and unrecorded collectors inside the 6 h window are left alone; an offline
// keyed node waits until it is online.
func TestDecideCollectorActions_UpgradeFromBusPin(t *testing.T) {
	now := time.Now().UTC()
	d := CollectorDeployDeps{MeshCAPEM: testMeshCA}
	busFP := proto.MeshCAFingerprint([]byte(testBusCert))
	caFP := proto.MeshCAFingerprint([]byte(testMeshCA))
	keys := map[string]proto.NodeKeys{
		"a": {proto.NodeKeyCollector: "sha256/a"},
		"d": {proto.NodeKeyCollector: "sha256/d"},
	}
	want := func(id string) collectorWant { return d.wantFor(keys[id]) }
	recent := now.Add(-time.Hour)
	state := map[string]*nodeJobState{
		"a": {lastSuccess: recent, deployed: collectorWant{key: "sha256/a", trust: busFP}},
		"b": {lastSuccess: recent, deployed: collectorWant{trust: caFP}},
		"c": {lastSuccess: recent},
		"d": {lastSuccess: recent, deployed: collectorWant{key: "sha256/d", trust: busFP}},
	}
	node := func(id string, seen time.Time) *proto.Node {
		return &proto.Node{ID: id, Role: proto.RoleCompute, LastSeen: seen}
	}
	nodes := []*proto.Node{node("a", now), node("b", now), node("c", now), node("d", now.Add(-5*time.Minute))}

	act := decideCollectorActions(nodes, state, nil, true, now, allAdmitted, want)
	if len(act.deploy) != 1 || act.deploy[0] != "a" {
		t.Errorf("deploy = %v, want [a]", act.deploy)
	}
	if act.skipped["fresh"] != 2 || act.skipped["offline"] != 1 {
		t.Errorf("skipped = %v, want fresh:2 (b, c) and offline:1 (d)", act.skipped)
	}

	nodes[3] = node("d", now)
	act = decideCollectorActions(nodes, state, nil, true, now, allAdmitted, want)
	if !slices.Contains(act.deploy, "d") {
		t.Errorf("deploy once d is online = %v, want d included", act.deploy)
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
	act := decideCollectorActions(nodes, depState, nil, true, now, allAdmitted, same)
	if len(act.deploy) != 0 || act.skipped["fresh"] != 1 {
		t.Fatalf("a current collector was redeployed: %+v", act)
	}

	for name, want := range map[string]collectorWant{
		"the node registered a new key":       {key: "sha256/new", trust: "busfp"},
		"the trust anchor changed":            {key: "sha256/old", trust: "othertrust"},
		"the node moved off the legacy shape": {key: "sha256/first", trust: "busfp"},
	} {
		t.Run(name, func(t *testing.T) {
			act := decideCollectorActions(nodes, depState, nil, true, now, allAdmitted,
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
	act := decideCollectorActions(nodes, depState, nil, true, now, allAdmitted,
		func(string) collectorWant { return collectorWant{key: "sha256/new", trust: "busfp"} })
	if len(act.deploy) != 0 || act.skipped["fresh"] != 1 {
		t.Fatalf("an unrecorded deploy was treated as stale: %+v", act)
	}
	// And the safety net still picks it up.
	act = decideCollectorActions(nodes,
		map[string]*nodeJobState{"c02": {lastSuccess: now.Add(-7 * time.Hour)}}, nil, true, now,
		allAdmitted, func(string) collectorWant { return collectorWant{} })
	if len(act.deploy) != 1 {
		t.Fatalf("the safety net did not redeploy: %+v", act)
	}
}

// allAdmitted is the registry answer for the cases below, which are about what
// a collector CARRIES rather than about admission. Admission has its own
// cases in collector_jobs_test.go.
func allAdmitted(string) bool { return true }

// wantFor answers the LEGACY shape whenever it cannot establish that a node
// has a collector key: no inventory to ask, or a read that failed. Failing
// the other way would put a node on a key the api cannot confirm it has, and
// the collector would be deployed unable to authenticate.
func TestCollectorReconcileDeps_WantForFallsBackWhenItCannotAsk(t *testing.T) {
	ctx := context.Background()
	want := collectorWant{trust: proto.MeshCAFingerprint([]byte(testMeshCA))}

	// No inventory wired at all.
	d := CollectorReconcileDeps{Deploy: CollectorDeployDeps{MeshCAPEM: testMeshCA}}
	if got := d.wantFor(ctx, "c02"); got != want {
		t.Errorf("no inventory: want = %+v, want the legacy shape %+v", got, want)
	}

	// An inventory whose read fails: the store's database is closed.
	inv, err := inventory.OpenStore(ctx, filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := inv.Close(); err != nil {
		t.Fatal(err)
	}
	d.Inv = inv
	if got := d.wantFor(ctx, "c02"); got != want {
		t.Errorf("unreadable inventory: want = %+v, want the legacy shape %+v", got, want)
	}
}
