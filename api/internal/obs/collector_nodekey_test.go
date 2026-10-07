package obs

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
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
		CAPEM:           testMeshCA,
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
		t.Errorf("mesh_ca config content = %q, want the controlplane CA", got)
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
		"keyed": nodeKeyCollectorSpec(),
	} {
		out, _ := renderCompose(t, spec)
		if strings.Contains(out, "ca_pem") {
			t.Errorf("%s: the compose renders ca_pem", name)
		}
	}
}

// TC-672-03: a missing or blank controlplane CA is refused, with no compose
// rendered, so Alloy never falls back to the system roots.
func TestBuildCollectorCompose_RefusesWithNoMeshCA(t *testing.T) {
	for name, spec := range map[string]CollectorSpec{
		"keyed": nodeKeyCollectorSpec(),
	} {
		for _, ca := range []string{"", "  \n"} {
			spec.CAPEM = ca
			out, err := BuildCollectorCompose(spec)
			if out != "" || err == nil || !strings.Contains(err.Error(), "CAPEM required") {
				t.Errorf("%s, CAPEM %q = (%d bytes, %v), want (\"\", CAPEM required)", name, ca, len(out), err)
			}
		}
	}
}

// TC-516-13: the node key is the only shape. A spec without the node-key
// paths is refused; one with them binds them read-only and carries no private
// key, no leaf config or target, and exactly one certificate: the controlplane CA.
func TestBuildCollectorCompose_RequiresTheNodeKey(t *testing.T) {
	for name, blank := range map[string]func(*CollectorSpec){
		"no NodeKeyCertPath": func(s *CollectorSpec) { s.NodeKeyCertPath = "" },
		"no NodeKeyPath":     func(s *CollectorSpec) { s.NodeKeyPath = "  " },
		"neither":            func(s *CollectorSpec) { s.NodeKeyCertPath, s.NodeKeyPath = "", "" },
	} {
		spec := nodeKeyCollectorSpec()
		blank(&spec)
		if out, err := BuildCollectorCompose(spec); err == nil || out != "" {
			t.Errorf("%s: rendered %d bytes, err %v; want a refusal", name, len(out), err)
		}
	}

	out, cf := renderCompose(t, nodeKeyCollectorSpec())
	svc := cf.Services["alloy"]
	for _, want := range []string{
		proto.NodeCertPath(proto.NodeKeyCollector) + ":" + collectorNodeKeyCertPath + ":ro",
		proto.NodeKeyPath(proto.NodeKeyCollector) + ":" + collectorNodeKeyPath + ":ro",
	} {
		if !containsStr(svc.Volumes, want) {
			t.Errorf("volume %q not mounted read-only; got %v", want, svc.Volumes)
		}
	}
	if strings.Contains(out, "PRIVATE KEY") {
		t.Error("the compose contains a PRIVATE KEY block")
	}
	for name := range cf.Configs {
		if name == "leaf_cert" || name == "leaf_key" {
			t.Errorf("the compose carries a %s config", name)
		}
	}
	if strings.Contains(out, "leaf.pem") || strings.Contains(out, "leaf.key") {
		t.Error("the compose names a leaf.pem or leaf.key target")
	}
	if n := strings.Count(out, "BEGIN CERTIFICATE"); n != 1 {
		t.Errorf("BEGIN CERTIFICATE appears %d time(s), want 1 (the mesh_ca config)", n)
	}
	if !strings.Contains(cf.Configs["mesh_ca"].Content, "BEGIN CERTIFICATE") {
		t.Error("the one certificate is not the mesh_ca config's content")
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
		"keyed": nodeKeyCollectorSpec(),
	} {
		cert, key := collectorNodeKeyCertPath, collectorNodeKeyPath
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
	d := CollectorDeployDeps{CAPEM: testMeshCA}
	caFP := proto.TrustFingerprint([]byte(testMeshCA))
	keys := proto.NodeKeys{proto.NodeKeyCollector: "sha256/k", proto.NodeKeyAgent: "sha256/a"}
	if got := d.wantFor(keys); got != (collectorWant{key: "sha256/k", trust: caFP}) {
		t.Errorf("keyed want = %+v", got)
	}
	// The AGENT key alone is not a collector key.
	if got := d.wantFor(proto.NodeKeys{proto.NodeKeyAgent: "sha256/a"}); got != (collectorWant{trust: caFP}) {
		t.Errorf("no-collector-key want = %+v", got)
	}
	if got := (CollectorDeployDeps{}).wantFor(keys); got.trust != "" {
		t.Errorf("want with no controlplane CA has trust %q, want empty", got.trust)
	}
}

// TC-672-07: upgrade from the release that pinned the bus certificate. A keyed
// collector recorded with the bus fingerprint is redeployed at once; legacy
// and unrecorded collectors inside the 6 h window are left alone; an offline
// keyed node waits until it is online.
func TestDecideCollectorActions_UpgradeFromBusPin(t *testing.T) {
	now := time.Now().UTC()
	d := CollectorDeployDeps{CAPEM: testMeshCA}
	busFP := proto.TrustFingerprint([]byte(testBusCert))
	caFP := proto.TrustFingerprint([]byte(testMeshCA))
	keys := map[string]proto.NodeKeys{
		"a": {proto.NodeKeyCollector: "sha256/a"},
		"d": {proto.NodeKeyCollector: "sha256/d"},
	}
	want := func(id string) (collectorWant, bool) { return d.wantFor(keys[id]), true }
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

	same := func(string) (collectorWant, bool) { return deployed, true }
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
				func(string) (collectorWant, bool) { return want, true })
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
		func(string) (collectorWant, bool) { return collectorWant{key: "sha256/new", trust: "busfp"}, true })
	if len(act.deploy) != 0 || act.skipped["fresh"] != 1 {
		t.Fatalf("an unrecorded deploy was treated as stale: %+v", act)
	}
	// And the safety net still picks it up.
	act = decideCollectorActions(nodes,
		map[string]*nodeJobState{"c02": {lastSuccess: now.Add(-7 * time.Hour)}}, nil, true, now,
		allAdmitted, func(string) (collectorWant, bool) { return collectorWant{}, true })
	if len(act.deploy) != 1 {
		t.Fatalf("the safety net did not redeploy: %+v", act)
	}
}

// allAdmitted is the registry answer for the cases below, which are about what
// a collector CARRIES rather than about admission. Admission has its own
// cases in collector_jobs_test.go.
func allAdmitted(string) bool { return true }

// TC-516-21: wantFor has no answer when it cannot read a node's keys — no
// inventory to ask, or a read that failed — and says why, rather than
// guessing a shape.
func TestCollectorReconcileDeps_WantForHasNoAnswerWhenItCannotAsk(t *testing.T) {
	ctx := context.Background()

	// No inventory wired at all.
	d := CollectorReconcileDeps{Deploy: CollectorDeployDeps{CAPEM: testMeshCA}}
	if got, err := d.wantFor(ctx, "c02"); err == nil || got != (collectorWant{}) {
		t.Errorf("no inventory: want = %+v, %v; want no answer and an error", got, err)
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
	if got, err := d.wantFor(ctx, "c02"); err == nil || got != (collectorWant{}) {
		t.Errorf("unreadable inventory: want = %+v, %v; want no answer and an error", got, err)
	}
}

// TC-516-21: with obs on, a node whose want has no answer is neither deployed
// nor torn down, whether or not it runs a collector, and is counted under
// keys_unreadable.
func TestDecideCollectorActions_LeavesANodeWithUnreadableKeysAlone(t *testing.T) {
	now := time.Now().UTC()
	nodes := []*proto.Node{
		{ID: "running", Role: proto.RoleCompute, LastSeen: now},
		{ID: "none", Role: proto.RoleCompute, LastSeen: now},
	}
	depState := map[string]*nodeJobState{
		"running": {lastSuccess: now.Add(-7 * time.Hour), deployed: collectorWant{key: "sha256/k", trust: "t"}},
	}
	act := decideCollectorActions(nodes, depState, nil, true, now, allAdmitted,
		func(string) (collectorWant, bool) { return collectorWant{}, false })
	if len(act.deploy) != 0 || len(act.teardown) != 0 {
		t.Fatalf("acted on unreadable keys: deploy %v, teardown %v", act.deploy, act.teardown)
	}
	if act.skipped["keys_unreadable"] != 2 {
		t.Errorf("skipped = %v, want keys_unreadable:2", act.skipped)
	}
}

// TC-516-21: the reconcile step, obs on, over two online admitted nodes whose
// keys cannot be read (the key table is gone; inventory still lists them):
// it submits nothing, counts both under keys_unreadable, writes one warn feed
// line per node naming it and the read error, and nothing to the standard
// log package.
func TestCollectorConverge_LeavesNodesWithUnreadableKeysAlone(t *testing.T) {
	var global bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&global)
	t.Cleanup(func() { log.SetOutput(prev) })

	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "inv.db")
	inv := admittedStoreAt(t, dbPath, "c01", "c02")
	breakNodeKeys(t, dbPath)
	js, err := jobs.OpenStore(ctx, filepath.Join(dir, "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.Close() })
	d := CollectorReconcileDeps{
		Inv: inv, Jobs: js, Runner: jobs.NewRunner(js, nil),
		Deploy: CollectorDeployDeps{Inv: inv, CAPEM: testMeshCA},
	}
	var feed []string
	out, err := collectorConverge(d)(&jobs.StepCtx{Ctx: ctx, JobID: "j", Log: func(level, msg string) {
		feed = append(feed, level+": "+msg)
	}})
	if err != nil {
		t.Fatalf("converge: %v", err)
	}
	var res struct {
		Deployed []string       `json:"deployed"`
		TornDown []string       `json:"tornDown"`
		Skipped  map[string]int `json:"skipped"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Deployed) != 0 || len(res.TornDown) != 0 || res.Skipped["keys_unreadable"] != 2 {
		t.Errorf("result = %+v, want nothing deployed or torn down and keys_unreadable:2", res)
	}
	for _, kind := range []string{CollectorDeployKind, CollectorTeardownKind} {
		if submitted, err := js.ListJobsByKind(ctx, kind, 10); err != nil || len(submitted) != 0 {
			t.Errorf("%s jobs submitted: %d (%v), want 0", kind, len(submitted), err)
		}
	}
	for _, node := range []string{"c01", "c02"} {
		n := 0
		for _, l := range feed {
			if strings.HasPrefix(l, "warn: ") && strings.Contains(l, "node "+node+"'s registered keys") && strings.Contains(l, "node_keys") {
				n++
			}
		}
		if n != 1 {
			t.Errorf("warn lines naming %s and the read error = %d, want 1; feed:\n%s", node, n, strings.Join(feed, "\n"))
		}
	}
	if global.Len() != 0 {
		t.Errorf("the global log was written: %q", global.String())
	}
}

// A deploy the runner refuses (here no deploy workflow is registered) is not
// reported as deployed: it is counted under submit_error and logged as one
// warn feed line naming the kind and the node.
func TestCollectorConverge_CountsARefusedSubmit(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	inv := admittedStoreAt(t, filepath.Join(dir, "inv.db"), "c01")
	js, err := jobs.OpenStore(ctx, filepath.Join(dir, "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.Close() })
	d := CollectorReconcileDeps{
		Inv: inv, Jobs: js, Runner: jobs.NewRunner(js, nil),
		Deploy: CollectorDeployDeps{Inv: inv, CAPEM: testMeshCA},
	}
	var feed []string
	out, err := collectorConverge(d)(&jobs.StepCtx{Ctx: ctx, JobID: "j", Log: func(level, msg string) {
		feed = append(feed, level+": "+msg)
	}})
	if err != nil {
		t.Fatalf("converge: %v", err)
	}
	var res struct {
		Deployed []string       `json:"deployed"`
		Skipped  map[string]int `json:"skipped"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Deployed) != 0 || res.Skipped["submit_error"] != 1 {
		t.Errorf("result = %+v, want nothing deployed and submit_error:1", res)
	}
	n := 0
	for _, l := range feed {
		if strings.HasPrefix(l, "warn: converge: submit "+CollectorDeployKind+" for c01: ") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("warn lines for the refused submit = %d, want 1; feed:\n%s", n, strings.Join(feed, "\n"))
	}
}
