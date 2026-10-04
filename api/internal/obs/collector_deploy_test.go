package obs

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
	"gopkg.in/yaml.v3"
)

// The deploy step, driven directly with a real inventory and an in-process
// NATS server. fakeCollectorAgent stands in for the node's agent and records
// every docker.deploy it is sent.

type fakeCollectorAgent struct {
	mu   sync.Mutex
	cmds []proto.AppDeployCmd
}

func (f *fakeCollectorAgent) sent() []proto.AppDeployCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]proto.AppDeployCmd(nil), f.cmds...)
}

func startCollectorAgent(t *testing.T, nodeID string) (*nats.Conn, *fakeCollectorAgent) {
	t.Helper()
	srv := natsserver.RunRandClientPortServer()
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	t.Cleanup(nc.Close)
	f := &fakeCollectorAgent{}
	sub, err := nc.Subscribe(proto.AppDeploySubject(nodeID), func(m *nats.Msg) {
		var cmd proto.AppDeployCmd
		_ = json.Unmarshal(m.Data, &cmd)
		f.mu.Lock()
		f.cmds = append(f.cmds, cmd)
		f.mu.Unlock()
		b, _ := json.Marshal(proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	return nc, f
}

type deployRun struct {
	err  error
	logs []string
}

func runCollectorDeploy(t *testing.T, d CollectorDeployDeps, nc *nats.Conn, nodeID string) deployRun {
	t.Helper()
	spec, _ := json.Marshal(CollectorNodeSpec{NodeID: nodeID})
	var r deployRun
	_, r.err = collectorDeploy(d)(&jobs.StepCtx{
		Ctx: context.Background(), JobID: "j", Spec: spec, NATS: nc,
		Log: func(_, msg string) { r.logs = append(r.logs, msg) },
	})
	return r
}

func alloyConfigOf(t *testing.T, compose string) composeFile {
	t.Helper()
	var cf composeFile
	if err := yaml.Unmarshal([]byte(compose), &cf); err != nil {
		t.Fatalf("deployed compose is not valid YAML: %v", err)
	}
	return cf
}

// TC-672-08: a keyed node gets the Mesh-chain trust line under the deps'
// ServerName, and the step says trust=mesh-ca with the CA's short
// fingerprint.
func TestCollectorDeploy_KeyedNodeTrustsTheMeshChain(t *testing.T) {
	inv := admittedStore(t, "c02")
	if _, err := inv.SetNodeKeys(context.Background(), "c02",
		proto.NodeKeys{proto.NodeKeyCollector: "sha256/" + strings.Repeat("A", 43) + "="}); err != nil {
		t.Fatal(err)
	}
	nc, agent := startCollectorAgent(t, "c02")
	d := CollectorDeployDeps{
		Inv: inv, MeshCAPEM: testMeshCA,
		IngressBaseURL: "https://home1.local:8443", ServerName: "home1.local",
	}
	r := runCollectorDeploy(t, d, nc, "c02")
	if r.err != nil {
		t.Fatalf("deploy: %v", r.err)
	}
	cmds := agent.sent()
	if len(cmds) != 1 {
		t.Fatalf("deploy RPCs = %d, want 1", len(cmds))
	}
	alloy := alloyConfigOf(t, cmds[0].ComposeYAML).Configs["alloy_config"].Content
	if !strings.Contains(alloy, `server_name = "home1.local"`) || !strings.Contains(alloy, collectorTrustLine) {
		t.Errorf("keyed compose lacks the Mesh trust line or server name:\n%s", alloy)
	}
	short := proto.ShortFingerprint(proto.MeshCAFingerprint([]byte(testMeshCA)))
	found := false
	for _, l := range r.logs {
		if strings.Contains(l, "trust=mesh-ca "+short) {
			found = true
		}
	}
	if !found {
		t.Errorf("no step log line carries trust=mesh-ca %s; logs = %q", short, r.logs)
	}
}

// TC-516-12: a node with no registered collector key is refused by name and
// sent nothing; a key read that fails fails the step with the wrapped error
// and sends nothing.
func TestCollectorDeploy_RefusesANodeWithNoCollectorKey(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "inv.db")
	inv := admittedStoreAt(t, dbPath, "c03")
	if _, err := inv.SetNodeKeys(context.Background(), "c03",
		proto.NodeKeys{proto.NodeKeyAgent: "sha256/" + strings.Repeat("C", 43) + "="}); err != nil {
		t.Fatal(err)
	}
	nc, agent := startCollectorAgent(t, "c03")
	d := CollectorDeployDeps{
		Inv: inv, MeshCAPEM: testMeshCA,
		IngressBaseURL: "https://home1.local:8443", ServerName: "home1.local",
	}
	r := runCollectorDeploy(t, d, nc, "c03")
	if r.err == nil {
		t.Fatal("a node with no registered collector key was deployed")
	}
	for _, sub := range []string{"node c03", "has no registered collector key", "not deployed"} {
		if !strings.Contains(r.err.Error(), sub) {
			t.Errorf("error %q lacks %q", r.err, sub)
		}
	}
	if n := len(agent.sent()); n != 0 {
		t.Fatalf("%d deploy RPC(s) sent to a node with no collector key", n)
	}

	// The keys table is gone: inventory answers Get, and NodeKeys fails.
	breakNodeKeys(t, dbPath)
	r = runCollectorDeploy(t, d, nc, "c03")
	if r.err == nil || !strings.Contains(r.err.Error(), "read node keys for c03") || !strings.Contains(r.err.Error(), "node_keys") {
		t.Errorf("deploy with an unreadable key table = %v, want the wrapped read error", r.err)
	}
	if n := len(agent.sent()); n != 0 {
		t.Errorf("%d deploy RPC(s) sent after the key read failed", n)
	}
}

// TC-672-10: with no Mesh CA configured, a keyed node's deploy fails with an
// error that wraps "MeshCAPEM required" and names the node, and no RPC is
// sent.
func TestCollectorDeploy_RefusesWithNoMeshCA(t *testing.T) {
	inv := admittedStore(t, "k1")
	if _, err := inv.SetNodeKeys(context.Background(), "k1",
		proto.NodeKeys{proto.NodeKeyCollector: "sha256/" + strings.Repeat("B", 43) + "="}); err != nil {
		t.Fatal(err)
	}
	for _, node := range []string{"k1"} {
		t.Run(node, func(t *testing.T) {
			nc, agent := startCollectorAgent(t, node)
			d := CollectorDeployDeps{
				Inv:            inv,
				IngressBaseURL: "https://home1.local:8443", ServerName: "home1.local",
			}
			r := runCollectorDeploy(t, d, nc, node)
			if r.err == nil || !strings.Contains(r.err.Error(), "MeshCAPEM required") || !strings.Contains(r.err.Error(), node) {
				t.Errorf("deploy with no Mesh CA = %v, want an error naming %s and MeshCAPEM required", r.err, node)
			}
			if n := len(agent.sent()); n != 0 {
				t.Errorf("%d deploy RPC(s) sent with no Mesh CA", n)
			}
		})
	}
}
