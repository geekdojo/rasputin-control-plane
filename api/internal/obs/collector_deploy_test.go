package obs

import (
	"context"
	"encoding/json"
	"errors"
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

// countingMint is a Mint that records its calls and returns a fixed leaf, or
// err when set.
type countingMint struct {
	calls int
	err   error
}

func (m *countingMint) fn(string) (string, string, error) {
	m.calls++
	if m.err != nil {
		return "", "", m.err
	}
	return testLeafCert, testLeafKey, nil
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
// ServerName, Mint is never called, and the step says trust=mesh-ca with the
// CA's short fingerprint.
func TestCollectorDeploy_KeyedNodeTrustsTheMeshChain(t *testing.T) {
	inv := admittedStore(t, "c02")
	if _, err := inv.SetNodeKeys(context.Background(), "c02",
		proto.NodeKeys{proto.NodeKeyCollector: "sha256/" + strings.Repeat("A", 43) + "="}); err != nil {
		t.Fatal(err)
	}
	nc, agent := startCollectorAgent(t, "c02")
	mint := &countingMint{}
	d := CollectorDeployDeps{
		Inv: inv, Mint: mint.fn, MeshCAPEM: testMeshCA,
		IngressBaseURL: "https://home1.local:8443", ServerName: "home1.local",
	}
	r := runCollectorDeploy(t, d, nc, "c02")
	if r.err != nil {
		t.Fatalf("deploy: %v", r.err)
	}
	if mint.calls != 0 {
		t.Errorf("Mint called %d time(s) for a keyed node, want 0", mint.calls)
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

// TC-672-09: a node with no collector key is minted a leaf once and its
// compose carries d.MeshCAPEM; a Mint failure fails the step naming the node,
// with no RPC sent.
func TestCollectorDeploy_LegacyNodeAndMintFailure(t *testing.T) {
	inv := admittedStore(t, "c03")
	nc, agent := startCollectorAgent(t, "c03")
	mint := &countingMint{}
	d := CollectorDeployDeps{
		Inv: inv, Mint: mint.fn, MeshCAPEM: testMeshCA,
		IngressBaseURL: "https://home1.local:8443", ServerName: "home1.local",
	}
	if r := runCollectorDeploy(t, d, nc, "c03"); r.err != nil {
		t.Fatalf("deploy: %v", r.err)
	}
	if mint.calls != 1 {
		t.Errorf("Mint called %d time(s), want 1", mint.calls)
	}
	cmds := agent.sent()
	if len(cmds) != 1 {
		t.Fatalf("deploy RPCs = %d, want 1", len(cmds))
	}
	if got := strings.TrimRight(alloyConfigOf(t, cmds[0].ComposeYAML).Configs["mesh_ca"].Content, "\n"); got != testMeshCA {
		t.Errorf("legacy mesh_ca = %q, want d.MeshCAPEM", got)
	}

	failing := &countingMint{err: errors.New("disk full")}
	d.Mint = failing.fn
	r := runCollectorDeploy(t, d, nc, "c03")
	if r.err == nil || !strings.Contains(r.err.Error(), "c03") {
		t.Errorf("mint failure = %v, want an error naming c03", r.err)
	}
	if n := len(agent.sent()); n != 1 {
		t.Errorf("a deploy RPC was sent after the mint failed (%d total)", n)
	}
}

// TC-672-10: with no Mesh CA configured, both shapes fail with an error that
// wraps "MeshCAPEM required" and names the node, and no RPC is sent.
func TestCollectorDeploy_RefusesWithNoMeshCA(t *testing.T) {
	inv := admittedStore(t, "k1", "l1")
	if _, err := inv.SetNodeKeys(context.Background(), "k1",
		proto.NodeKeys{proto.NodeKeyCollector: "sha256/" + strings.Repeat("B", 43) + "="}); err != nil {
		t.Fatal(err)
	}
	for _, node := range []string{"k1", "l1"} {
		t.Run(node, func(t *testing.T) {
			nc, agent := startCollectorAgent(t, node)
			mint := &countingMint{}
			d := CollectorDeployDeps{
				Inv: inv, Mint: mint.fn,
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
