package mesh

import (
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/nodetrust"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

var enrollTrustBundle = []byte("-----BEGIN CERTIFICATE-----\nENROLL\n-----END CERTIFICATE-----\n")

// enrollTrustFixture is a convergeFixture whose Service delivers trust through
// the real nodetrust service, with fake agents that record every command
// subject the node answers, in order, and the mesh.enroll payload.
type enrollTrustFixture struct {
	*convergeFixture
	mu       sync.Mutex
	subjects []string
	enroll   *proto.MeshEnrollCmd
}

func newEnrollTrustFixture(t *testing.T, nodeID, agentVersion string) *enrollTrustFixture {
	t.Helper()
	cf := newConvergeFixture(t)
	ts, err := nodetrust.New(nodetrust.Options{Bundle: enrollTrustBundle, Nodes: cf.inv, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	cf.svc = NewService(Config{Trust: ts, TrustFingerprint: ts, LegacyTrustBundle: enrollTrustBundle}, cf.store, cf.client, NewNoopSupervisor())
	now := time.Now().UTC()
	if err := cf.inv.Insert(cf.ctx, &proto.Node{ID: nodeID, Role: proto.RoleCompute, Hostname: nodeID, AgentVersion: agentVersion, FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	cf.admit(nodeID)
	f := &enrollTrustFixture{convergeFixture: cf}
	enr, err := cf.nc.Subscribe(proto.MeshEnrollSubject(nodeID), func(m *nats.Msg) {
		var cmd proto.MeshEnrollCmd
		_ = json.Unmarshal(m.Data, &cmd)
		f.mu.Lock()
		f.enroll = &cmd
		f.subjects = append(f.subjects, m.Subject)
		f.mu.Unlock()
		body, _ := json.Marshal(proto.MeshEnrollAck{OK: true, Backend: "mock", TailnetID: "hs-1", TailnetIP: "100.64.0.9"})
		_ = m.Respond(body)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = enr.Unsubscribe() })
	return f
}

// trustAgent answers trust.install on nodeID with ack.
func (f *enrollTrustFixture) trustAgent(t *testing.T, nodeID string, ack proto.TrustInstallAck) {
	t.Helper()
	sub, err := f.nc.Subscribe(proto.TrustInstallSubject(nodeID), func(m *nats.Msg) {
		f.mu.Lock()
		f.subjects = append(f.subjects, m.Subject)
		f.mu.Unlock()
		body, _ := json.Marshal(ack)
		_ = m.Respond(body)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
}

func (f *enrollTrustFixture) dispatch(t *testing.T, nodeID string) error {
	t.Helper()
	if err := f.nc.Flush(); err != nil {
		t.Fatal(err)
	}
	wf := EnrollNodeWorkflow(f.svc, f.inv, f.nc)
	spec, _ := json.Marshal(EnrollSpec{NodeID: nodeID})
	prior := runEnrollUpTo(t, wf, spec, f.nc, f.ctx, "dispatch")
	sc := &jobs.StepCtx{Ctx: f.ctx, JobID: "test-job", Spec: spec, NATS: f.nc, PriorResults: prior, Log: func(string, string) {}}
	_, err := enrollStep(t, wf, "dispatch").Do(sc)
	if ferr := f.nc.Flush(); ferr != nil {
		t.Fatal(ferr)
	}
	return err
}

// TC-741-16: a current agent receives trust.install before mesh.enroll, and
// the enroll command carries no bundle; an agent below the floor gets
// mesh.enroll carrying the bundle; any other delivery failure fails the step
// with "deliver trust to <node>:" and no pre-auth key is minted.
func TestEnrollDispatch_DeliversTrustFirst(t *testing.T) {
	fl, ok := proto.VerbMinAgentVersion(proto.TrustInstallVerb)
	if !ok {
		t.Fatal("no trust.install floor")
	}
	t.Run("current agent: trust.install, then mesh.enroll with no bundle", func(t *testing.T) {
		f := newEnrollTrustFixture(t, "node-1", fl)
		f.trustAgent(t, "node-1", proto.TrustInstallAck{OK: true, Changed: true, Fingerprint: proto.TrustFingerprint(enrollTrustBundle)})
		if err := f.dispatch(t, "node-1"); err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		want := []string{proto.TrustInstallSubject("node-1"), proto.MeshEnrollSubject("node-1")}
		if strings.Join(f.subjects, ",") != strings.Join(want, ",") {
			t.Errorf("subjects %v, want %v", f.subjects, want)
		}
		if f.enroll == nil || len(f.enroll.LegacyTrustBundlePEM) != 0 {
			t.Errorf("mesh.enroll %+v, want no bundle", f.enroll)
		}
	})
	t.Run("legacy agent: mesh.enroll carries the bundle", func(t *testing.T) {
		f := newEnrollTrustFixture(t, "node-1", legacyAgentVersion)
		if err := f.dispatch(t, "node-1"); err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		if f.enroll == nil || string(f.enroll.LegacyTrustBundlePEM) != string(enrollTrustBundle) {
			t.Errorf("mesh.enroll %+v, want the legacy bundle", f.enroll)
		}
	})
	t.Run("delivery failure: the step fails before a key is minted", func(t *testing.T) {
		f := newEnrollTrustFixture(t, "node-1", fl)
		f.trustAgent(t, "node-1", proto.TrustInstallAck{Detail: "installed; reloading tailscaled failed: boom"})
		err := f.dispatch(t, "node-1")
		if err == nil || !strings.HasPrefix(err.Error(), "deliver trust to node-1:") {
			t.Fatalf("err %v, want a deliver trust failure", err)
		}
		if values, _ := f.client.minted(); len(values) != 0 {
			t.Errorf("%d key(s) minted after a failed delivery", len(values))
		}
		if f.enroll != nil {
			t.Error("mesh.enroll was sent after a failed delivery")
		}
	})
}

// TC-741-09 (app and Headscale leaves): both existing specs ask for a server
// leaf, and each leaf carries exactly ServerAuth.
func TestExistingLeafSpecsAreServerLeaves(t *testing.T) {
	ca := newCAForTest(t)
	certPEM, key, _, err := PrepareAppLeaf(ca, t.TempDir(), "home1", "jellyfin")
	if err != nil {
		t.Fatal(err)
	}
	key.Destroy()
	assertServerOnly(t, "app", mustParseCert(t, certPEM).ExtKeyUsage)
	if appLeafSpec("home1", "jellyfin").Usage.String() != "server" {
		t.Error("appLeafSpec is not a server spec")
	}

	sup, err := NewDockerSupervisor(DockerSupervisorConfig{StateDir: t.TempDir(), ListenAddr: "127.0.0.1:18080", MeshCA: ca})
	if err != nil {
		t.Fatal(err)
	}
	spec, err := sup.leafSpec()
	if err != nil {
		t.Fatal(err)
	}
	if spec.Usage.String() != "server" {
		t.Errorf("Headscale spec usage %s", spec.Usage)
	}
	if err := sup.ensureLeaf(); err != nil {
		t.Fatal(err)
	}
	cert := mustParseCertFileAt(t, sup.certsDir())
	assertServerOnly(t, "headscale", cert.ExtKeyUsage)
}

func assertServerOnly(t *testing.T, name string, ekus []x509.ExtKeyUsage) {
	t.Helper()
	if len(ekus) != 1 || ekus[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("%s leaf ExtKeyUsage %v, want exactly [ServerAuth]", name, ekus)
	}
}

func mustParseCertFileAt(t *testing.T, dir string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(tlsca.LeafPathsIn(dir).CertPath)
	if err != nil {
		t.Fatal(err)
	}
	return mustParseCert(t, b)
}
