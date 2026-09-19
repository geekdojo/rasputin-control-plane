//go:build supervisor

package mesh

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

const bindingsTestContainer = "rasputin-headscale-bindings-test"

// TestSupervisor_LiveBindingsAndRoutes drives device→node binding and route
// handling against a real headscale container (the pinned image), with
// nodes registered through `headscale debug create-node` + `nodes register`
// so Headscale itself reports their advertised routes:
//
//  1. an upgrade's VerifyBindings keeps the binding a succeeded enrol
//     recorded and clears a hostname-derived one for the same node;
//  2. reconcile syncs the node's advertised route from Headscale, and an
//     automatic re-enrol of that node names the route (so the agent's
//     `tailscale up --reset` keeps it);
//  3. push_routes approves the route on the bound device in Headscale;
//  4. with a second device bound to the node, push_routes refuses and
//     approves nothing on it.
func TestSupervisor_LiveBindingsAndRoutes(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker not on PATH: %v", err)
	}
	if out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		t.Skipf("docker daemon unreachable; output=%q err=%v", strings.TrimSpace(string(out)), err)
	}
	base, err := resolveSupervisorStateDir()
	if err != nil {
		t.Fatalf("state dir: %v", err)
	}
	stateDir := filepath.Join(base, "bindings")
	listenAddr := envDefault("SUPERVISOR_BINDINGS_LISTEN_ADDR", "127.0.0.1:18085")
	_ = exec.Command("docker", "rm", "-f", bindingsTestContainer).Run()
	_ = os.RemoveAll(stateDir)
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", bindingsTestContainer).Run()
		_ = os.RemoveAll(stateDir)
	})
	if err := os.MkdirAll(filepath.Join(stateDir, "trust"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	ca, err := EnsureMeshCA(filepath.Join(stateDir, "trust"), "bindings-smoke")
	if err != nil {
		t.Fatalf("EnsureMeshCA: %v", err)
	}
	sup, err := NewDockerSupervisor(DockerSupervisorConfig{
		StateDir: filepath.Join(stateDir, "hs"), ContainerName: bindingsTestContainer,
		ListenAddr: listenAddr, ServerURL: "https://" + listenAddr,
		HealthTimeout: 60 * time.Second, PullTimeout: 3 * time.Minute, MeshCA: ca,
	})
	if err != nil {
		t.Fatalf("NewDockerSupervisor: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	key, err := sup.MintSessionAPIKey(ctx)
	if err != nil {
		t.Fatalf("MintSessionAPIKey: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM)
	client, err := NewRealClient(RealClientConfig{BaseURL: "https://" + listenAddr, APIKey: key,
		RefreshAPIKey: sup.MintSessionAPIKey, RequestTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}})
	if err != nil {
		t.Fatalf("NewRealClient: %v", err)
	}
	const user = "rasputin-operator"
	if err := client.EnsureUser(ctx, user); err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	hsExec := func(args ...string) string {
		out, err := exec.CommandContext(ctx, "docker", append([]string{"exec", bindingsTestContainer, "headscale"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("headscale %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	// register creates a node in Headscale advertising routes and returns its id.
	register := func(name string, routes ...string) string {
		b := make([]byte, 18)
		_, _ = rand.Read(b)
		regID := base64.RawURLEncoding.EncodeToString(b) // 24 characters
		args := []string{"debug", "create-node", "--name", name, "--user", user, "--key", regID}
		for _, r := range routes {
			args = append(args, "--route", r)
		}
		hsExec(args...)
		hsExec("nodes", "register", "--user", user, "--key", regID)
		nodes, err := client.ListNodes(ctx)
		if err != nil {
			t.Fatalf("ListNodes: %v", err)
		}
		for _, n := range nodes {
			if n.Hostname == name {
				return n.ID
			}
		}
		t.Fatalf("node %s not listed after register", name)
		return ""
	}
	realID := register("fw", "192.168.1.0/24")
	spoofID := register("fw-spoof")
	t.Logf("headscale nodes: fw=%s spoof=%s", realID, spoofID)

	// The api's stores, as an upgraded controlplane has them: the real
	// device bound by an enrol the ledger recorded, a second device bound
	// to the same node by hostname (no enrol).
	dir := t.TempDir()
	st, err := OpenStore(ctx, filepath.Join(dir, "mesh.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer st.Close()
	jst, err := jobs.OpenStore(ctx, filepath.Join(dir, "mesh.db"))
	if err != nil {
		t.Fatalf("jobs.OpenStore: %v", err)
	}
	defer jst.Close()
	seedLegacyBinding(t, st, realID, "fw")
	seedLegacyBinding(t, st, spoofID, "fw")
	seedLedgerEnrol(t, ctx, jst, "job-fw", "fw", realID, []string{"192.168.1.0/24"})

	rep, err := VerifyBindings(ctx, st, JobsLedger{Store: jst})
	if err != nil {
		t.Fatalf("VerifyBindings: %v", err)
	}
	t.Logf("VerifyBindings: kept=%v cleared=%v", rep.Kept, rep.Cleared)
	if !slices.Equal(rep.Kept, []string{"fw=" + realID}) || !slices.Equal(rep.Cleared, []string{"fw=" + spoofID}) {
		t.Fatalf("report %+v; want the enrolled device kept and the hostname one cleared", rep)
	}

	nc := embeddedNATS(t)
	svc := NewService(Config{DefaultUser: user}, st, client, NewNoopSupervisor())
	if _, err := reconcileFetch(svc, nc)(stepCtx(ctx, nc, struct{}{})); err != nil {
		t.Fatalf("reconcile fetch: %v", err)
	}
	bound, err := st.GetDeviceByRasputinNodeID(ctx, "fw")
	if err != nil || bound == nil || bound.HSID != realID {
		t.Fatalf("fw resolves to %+v, %v; want %s", bound, err, realID)
	}
	routes, source := ReenrolRoutes(ctx, svc, "fw", bound, nil)
	t.Logf("re-enrol of fw would advertise %v (from %s); Headscale reports %v", routes, source, bound.AdvertisedRoutes)
	if !slices.Equal(routes, []string{"192.168.1.0/24"}) {
		t.Errorf("re-enrol routes %v; want the route Headscale reports fw advertising", routes)
	}

	now := time.Now().UTC()
	if err := st.CreateIntent(ctx, &Intent{ID: "r1", Kind: string(proto.IntentSubnetRoute), Name: "lan", Enabled: true,
		Spec: mustMarshal(t, proto.SubnetRouteSpec{NodeID: "fw", CIDR: "192.168.1.0/24"}), CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("CreateIntent: %v", err)
	}
	if _, err := applyPushRoutes(svc, nil)(stepCtx(ctx, nc, struct{}{})); err != nil {
		t.Fatalf("push_routes: %v", err)
	}
	approved := func(id string) []string {
		nodes, err := client.ListNodes(ctx)
		if err != nil {
			t.Fatalf("ListNodes: %v", err)
		}
		for _, n := range nodes {
			if n.ID == id {
				return n.ApprovedRoutes
			}
		}
		return nil
	}
	if got := approved(realID); !slices.Contains(got, "192.168.1.0/24") {
		t.Errorf("fw's approved routes in Headscale = %v; want 192.168.1.0/24", got)
	}

	// A duplicate binding (the index dropped to model a database that
	// predates it): push_routes approves nothing on either device.
	third := register("fw-third", "192.168.1.0/24")
	seedLegacyBinding(t, st, third, "fw")
	out, err := applyPushRoutes(svc, nil)(stepCtx(ctx, nc, struct{}{}))
	if err != nil {
		t.Fatalf("push_routes with a duplicate: %v", err)
	}
	t.Logf("push_routes with fw bound twice: %s", out)
	if !strings.Contains(string(out), `"refusedDuplicateBinding":["fw"]`) {
		t.Errorf("push_routes did not refuse the duplicate: %s", out)
	}
	if got := approved(third); len(got) != 0 {
		t.Errorf("a route was approved on the duplicate device: %v", got)
	}
}

// seedLedgerEnrol writes a succeeded mesh.enroll_node job with its record
// step, as a real enrol leaves it.
func seedLedgerEnrol(t *testing.T, ctx context.Context, jst *jobs.Store, jobID, nodeID, hsID string, routes []string) {
	t.Helper()
	f := &convergeFixture{meshFixture: &meshFixture{ctx: ctx}, jstore: jst}
	seedSucceededEnrol(t, f, jobID, nodeID, hsID, routes, time.Now().UTC())
}
