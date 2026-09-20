package main

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

func sweepInventory(t *testing.T, ids ...string) *inventory.Store {
	t.Helper()
	ctx := context.Background()
	inv, err := inventory.OpenStore(ctx, filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatalf("inventory OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = inv.Close() })
	for _, id := range ids {
		if err := inv.Insert(ctx, &proto.Node{ID: id, Role: proto.RoleCompute, Hostname: id}); err != nil {
			t.Fatalf("insert %q: %v", id, err)
		}
	}
	return inv
}

func names(cs []mesh.LeafConsumer) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Name)
	}
	slices.Sort(out)
	return out
}

// The source lists exactly the leaves that exist AND belong to a node still in
// inventory: a removed node's leaf stops being renewed, and a node that never
// had a collector is never minted one by the sweep.
func TestCollectorLeafSource_OnlyExistingLeavesOfKnownNodes(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"c01", "gone"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// A file, not a directory — must not be read as a node.
	if err := os.WriteFile(filepath.Join(root, "stray"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// c02 is in inventory but has never had a collector deployed.
	inv := sweepInventory(t, "c01", "c02", "stray")

	src := collectorLeafSource(root, inv, nil)
	got, err := src(context.Background())
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	if want := []string{"collector/c01"}; !slices.Equal(names(got), want) {
		t.Errorf("consumers = %v, want %v", names(got), want)
	}
	if got[0].Dir != filepath.Join(root, "c01") {
		t.Errorf("Dir = %q", got[0].Dir)
	}
	spec, err := got[0].Spec()
	if err != nil {
		t.Fatalf("Spec: %v", err)
	}
	if spec.CommonName != "c01" || !spec.ClientAuth {
		t.Errorf("spec = %+v, want the collector's client-auth leaf for c01", spec)
	}
}

// Nothing has ever been deployed: the source says so rather than erroring, so
// a first-boot sweep is quiet.
func TestCollectorLeafSource_MissingRootIsNotAnError(t *testing.T) {
	src := collectorLeafSource(filepath.Join(t.TempDir(), "never-created"), sweepInventory(t), nil)
	got, err := src(context.Background())
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v; want no consumers and no error", got, err)
	}
}

// The reload hook is the redeploy — a collector's leaf rides to the node
// inside its compose, so a renewed file on the controlplane reaches nothing
// until the node is redeployed.
func TestCollectorLeafSource_ReloadRedeploysThatNode(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "c01"), 0o700); err != nil {
		t.Fatal(err)
	}
	var redeployed []string
	src := collectorLeafSource(root, sweepInventory(t, "c01"), func(_ context.Context, nodeID string) error {
		redeployed = append(redeployed, nodeID)
		return nil
	})
	got, err := src(context.Background())
	if err != nil || len(got) != 1 {
		t.Fatalf("source: %v %v", got, err)
	}
	if err := got[0].Reload(context.Background(), mesh.LeafPathsIn(got[0].Dir)); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !slices.Equal(redeployed, []string{"c01"}) {
		t.Errorf("redeployed = %v, want [c01]", redeployed)
	}
}

// The api's HTTPS leaf renews in place: refresh swaps in whatever is now on
// disk at the same address, where load — correctly, for its own job — short
// -circuits. That difference is the whole reason the sweep has a hook here:
// without it a renewed file would sit unserved until the api restarted.
func TestAPILeaf_RefreshPicksUpARenewedLeaf(t *testing.T) {
	dir := t.TempDir()
	ca, err := mesh.EnsureMeshCA(dir, "test")
	if err != nil {
		t.Fatalf("EnsureMeshCA: %v", err)
	}
	// Two leaves for the same address, distinguishable by NotAfter — "the
	// file the sweep replaced" and "what it replaced it with".
	hostname, _ := os.Hostname()
	ip := net.ParseIP("192.168.1.2")
	mintInto := func(lifetime time.Duration) mesh.LeafPaths {
		t.Helper()
		spec := apiLeafSpec(hostname, ip)
		spec.Lifetime = lifetime
		out := filepath.Join(dir, "tls", lifetime.String())
		paths, err := mesh.MintLeafToDisk(ca, out, spec)
		if err != nil {
			t.Fatalf("MintLeafToDisk: %v", err)
		}
		return paths
	}
	before := mintInto(200 * 24 * time.Hour)
	after := mintInto(400 * 24 * time.Hour)

	current := before
	leaf := &apiLeaf{mint: func(net.IP) (mesh.LeafPaths, error) { return current, nil }}
	if err := leaf.load(ip); err != nil {
		t.Fatalf("load: %v", err)
	}
	served := func() time.Time {
		t.Helper()
		c, err := leaf.getCertificate(&tls.ClientHelloInfo{})
		if err != nil {
			t.Fatal(err)
		}
		return c.Leaf.NotAfter
	}
	first := served()

	current = after
	if err := leaf.load(ip); err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := served(); !got.Equal(first) {
		t.Fatal("load must keep its same-address short-circuit")
	}
	if err := leaf.refresh(ip); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got := served(); !got.After(first) {
		t.Errorf("refresh did not swap in the renewed leaf (NotAfter still %s)", first)
	}
	// And the address it is loaded for is still recorded, so a later address
	// change is still noticed.
	if leaf.ip != ipString(ip) {
		t.Errorf("leaf.ip = %q, want %q", leaf.ip, ipString(ip))
	}
}
