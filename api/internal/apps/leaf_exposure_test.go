package apps

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// realRotator is the rotator main.go actually wires — PrepareAppLeaf against an
// on-disk leaf, CommitAppLeaf after the node accepts it.
//
// The handler tests for #197 all install a MOCK rotator, which is exactly why
// they could not see that revoking exposure shipped nothing: a mock returning
// renewed=false looks identical to the real thing wrongly deciding the leaf is
// still usable. This test drives the real one end to end and asserts on the
// bytes that reach the node.
func realRotator(t *testing.T, ca *mesh.MeshCA, dir, clusterID string) LeafRotator {
	t.Helper()
	return func(app *App) (proto.AppLeafCmd, bool, func() error, error) {
		leafDir := filepath.Join(dir, app.ID)
		certPEM, keyPEM, renewed, err := mesh.PrepareAppLeaf(ca, leafDir, clusterID, app.Name, app.ExposeLAN)
		if err != nil {
			return proto.AppLeafCmd{}, false, nil, err
		}
		names := mesh.AppLeafDNSNames(clusterID, app.Name, app.ExposeLAN)
		cmd := proto.AppLeafCmd{
			AppID: app.ID, Name: app.Name, CertPEM: certPEM, KeyPEM: keyPEM,
			TailnetFQDN: names[0], UpstreamPort: app.PublishedPort,
		}
		if len(names) > 1 {
			cmd.LANFQDN = names[1]
		}
		return cmd, renewed, func() error { return mesh.CommitAppLeaf(leafDir, certPEM, keyPEM) }, nil
	}
}

// Revoking LAN exposure must actually reach the node. The .lan name is a route
// on the proxy's LAN listener, cleared only by shipping a fresh AppLeafCmd with
// an empty LANFQDN — so "the database says tailnet-only" is not revocation.
//
// Before the exact-SAN fix this test failed at the second stage: the wanted SAN
// set became a SUBSET of the committed leaf's, the generic drift check tolerates
// extra names, so renewed came back false and nothing was delivered. The node
// kept a valid <app>.lan certificate and its LAN route for ~10 months.
func TestRotateAppLeaf_RevokingExposureReachesTheNode(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedAppWithPort(t, "n", "a", "jellyfin", 8096, true)
	ca, err := mesh.EnsureMeshCA(t.TempDir(), "home1")
	if err != nil {
		t.Fatalf("mesh CA: %v", err)
	}
	rotate := realRotator(t, ca, t.TempDir(), "home1")

	got := make(chan proto.AppLeafCmd, 2)
	sub := fakeLeafAgent(t, nc, "n", got)
	defer sub.Unsubscribe()

	app, err := store.Get(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}

	// 1. First rotation while exposed: the node gets the .lan name.
	if res := RotateAppLeaf(ctx, inv, nc, rotate, app); res.Outcome != LeafShipped {
		t.Fatalf("first rotation: outcome %q err %v", res.Outcome, res.Err)
	}
	first := <-got
	if first.LANFQDN != "jellyfin.lan.home1.internal" {
		t.Fatalf("exposed app should carry the .lan name, got %q", first.LANFQDN)
	}

	// 2. Revoke, exactly as the PATCH handler does.
	if err := store.SetExposeLAN(ctx, "a", false, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	app.ExposeLAN = false
	res := RotateAppLeaf(ctx, inv, nc, rotate, app)
	if res.Outcome != LeafShipped {
		t.Fatalf("revoking exposure must ship a fresh leaf, got outcome %q err %v — the node keeps its LAN route otherwise", res.Outcome, res.Err)
	}
	second := <-got
	if second.LANFQDN != "" {
		t.Fatalf("revoked app must ship an EMPTY LANFQDN so the proxy drops the LAN host route, got %q", second.LANFQDN)
	}
	if second.TailnetFQDN != "jellyfin.home1.internal" {
		t.Errorf("tailnet name must survive the revoke, got %q", second.TailnetFQDN)
	}

	// 3. And it settles: a second rotation at the same exposure ships nothing.
	// Exact SAN matching would otherwise re-mint on every sweep forever.
	if res := RotateAppLeaf(ctx, inv, nc, rotate, app); res.Outcome != LeafUnchanged {
		t.Fatalf("a settled leaf must not re-ship, got %q", res.Outcome)
	}
}
