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
		certPEM, keyPEM, renewed, err := mesh.PrepareAppLeaf(ca, leafDir, clusterID, app.Name)
		if err != nil {
			return proto.AppLeafCmd{}, false, nil, err
		}
		tailnetFQDN, lanFQDN := mesh.AppRouteHosts(clusterID, app.Name, app.ExposeLAN)
		cmd := proto.AppLeafCmd{
			AppID: app.ID, Name: app.Name, CertPEM: certPEM, KeyPEM: keyPEM,
			TailnetFQDN: tailnetFQDN, LANFQDN: lanFQDN, UpstreamPort: app.PublishedPort,
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
//
// The leaf is now exposure-INDEPENDENT — it carries both names always — so the
// SAN set does not move when exposure does, and there is deliberately no
// mechanism that notices it moving. RotateAppLeaf asserts desired state on
// every delivery instead, which is what makes this test pass for a reason that
// cannot silently stop being true. It drives the real rotator and asserts on
// the LANFQDN that reaches the node, never on how the decision was made.
func TestRotateAppLeaf_RevokingExposureReachesTheNode(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedAppWithPort(t, "n", "a", "jellyfin", 8096, true)
	ca, err := mesh.EnsureMeshCA(t.TempDir(), "home1")
	if err != nil {
		t.Fatalf("mesh CA: %v", err)
	}
	rotate := realRotator(t, ca, t.TempDir(), "home1")

	got := make(chan proto.AppLeafCmd, 4)
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

	// The CERT must not have moved. Revoking exposure is a route change, and
	// re-minting a leaf for it is the churn this design exists to remove — an
	// identity that changes whenever a policy toggle does is not an identity.
	if string(second.CertPEM) != string(first.CertPEM) {
		t.Error("revoking exposure re-minted the leaf; the cert carries both names and must survive a route change")
	}

	// 3. A repeat rotation at the same exposure re-asserts the SAME state: it
	// delivers again (that is the design — assert, don't detect) but must not
	// re-mint, or every sweep would hand the node a new certificate forever.
	repeat := RotateAppLeaf(ctx, inv, nc, rotate, app)
	if repeat.Outcome != LeafShipped {
		t.Fatalf("desired state is re-asserted every sweep, got outcome %q", repeat.Outcome)
	}
	if repeat.Renewed {
		t.Error("a settled leaf must not be re-minted just because it was re-delivered")
	}
	if again := <-got; again.LANFQDN != "" || again.TailnetFQDN != "jellyfin.home1.internal" {
		t.Errorf("re-assert changed the route: lan=%q tailnet=%q", again.LANFQDN, again.TailnetFQDN)
	}

	// 4. Granting it back reaches the node too — the reverse edge of the same
	// mechanism, and the case a marker written on the wrong side would break.
	if err := store.SetExposeLAN(ctx, "a", true, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	app.ExposeLAN = true
	if res := RotateAppLeaf(ctx, inv, nc, rotate, app); res.Outcome != LeafShipped {
		t.Fatalf("re-granting exposure must ship, got outcome %q err %v", res.Outcome, res.Err)
	}
	if third := <-got; third.LANFQDN != "jellyfin.lan.home1.internal" {
		t.Fatalf("re-granted app must carry the .lan name again, got %q", third.LANFQDN)
	}
}
