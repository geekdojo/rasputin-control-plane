package apps

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nats-io/nats.go"

	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// A deploy must leave the app's leaf on disk, so the renewal sweep sees an app
// that already HAS one.
//
// This is geekdojo/geekdojo-brain#603. The deploy saga used to hold a minter of
// its own — mint in memory, ship, persist nothing — while the sweep went
// through PrepareAppLeaf, which looks for an on-disk leaf and mints a
// replacement when it finds none. So the first sweep after any deploy found an
// empty directory for an app that was already serving a perfectly good
// certificate, minted a second one and re-shipped it. Every deployed app on the
// cluster was re-leafed exactly once, for nothing: needless Mesh CA issuance,
// a needless push to the node, and a spurious apps.leaf_rotate in the ledger.
//
// It went unnoticed because nothing asserted it. sweep_test.go:341 covers the
// equivalent property for the HEADSCALE leaf — the sweep's spec must match what
// Start mints, or it re-mints every sweep — and the app path had no counterpart.
// This is that counterpart.
//
// Both paths run the same rotator now, so the assertion is about the contract,
// not about which function was called: deploy, then sweep, and the sweep must
// report renewed=false and hand the node the same bytes.
func TestProvisionAppLeaf_DeployPersistsSoTheSweepDoesNotReMint(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	_, inv := seedAppWithPort(t, "n", "a", "jellyfin", 8096, true)

	caDir := t.TempDir()
	ca, err := mesh.EnsureMeshCA(caDir, "home1")
	if err != nil {
		t.Fatalf("mesh CA: %v", err)
	}
	leafRoot := t.TempDir()
	rotate := realRotator(t, ca, leafRoot, "home1")

	got := make(chan proto.AppLeafCmd, 4)
	sub := fakeLeafAgent(t, nc, "n", got)
	defer sub.Unsubscribe()

	app := &App{ID: "a", Name: "jellyfin", TargetNode: "n", PublishedPort: 8096, ExposeLAN: true}

	// 1. The deploy saga's leaf provisioning.
	ok, detail := provisionAppLeaf(ctx, nc, rotate, app)
	if !ok {
		t.Fatalf("deploy leaf provisioning failed: %s", detail)
	}
	deployed := receiveWithin(t, got, "no leaf reached the node on deploy")

	// 2. The leaf is on disk. This is the whole bug: it used to not be.
	certPath := mesh.LeafPathsIn(filepath.Join(leafRoot, "a")).CertPath
	onDisk, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("deploy did not persist the app's leaf (%s): %v — "+
			"the next sweep will mint a second one for an app that already has one", certPath, err)
	}
	if string(onDisk) != string(deployed.CertPEM) {
		t.Error("the persisted leaf is not the one the node was given")
	}

	// 3. The renewal sweep's per-app path, exactly as RotateLeavesWorkflow runs
	//    it. It re-asserts desired state (so it ships again, by design) but must
	//    NOT mint.
	res := RotateAppLeaf(ctx, inv, nc, rotate, app)
	if res.Outcome != LeafShipped {
		t.Fatalf("sweep outcome %q err %v", res.Outcome, res.Err)
	}
	if res.Renewed {
		t.Error("the first sweep after a deploy re-minted the app's leaf — " +
			"the deploy did not leave a usable leaf on disk (geekdojo/geekdojo-brain#603)")
	}
	swept := receiveWithin(t, got, "no leaf reached the node on the sweep")
	if string(swept.CertPEM) != string(deployed.CertPEM) {
		t.Error("the sweep handed the node a DIFFERENT certificate than the deploy did")
	}
}

// A node that refuses the leaf must not leave it persisted, or the app is stuck
// with a certificate the node never took and the sweep has nothing to retry.
// Same invariant RotateAppLeaf holds for an offline node; it is why the commit
// is after the ack and not before it.
func TestProvisionAppLeaf_RejectedLeafIsNotPersisted(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	seedAppWithPort(t, "n", "a", "jellyfin", 8096, true)

	ca, err := mesh.EnsureMeshCA(t.TempDir(), "home1")
	if err != nil {
		t.Fatalf("mesh CA: %v", err)
	}
	leafRoot := t.TempDir()
	rotate := realRotator(t, ca, leafRoot, "home1")

	sub := refusingLeafAgent(t, nc, "n")
	defer sub.Unsubscribe()

	app := &App{ID: "a", Name: "jellyfin", TargetNode: "n", PublishedPort: 8096, ExposeLAN: true}
	if ok, _ := provisionAppLeaf(ctx, nc, rotate, app); ok {
		t.Fatal("a refused leaf must not report the app as routed")
	}
	if _, err := os.Stat(mesh.LeafPathsIn(filepath.Join(leafRoot, "a")).CertPath); !os.IsNotExist(err) {
		t.Errorf("a leaf the node refused must not be persisted (stat err = %v)", err)
	}
}

// refusingLeafAgent is a node that answers the leaf RPC and rejects it — the
// case that separates "the node has this leaf" from "we minted this leaf".
func refusingLeafAgent(t *testing.T, nc *nats.Conn, nodeID string) *nats.Subscription {
	t.Helper()
	sub, err := nc.Subscribe(proto.AppLeafSubject(nodeID), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.AppLeafAck{OK: false, Detail: "no thanks"})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatalf("agent sub: %v", err)
	}
	return sub
}
