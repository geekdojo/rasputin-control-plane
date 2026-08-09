package apps

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// seedAppWithPort seeds a compute node + an app with a published port so the
// leaf step has something to front.
func seedAppWithPort(t *testing.T, nodeID, appID, appName string, port int, exposeLAN bool) (*Store, *inventory.Store) {
	t.Helper()
	ctx := context.Background()
	store := newStore(t)
	inv := newInventory(t)
	if err := inv.Insert(ctx, &proto.Node{ID: nodeID, Role: proto.RoleCompute, Hostname: nodeID + ".test", FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC()}); err != nil {
		t.Fatalf("inv insert: %v", err)
	}
	a := makeApp(appID, appName)
	a.TargetNode = nodeID
	a.PublishedPort = port
	a.ExposeLAN = exposeLAN
	if err := store.Create(ctx, a); err != nil {
		t.Fatalf("create app: %v", err)
	}
	return store, inv
}

// fakeLeafAgent subscribes to the node's leaf subject, captures the cmd, acks OK.
func fakeLeafAgent(t *testing.T, nc *nats.Conn, nodeID string, got chan<- proto.AppLeafCmd) *nats.Subscription {
	t.Helper()
	sub, err := nc.Subscribe(proto.AppLeafSubject(nodeID), func(m *nats.Msg) {
		var cmd proto.AppLeafCmd
		_ = json.Unmarshal(m.Data, &cmd)
		got <- cmd
		ack, _ := json.Marshal(proto.AppLeafAck{OK: true})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatalf("agent sub: %v", err)
	}
	return sub
}

func TestDeployLeaf_MintsAndDelivers(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedAppWithPort(t, "n", "a", "jellyfin", 8096, true)

	got := make(chan proto.AppLeafCmd, 1)
	sub := fakeLeafAgent(t, nc, "n", got)
	defer sub.Unsubscribe()

	// Stub minter returns a known delivery command; the step must publish it.
	mint := func(app *App) (proto.AppLeafCmd, error) {
		return proto.AppLeafCmd{
			AppID: app.ID, Name: app.Name, CertPEM: []byte("C"), KeyPEM: []byte("K"),
			TailnetFQDN: "jellyfin.home1.internal", LANFQDN: "jellyfin.lan.home1.internal",
			UpstreamPort: app.PublishedPort,
		}, nil
	}

	if _, err := deployLeaf(store, inv, nc, mint)(newStepCtxNATS(`{"appId":"a"}`, nc)); err != nil {
		t.Fatalf("deployLeaf: %v", err)
	}
	select {
	case cmd := <-got:
		if cmd.AppID != "a" || cmd.UpstreamPort != 8096 || cmd.TailnetFQDN != "jellyfin.home1.internal" || cmd.Remove {
			t.Errorf("delivered cmd wrong: %+v", cmd)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent never received the leaf")
	}
}

func TestDeployLeaf_SkipsWhenNoPortOrNilMinter(t *testing.T) {
	nc := startNATS(t)
	mint := func(app *App) (proto.AppLeafCmd, error) {
		t.Fatal("minter should not be called")
		return proto.AppLeafCmd{}, nil
	}

	// Headless app (port 0): minter not called, no delivery.
	store, inv := seedAppWithPort(t, "n", "a", "headless", 0, false)
	if _, err := deployLeaf(store, inv, nc, mint)(newStepCtxNATS(`{"appId":"a"}`, nc)); err != nil {
		t.Fatalf("deployLeaf (headless): %v", err)
	}

	// nil minter: leaf delivery disabled, no-op.
	store2, inv2 := seedAppWithPort(t, "n2", "b", "app", 80, false)
	if _, err := deployLeaf(store2, inv2, nc, nil)(newStepCtxNATS(`{"appId":"b"}`, nc)); err != nil {
		t.Fatalf("deployLeaf (nil minter): %v", err)
	}
}

func TestDeleteLeaf_SendsRemove(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedAppWithPort(t, "n", "a", "jellyfin", 8096, false)

	got := make(chan proto.AppLeafCmd, 1)
	sub := fakeLeafAgent(t, nc, "n", got)
	defer sub.Unsubscribe()

	removed := ""
	rm := func(appID string) error { removed = appID; return nil }
	if _, err := deleteLeaf(store, inv, nc, rm)(newStepCtxNATS(`{"appId":"a"}`, nc)); err != nil {
		t.Fatalf("deleteLeaf: %v", err)
	}
	select {
	case cmd := <-got:
		if cmd.AppID != "a" || !cmd.Remove {
			t.Errorf("teardown cmd wrong: %+v", cmd)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent never received the teardown")
	}
	if removed != "a" {
		t.Errorf("removeLeaf called with %q, want \"a\" (CP-side leaf dir cleanup)", removed)
	}
}
