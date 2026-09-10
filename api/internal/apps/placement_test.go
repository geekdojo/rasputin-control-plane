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

// design/storage.md §6.4's placement, on the api's side of the wire: it has to
// survive the ledger and it has to reach the agent, because the agent is the
// only process that can act on it.

// A placement that does not round-trip through the ledger is a placement the
// deploy path will silently forget — and forgetting it means the app's volumes
// go to the boot medium while the operator believes they are on their disk.
func TestStore_PlacementRoundTrips(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	now := time.Now().UTC()

	placed := &App{
		ID: "A1", Name: "immich", ComposeYAML: "services: {}", TargetNode: "n",
		DataDiskPartUUID: "9d0f4a2b-01",
		LastStatus:       proto.AppStatusStopped, CreatedAt: now, UpdatedAt: now,
	}
	if err := store.Create(ctx, placed); err != nil {
		t.Fatalf("create: %v", err)
	}
	unplaced := &App{
		ID: "A2", Name: "freshrss", ComposeYAML: "services: {}", TargetNode: "n",
		LastStatus: proto.AppStatusStopped, CreatedAt: now, UpdatedAt: now,
	}
	if err := store.Create(ctx, unplaced); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := store.Get(ctx, "A1")
	if err != nil || got == nil {
		t.Fatalf("get: %v", err)
	}
	if got.DataDiskPartUUID != "9d0f4a2b-01" {
		t.Errorf("DataDiskPartUUID = %q, want 9d0f4a2b-01", got.DataDiskPartUUID)
	}
	// The default has to read back as the default. Empty is the boot medium,
	// and every app installed before this column existed is empty.
	got, err = store.Get(ctx, "A2")
	if err != nil || got == nil {
		t.Fatalf("get: %v", err)
	}
	if got.DataDiskPartUUID != "" {
		t.Errorf("an unplaced app read back placed: %q", got.DataDiskPartUUID)
	}
}

// The placement on the app row is useless if it never reaches the agent — the
// agent is the process that resolves it, proves the disk and rewrites the
// compose. Assert the wire, not the intention.
func TestDeployPush_SendsThePlacementToTheAgent(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", "a", "immich")

	app, _ := store.Get(context.Background(), "a")
	app.DataDiskPartUUID = "9d0f4a2b-01"
	if err := store.Delete(context.Background(), "a"); err != nil {
		t.Fatalf("reseed delete: %v", err)
	}
	if err := store.Create(context.Background(), app); err != nil {
		t.Fatalf("reseed create: %v", err)
	}

	if cmd := captureDeployCmd(t, nc, store, inv); cmd.DataDiskPartUUID != "9d0f4a2b-01" {
		t.Errorf("agent was sent DataDiskPartUUID=%q, want 9d0f4a2b-01 — without it the "+
			"agent deploys onto the boot medium and reports success",
			cmd.DataDiskPartUUID)
	}
}

// An unplaced app must send NOTHING. The empty string is what the agent reads
// as "the boot medium", and it is the difference between a deploy the agent
// passes straight through and one it parses, rewrites and can refuse.
func TestDeployPush_UnplacedAppSendsNoPlacement(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", "a", "freshrss")

	if cmd := captureDeployCmd(t, nc, store, inv); cmd.DataDiskPartUUID != "" {
		t.Errorf("DataDiskPartUUID = %q, want empty", cmd.DataDiskPartUUID)
	}
}

// captureDeployCmd runs deployPush against a subscriber that answers OK, and
// returns the command the agent would have received.
func captureDeployCmd(t *testing.T, nc *nats.Conn, store *Store, inv *inventory.Store) proto.AppDeployCmd {
	t.Helper()
	got := make(chan proto.AppDeployCmd, 1)
	sub, err := nc.Subscribe(proto.AppDeploySubject("n"), func(m *nats.Msg) {
		var cmd proto.AppDeployCmd
		_ = json.Unmarshal(m.Data, &cmd)
		got <- cmd
		ack, _ := json.Marshal(proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatalf("sub: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	if _, err := deployPush(store, inv, nc)(newStepCtxNATS(`{"appId":"a"}`, nc)); err != nil {
		t.Fatalf("deployPush: %v", err)
	}
	select {
	case cmd := <-got:
		return cmd
	case <-time.After(2 * time.Second):
		t.Fatal("agent never received a deploy command")
		return proto.AppDeployCmd{}
	}
}
