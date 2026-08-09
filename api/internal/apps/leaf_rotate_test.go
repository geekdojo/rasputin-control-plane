package apps

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// rotateCounts decodes the sweep step's result JSON.
func rotateCounts(t *testing.T, raw json.RawMessage) map[string]int {
	t.Helper()
	var m map[string]int
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode sweep counts: %v", err)
	}
	return m
}

// TestRotateLeaves_ShipsAndCommitsWhenRenewed: a renewed leaf on an online node
// is delivered, and commit runs only AFTER the node accepts it.
func TestRotateLeaves_ShipsAndCommitsWhenRenewed(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedAppWithPort(t, "n", "a", "jellyfin", 8096, true)

	got := make(chan proto.AppLeafCmd, 1)
	sub := fakeLeafAgent(t, nc, "n", got)
	defer sub.Unsubscribe()

	committed := 0
	rotate := func(app *App) (proto.AppLeafCmd, bool, func() error, error) {
		cmd := proto.AppLeafCmd{
			AppID: app.ID, Name: app.Name, CertPEM: []byte("C"), KeyPEM: []byte("K"),
			TailnetFQDN: "jellyfin.home1.internal", UpstreamPort: app.PublishedPort,
		}
		return cmd, true, func() error { committed++; return nil }, nil
	}

	res, err := rotateLeavesSweep(store, inv, nc, rotate)(newStepCtxNATS(`{}`, nc))
	if err != nil {
		t.Fatalf("rotate sweep: %v", err)
	}
	select {
	case cmd := <-got:
		if cmd.AppID != "a" || cmd.Remove || cmd.UpstreamPort != 8096 {
			t.Errorf("shipped cmd wrong: %+v", cmd)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent never received the rotated leaf")
	}
	if committed != 1 {
		t.Errorf("commit called %d times, want 1 (only after delivery)", committed)
	}
	c := rotateCounts(t, res)
	if c["rotated"] != 1 || c["shipped"] != 1 || c["checked"] != 1 {
		t.Errorf("counts = %v, want checked=1 rotated=1 shipped=1", c)
	}
}

// TestRotateLeaves_SkipsWhenNotRenewed: a still-valid leaf (renewed=false) is
// neither shipped nor committed.
func TestRotateLeaves_SkipsWhenNotRenewed(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedAppWithPort(t, "n", "a", "jellyfin", 8096, false)

	committed := 0
	rotate := func(app *App) (proto.AppLeafCmd, bool, func() error, error) {
		return proto.AppLeafCmd{AppID: app.ID}, false, func() error { committed++; return nil }, nil
	}

	res, err := rotateLeavesSweep(store, inv, nc, rotate)(newStepCtxNATS(`{}`, nc))
	if err != nil {
		t.Fatalf("rotate sweep: %v", err)
	}
	if committed != 0 {
		t.Errorf("commit called %d times, want 0 when not renewed", committed)
	}
	c := rotateCounts(t, res)
	if c["checked"] != 1 || c["rotated"] != 0 || c["shipped"] != 0 {
		t.Errorf("counts = %v, want checked=1 rotated=0 shipped=0", c)
	}
}

// TestRotateLeaves_OfflineNodeDefersNoCommit: a renewed leaf whose node is
// offline is not shipped and — critically — not committed, so the next sweep
// re-mints and retries (the on-disk leaf can't outrun what the node holds).
func TestRotateLeaves_OfflineNodeDefersNoCommit(t *testing.T) {
	nc := startNATS(t)
	ctx := context.Background()
	store := newStore(t)
	inv := newInventory(t)
	// Node last seen 10m ago → offline.
	if err := inv.Insert(ctx, &proto.Node{
		ID: "n", Role: proto.RoleCompute, Hostname: "n.test",
		FirstSeen: time.Now().Add(-time.Hour), LastSeen: time.Now().Add(-10 * time.Minute),
	}); err != nil {
		t.Fatalf("inv insert: %v", err)
	}
	a := makeApp("a", "jellyfin")
	a.TargetNode = "n"
	a.PublishedPort = 8096
	if err := store.Create(ctx, a); err != nil {
		t.Fatalf("create app: %v", err)
	}

	committed := 0
	rotate := func(app *App) (proto.AppLeafCmd, bool, func() error, error) {
		return proto.AppLeafCmd{AppID: app.ID}, true, func() error { committed++; return nil }, nil
	}

	res, err := rotateLeavesSweep(store, inv, nc, rotate)(newStepCtxNATS(`{}`, nc))
	if err != nil {
		t.Fatalf("rotate sweep: %v", err)
	}
	if committed != 0 {
		t.Error("commit ran for an offline node; the leaf must not advance until delivered")
	}
	c := rotateCounts(t, res)
	if c["rotated"] != 1 || c["shipped"] != 0 || c["skipped"] != 1 {
		t.Errorf("counts = %v, want rotated=1 shipped=0 skipped=1", c)
	}
}

// TestRotateLeaves_NilRotator is a no-op (dev without a CA).
func TestRotateLeaves_NilRotator(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedAppWithPort(t, "n", "a", "jellyfin", 8096, false)
	if _, err := rotateLeavesSweep(store, inv, nc, nil)(newStepCtxNATS(`{}`, nc)); err != nil {
		t.Fatalf("nil rotator should be a no-op: %v", err)
	}
}
