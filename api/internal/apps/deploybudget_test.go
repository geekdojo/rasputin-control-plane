package apps

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
	"github.com/nats-io/nats.go"
)

// The budget on the app row is useless if it never reaches the agent — the
// agent is the process that actually holds the deadline. Assert the wire, not
// the intention.
func TestDeployPush_SendsTheAppsOwnBudgetToTheAgent(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", "a", "immich")

	// Give the app a budget the way an install from a heavy tile would.
	app, _ := store.Get(context.Background(), "a")
	app.DeployBudgetSeconds = 900
	if err := store.Delete(context.Background(), "a"); err != nil {
		t.Fatalf("reseed delete: %v", err)
	}
	if err := store.Create(context.Background(), app); err != nil {
		t.Fatalf("reseed create: %v", err)
	}

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
		if cmd.WorkBudgetSeconds != 900 {
			t.Errorf("agent was sent WorkBudgetSeconds=%d, want 900 — without it the "+
				"agent falls back to the default and the tile's declaration does nothing",
				cmd.WorkBudgetSeconds)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent never received a deploy command")
	}
}

// An app that declared nothing must send zero, not a materialised default: the
// agent maps zero to its own default, and an api that started guessing here
// would silently override an agent that knew better.
func TestDeployPush_UndeclaredBudgetIsSentAsZero(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", "a", "freshrss")

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
		if cmd.WorkBudgetSeconds != 0 {
			t.Errorf("WorkBudgetSeconds=%d, want 0", cmd.WorkBudgetSeconds)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent never received a deploy command")
	}
}

// The reconcile sweep decides a transitional row is stale rather than busy by
// comparing its age against the deploy deadline. That has to be the APP's
// deadline: a tile granted fifteen minutes must not be declared stale at five,
// and a tile that asked for ninety seconds should not get five minutes of
// grace it never wanted.
func TestIsRealDrift_StalenessWindowFollowsTheAppsBudget(t *testing.T) {
	now := time.Now().UTC()

	heavy := &App{LastStatus: proto.AppStatusDeploying, DeployBudgetSeconds: 900}
	heavy.UpdatedAt = now.Add(-6 * time.Minute)
	if isRealDrift(heavy, proto.AppStatusStopped, now) {
		t.Error("a tile with a 15-minute budget was called stale after 6 minutes — " +
			"reconcile would clobber a deploy that is still pulling")
	}
	heavy.UpdatedAt = now.Add(-20 * time.Minute)
	if !isRealDrift(heavy, proto.AppStatusStopped, now) {
		t.Error("past its own budget the row is stale, not busy, and must be corrected")
	}

	light := &App{LastStatus: proto.AppStatusDeploying, DeployBudgetSeconds: 90}
	light.UpdatedAt = now.Add(-3 * time.Minute)
	if !isRealDrift(light, proto.AppStatusStopped, now) {
		t.Error("a tile with a 90-second budget was still considered in-flight after " +
			"3 minutes — the point of a short budget is a short wait")
	}

	// Undeclared falls back to the default window, unchanged from before.
	deflt := &App{LastStatus: proto.AppStatusDeploying}
	deflt.UpdatedAt = now.Add(-1 * time.Minute)
	if isRealDrift(deflt, proto.AppStatusStopped, now) {
		t.Error("an app with no declared budget must keep the default grace period")
	}
}

// proto and tileschema are separate modules and cannot import each other, so
// the default budget and the range a tile may declare are stated in two places.
// This is the only build that sees both. If they ever drift, a tile could
// declare a budget the reader refuses to honour — or, worse, the default could
// fall outside the range and every undeclared tile would be silently clamped.
func TestDefaultBudgetSitsInsideTheTileAuthoringBounds(t *testing.T) {
	def := int(proto.AppDeployWork.Seconds())
	if def < tileschema.DeployBudgetMinSeconds || def > tileschema.DeployBudgetMaxSeconds {
		t.Fatalf("proto default %ds is outside tileschema's %d-%d authoring range",
			def, tileschema.DeployBudgetMinSeconds, tileschema.DeployBudgetMaxSeconds)
	}
	if got := int(proto.AppDeployWorkMin.Seconds()); got != tileschema.DeployBudgetMinSeconds {
		t.Errorf("proto clamps at %ds but tileschema lets an author write %ds",
			got, tileschema.DeployBudgetMinSeconds)
	}
	if got := int(proto.AppDeployWorkMax.Seconds()); got != tileschema.DeployBudgetMaxSeconds {
		t.Errorf("proto clamps at %ds but tileschema lets an author write %ds",
			got, tileschema.DeployBudgetMaxSeconds)
	}
}
