package apps

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/appsecret"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// The three node-bound sites, and the one rule that distinguishes them
// (ADR-0006 Decision 11a, geekdojo/geekdojo-brain#520): the same compose string
// leaves the api for an agent from three places, and only the DEPLOY may carry a
// real secret. The other two escape the token — the pull because it has no use
// for a credential, and the volume check because it hands the compose to Docker
// Compose itself, whose interpolator hard-fails on the raw token and so refuses
// the whole check.
//
// These are wiring tests. appsecret's own suite owns whether the derivation and
// the substitution are correct; what is proved here is that each of the three
// call sites got the treatment it was supposed to get, because getting them
// mixed up is silent both ways: a resolved compose on the pull leaks a
// credential to a path that never needed it, and an unescaped one on the volume
// check refuses every compose change to a tile that uses a secret.

const secretCompose = "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: ${secret:db-password}\n"

func wiringSeed(t *testing.T) *appsecret.Seed {
	t.Helper()
	key := make([]byte, appsecret.SeedLen)
	for i := range key {
		key[i] = byte(i + 1)
	}
	seed, err := appsecret.NewSeed(key, appsecret.DerivationVersion)
	if err != nil {
		t.Fatal(err)
	}
	return seed
}

// seedAppWithSecret seeds an online compute node and an app whose INSTALLED
// compose declares a secret — the shape of a karakeep/romm/immich tile once #521
// moves them onto this channel.
func seedAppWithSecret(t *testing.T, nodeID, appID string) (*Store, *inventory.Store) {
	t.Helper()
	ctx := context.Background()
	store := newStore(t)
	inv := newInventory(t)
	now := time.Now().UTC()
	if err := inv.Insert(ctx, &proto.Node{
		ID: nodeID, Role: proto.RoleCompute, Hostname: nodeID + ".test",
		FirstSeen: now, LastSeen: now,
	}); err != nil {
		t.Fatalf("inv insert: %v", err)
	}
	app := makeApp(appID, "withsecret")
	app.TargetNode = nodeID
	app.ComposeYAML = secretCompose
	if err := store.Create(ctx, app); err != nil {
		t.Fatalf("Create app: %v", err)
	}
	return store, inv
}

func TestDeployPushResolvesTheSecretAndTheRowKeepsThePlaceholder(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedAppWithSecret(t, "n", testAppID)
	seed := wiringSeed(t)
	want, err := seed.Derive(testAppID, "db-password", appsecret.InitialVersion)
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	if _, err := deployPush(store, inv, nc, seed)(newStepCtxNATS(`{"appId":"`+testAppID+`"}`, nc)); err != nil {
		t.Fatalf("deployPush: %v", err)
	}
	var cmd proto.AppDeployCmd
	select {
	case cmd = <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("the agent never received a deploy command")
	}
	if strings.Contains(cmd.ComposeYAML, "${secret:") {
		t.Fatalf("the deploy carried an unresolved token — the container would get the literal as its password:\n%s", cmd.ComposeYAML)
	}
	if !strings.Contains(cmd.ComposeYAML, want) {
		t.Fatalf("the deploy does not carry the derived value:\n%s", cmd.ComposeYAML)
	}

	// THE point of resolving on the way out: the row still holds the
	// placeholder. The control plane's SQLite has no encryption at rest, and the
	// UI's compose preview reads this row.
	row, err := store.Get(ctx, testAppID)
	if err != nil {
		t.Fatal(err)
	}
	if row.ComposeYAML != secretCompose {
		t.Fatalf("the row no longer holds the verbatim placeholder compose:\n%s", row.ComposeYAML)
	}
	if strings.Contains(row.ComposeYAML, want) {
		t.Fatal("a derived credential was written into apps.compose_yaml")
	}
}

// No seed and a compose that needs one: refused, and refused before the status
// moves, so the app is left where it was rather than stranded in DEPLOYING.
func TestDeployPushRefusesASecretComposeWithNoSeed(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedAppWithSecret(t, "n", testAppID)
	before, err := store.Get(ctx, testAppID)
	if err != nil {
		t.Fatal(err)
	}

	sub, err := nc.Subscribe(proto.AppDeploySubject("n"), func(m *nats.Msg) {
		t.Error("the agent was sent a deploy command although no secret could be resolved")
		ack, _ := json.Marshal(proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	if _, err := deployPush(store, inv, nc, nil)(newStepCtxNATS(`{"appId":"`+testAppID+`"}`, nc)); err == nil {
		t.Fatal("the deploy went ahead with no seed loaded")
	}
	after, err := store.Get(ctx, testAppID)
	if err != nil {
		t.Fatal(err)
	}
	if after.LastStatus != before.LastStatus {
		t.Errorf("the refused deploy moved the status to %q (was %q)", after.LastStatus, before.LastStatus)
	}
}

// A compose with no token is sent byte for byte, with or without a seed: the
// install path stays a verbatim copy for every app in the field today.
func TestDeployPushSendsAComposeWithNoTokensVerbatim(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", testAppID, "plain")

	got := make(chan proto.AppDeployCmd, 1)
	sub, err := nc.Subscribe(proto.AppDeploySubject("n"), func(m *nats.Msg) {
		var cmd proto.AppDeployCmd
		_ = json.Unmarshal(m.Data, &cmd)
		got <- cmd
		ack, _ := json.Marshal(proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	row, err := store.Get(context.Background(), testAppID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deployPush(store, inv, nc, wiringSeed(t))(newStepCtxNATS(`{"appId":"`+testAppID+`"}`, nc)); err != nil {
		t.Fatalf("deployPush: %v", err)
	}
	select {
	case cmd := <-got:
		if cmd.ComposeYAML != row.ComposeYAML {
			t.Fatalf("a token-less compose was rewritten on the way out:\n got %q\nwant %q", cmd.ComposeYAML, row.ComposeYAML)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the agent never received a deploy command")
	}
}

func TestVolumesCheckEscapesTheTokenRatherThanResolvingIt(t *testing.T) {
	nc := startNATS(t)
	_, inv := seedAppWithSecret(t, "n", testAppID)
	cmds := fakeVolumeCheckAgent(t, nc)

	app := makeApp(testAppID, "withsecret")
	app.TargetNode = "n"
	if _, err := DroppedVolumesOnNode(context.Background(), inv, nc, app, secretCompose); err != nil {
		t.Fatalf("DroppedVolumesOnNode: %v", err)
	}
	select {
	case cmd := <-cmds:
		if !strings.Contains(cmd.ComposeYAML, "$${secret:db-password}") {
			t.Fatalf("the volume check did not escape the token; Docker Compose would refuse the file with an interpolation error:\n%s", cmd.ComposeYAML)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the agent never received a volumes check")
	}
}

func TestPullEscapesTheTokenRatherThanResolvingIt(t *testing.T) {
	nc := startNATS(t)
	_, inv := seedAppWithSecret(t, "n", testAppID)
	seed := wiringSeed(t)
	leaked, err := seed.Derive(testAppID, "db-password", appsecret.InitialVersion)
	if err != nil {
		t.Fatal(err)
	}

	cmds := make(chan proto.AppPullCmd, 1)
	sub, err := nc.Subscribe(proto.AppPullSubject("n"), func(m *nats.Msg) {
		var cmd proto.AppPullCmd
		_ = json.Unmarshal(m.Data, &cmd)
		cmds <- cmd
		ack, _ := json.Marshal(proto.AppPullAck{OK: true})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	app := makeApp(testAppID, "withsecret")
	app.TargetNode = "n"
	if reason := pullOnNode(context.Background(), inv, nc, app, pullTarget{ComposeYAML: secretCompose}); reason != "" {
		t.Fatalf("pullOnNode: %s", reason)
	}
	select {
	case cmd := <-cmds:
		if !strings.Contains(cmd.ComposeYAML, "$${secret:db-password}") {
			t.Fatalf("the pull did not escape the token:\n%s", cmd.ComposeYAML)
		}
		if strings.Contains(cmd.ComposeYAML, leaked) {
			t.Fatal("the pull carried the derived credential — a path that pulls images has no use for one")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the agent never received a pull command")
	}
}
