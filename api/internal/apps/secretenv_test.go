package apps

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// secretsFloor is the agent version a node needs to be sent a secret-bearing
// deploy (geekdojo/geekdojo-brain#776): the floor of docker.deploy_secrets.
func secretsFloor(t *testing.T) string {
	t.Helper()
	v, ok := proto.VerbMinAgentVersion(proto.AppDeploySecretsVerb)
	if !ok {
		t.Fatal("docker.deploy_secrets has no floor")
	}
	return v
}

// setAgentVersion makes node n report version v.
func setAgentVersion(t *testing.T, inv *inventory.Store, v string) {
	t.Helper()
	n, err := inv.Get(context.Background(), "n")
	if err != nil || n == nil {
		t.Fatalf("node n: %v", err)
	}
	n.AgentVersion = v
	if err := inv.Update(context.Background(), n); err != nil {
		t.Fatal(err)
	}
}

// busMessage is one message seen on the bus.
type busMessage struct {
	subject string
	data    []byte
}

// busCapture records every message on subjects, answering a deploy subject
// with a running ack as an agent at the floor would.
func busCapture(t *testing.T, nc *nats.Conn, subjects ...string) func() []busMessage {
	t.Helper()
	var mu sync.Mutex
	var seen []busMessage
	for _, subject := range subjects {
		sub, err := nc.Subscribe(subject, func(m *nats.Msg) {
			mu.Lock()
			seen = append(seen, busMessage{subject: m.Subject, data: append([]byte(nil), m.Data...)})
			mu.Unlock()
			if m.Reply != "" {
				ack, _ := json.Marshal(proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
				_ = m.Respond(ack)
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sub.Unsubscribe() })
	}
	return func() []busMessage {
		if err := nc.Flush(); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		return append([]busMessage(nil), seen...)
	}
}

// TC-776-13: a token-bearing app on a node at the floor goes out as exactly
// one message, on docker.deploy_secrets; its composeYaml holds the reference
// and not the value, and its secretEnv carries the value.
func TestPushStep_SecretComposeGoesOutOnTheSecretsVerb(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedAppWithSecret(t, "n", testAppID)
	src, derived := wiringSource(t)
	canary := derived(testAppID, "db-password")
	seen := busCapture(t, nc, proto.AppDeploySubject("n"), proto.AppDeploySecretsSubject("n"))

	if _, err := deployPush(store, inv, nc, src)(newStepCtxNATS(`{"appId":"`+testAppID+`"}`, nc)); err != nil {
		t.Fatalf("deployPush: %v", err)
	}
	msgs := seen()
	if len(msgs) != 1 || msgs[0].subject != proto.AppDeploySecretsSubject("n") {
		t.Fatalf("messages %d, first on %v; want exactly one, on %s", len(msgs), msgs, proto.AppDeploySecretsSubject("n"))
	}
	var raw struct {
		ComposeYAML string            `json:"composeYaml"`
		SecretEnv   map[string]string `json:"secretEnv"`
	}
	if err := json.Unmarshal(msgs[0].data, &raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw.ComposeYAML, canary) || !strings.Contains(raw.ComposeYAML, "${RASPUTIN_SECRET_DB_PASSWORD}") {
		t.Fatalf("composeYaml holds the value, or not the reference:\n%s", raw.ComposeYAML)
	}
	if raw.SecretEnv["RASPUTIN_SECRET_DB_PASSWORD"] != canary {
		t.Fatal("secretEnv does not carry the value")
	}
}

// TC-776-15: a token-free app on a node below the floor still deploys, on
// docker.deploy, with no secretEnv key.
func TestPushStep_TokenFreeComposeOnAnOldAgentUsesDockerDeploy(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedOnlineApp(t, "n", testAppID, "plain")
	setAgentVersion(t, inv, "2026.10.3")
	seen := busCapture(t, nc, proto.AppDeploySubject("n"), proto.AppDeploySecretsSubject("n"))

	if _, err := deployPush(store, inv, nc, testSource(t))(newStepCtxNATS(`{"appId":"`+testAppID+`"}`, nc)); err != nil {
		t.Fatalf("deployPush: %v", err)
	}
	msgs := seen()
	if len(msgs) != 1 || msgs[0].subject != proto.AppDeploySubject("n") {
		t.Fatalf("messages %v; want exactly one, on %s", msgs, proto.AppDeploySubject("n"))
	}
	if strings.Contains(string(msgs[0].data), "secretEnv") {
		t.Fatalf("a token-free deploy carries a secretEnv key: %s", msgs[0].data)
	}
}

// TC-776-14: a token-bearing app on a node whose agent is below the floor,
// unreported, a dev build's "0.0.1-dev", or garbage is refused before
// DEPLOYING, through the deploy saga (push step) and a compose-change saga
// (upgrade, pull step): one sentence naming the node, its version or "not
// reported" and the floor, ending "Update the node."; no status change, no
// change event, nothing published on either deploy subject (nor a pull or a
// volume check), and the app's compose unchanged.
func TestSecretDeployRefusedForAnAgentBelowTheFloor(t *testing.T) {
	const id = "01J9ZK3Q0M8X7Y6W5V4T3S2R1P"
	floor := secretsFloor(t)
	sagas := []struct {
		kind  string
		setup func(t *testing.T, nc *nats.Conn) (*Store, *inventory.Store, jobs.Workflow, any)
	}{
		{"app.deploy", func(t *testing.T, nc *nats.Conn) (*Store, *inventory.Store, jobs.Workflow, any) {
			store, inv := seedComposeApp(t, id, secretComposeV1)
			return store, inv, wf(t)(DeployWorkflow(store, inv, nc, nil, testSource(t))), DeploySpec{AppID: id}
		}},
		{"app.upgrade", func(t *testing.T, nc *nats.Conn) (*Store, *inventory.Store, jobs.Workflow, any) {
			store, inv := seedUpgradeApp(t, id)
			tile := strings.Replace(composeV2, "    volumes:", "    environment:\n      DB_PASSWORD: ${secret:db-password}\n    volumes:", 1)
			return store, inv, wf(t)(UpgradeWorkflow(store, inv, nc, nil, lookupOf(upgradeTile(tile), 2), testSource(t))), ComposeChangeSpec{AppID: id}
		}},
	}
	for _, saga := range sagas {
		for _, version := range []string{"2026.10.3", "", "0.0.1-dev", "garbage"} {
			t.Run(saga.kind+"/"+version, func(t *testing.T) {
				ctx := context.Background()
				nc := startNATS(t)
				store, inv, w, spec := saga.setup(t, nc)
				setAgentVersion(t, inv, version)
				before, err := store.Get(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				seen := busCapture(t, nc, proto.AppDeploySubject("n"), proto.AppDeploySecretsSubject("n"),
					proto.AppPullSubject("n"), proto.AppVolumesCheckSubject("n"), proto.AllAppsFilter)
				runner, jst := realRunner(t, nc, w)
				j, err := runner.Submit(ctx, saga.kind, spec, "test")
				if err != nil {
					t.Fatal(err)
				}
				runner.Wait()
				got, err := jst.GetJob(ctx, j.ID)
				if err != nil || got == nil || got.Status != jobs.StatusFailed {
					t.Fatalf("job ended %+v (%v), want failed", got, err)
				}
				reported := "has not reported its agent version"
				if version != "" {
					reported = "runs agent v" + version
				}
				if !strings.Contains(got.Error, "node n "+reported) || !strings.Contains(got.Error, "v"+floor) ||
					!strings.HasSuffix(got.Error, "Update the node.") {
					t.Errorf("job error %q does not name the node, %q and the floor %s, ending \"Update the node.\"", got.Error, reported, floor)
				}
				if msgs := seen(); len(msgs) != 0 {
					t.Errorf("the refused job published %d message(s), first on %s; want none", len(msgs), msgs[0].subject)
				}
				after, err := store.Get(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				if after.LastStatus != before.LastStatus || after.ComposeYAML != before.ComposeYAML {
					t.Errorf("status %q→%q, compose changed %v; want both unchanged", before.LastStatus, after.LastStatus, after.ComposeYAML != before.ComposeYAML)
				}
			})
		}
	}
}
