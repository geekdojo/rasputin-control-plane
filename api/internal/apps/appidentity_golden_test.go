package apps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/catalog"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// What an agent is sent on a deploy, pinned byte for byte
// (geekdojo/geekdojo-brain#1080). The goldens were written with -update
// against the code before the app-identity switch existed, so this test
// passing with the switch wired off is the proof that the switch changes
// nothing an agent receives: the same subject, the same AppDeployCmd bytes,
// and the same job steps.
//
// Regenerate with: go test ./api/internal/apps -run TestDeployGolden -update

var updateDeployGolden = flag.Bool("update", false, "rewrite testdata/deploy-golden from the current code")

const deployGoldenDir = "testdata/deploy-golden"

// deployGoldenCase is one app the golden pins: how it is seeded and the fixed
// id it is seeded under, so the bytes are the same every run.
type deployGoldenCase struct {
	name  string
	appID string
	app   func(t *testing.T) *App
	// secretsAgent puts the node at the secrets floor, for a compose that
	// carries values on the deploy-with-secrets verb.
	secretsAgent bool
}

func deployGoldenCases() []deployGoldenCase {
	return []deployGoldenCase{
		{
			// (a) a plain catalog tile, as catalog install builds its row.
			name:  "plain-tile",
			appID: "01JG1080000000000000000PTA",
			app: func(t *testing.T) *App {
				t.Helper()
				tile, ok := catalog.MustLoad().Get("minecraft")
				if !ok {
					t.Fatal("the embedded catalog has no minecraft tile")
				}
				now := time.Now().UTC()
				return &App{
					Name: "minecraft", ComposeYAML: tile.ComposeYAML,
					PublishedPort: tile.WebPort(), WebTLS: tile.WebPortTLS(), SourceTile: tile.ID,
					DeployBudgetSeconds: tile.DeployBudgetSeconds,
					LastStatus:          proto.AppStatusStopped, CreatedAt: now, UpdatedAt: now,
				}
			},
		},
		{
			// (b) a compose that uses a secret, resolved through the HKDF source
			// main wires, over a fixed synthetic seed.
			name:  "secret-compose",
			appID: "01JG1080000000000000000SCB",
			app: func(t *testing.T) *App {
				now := time.Now().UTC()
				return &App{
					Name: "karakeep", ComposeYAML: secretCompose, SourceTile: "karakeep",
					LastStatus: proto.AppStatusStopped, CreatedAt: now, UpdatedAt: now,
				}
			},
			secretsAgent: true,
		},
		{
			// (c) a custom app: an owner-supplied compose, no source tile.
			name:  "custom-app",
			appID: "01JG1080000000000000000CAC",
			app: func(t *testing.T) *App {
				now := time.Now().UTC()
				return &App{
					Name: "mine", ComposeYAML: customV1, SourceTile: "",
					PublishedPort: 8080, DeployBudgetSeconds: 300,
					LastStatus: proto.AppStatusStopped, CreatedAt: now, UpdatedAt: now,
				}
			},
		},
	}
}

// deployWorkflowFor builds the deploy saga under test from its collaborators.
type deployWorkflowFor func(store *Store, inv *inventory.Store, nc *nats.Conn, secrets SecretSource) (jobs.Workflow, error)

// deployGoldenWire runs c's app through the push step of the deploy saga
// build makes, taken by name as the runner would, against an agent listening
// on both deploy subjects of node n. It returns what the agent received as the
// golden records it: the subject, a newline, and the sha256 of the command's
// exact bytes, with the bytes themselves on a mismatch. A digest, not the
// bytes, because the secret case's bytes carry a derived value: synthetic,
// from a fixed test seed, but shaped like a credential, so the secret scanner
// flags it in plain text and in hex alike.
func deployGoldenWire(t *testing.T, build deployWorkflowFor, c deployGoldenCase) (golden string, data []byte) {
	t.Helper()
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := newStore(t), newInventory(t)
	node := &proto.Node{ID: "n", Role: proto.RoleCompute, Hostname: "n.test", FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC()}
	if c.secretsAgent {
		node.AgentVersion = secretsFloor(t)
	}
	if err := inv.Insert(ctx, node); err != nil {
		t.Fatal(err)
	}
	app := c.app(t)
	app.ID, app.TargetNode = c.appID, "n"
	if err := store.Create(ctx, app); err != nil {
		t.Fatal(err)
	}

	type received struct {
		subject string
		data    []byte
	}
	got := make(chan received, 4)
	for _, subject := range []string{proto.AppDeploySubject("n"), proto.AppDeploySecretsSubject("n")} {
		sub, err := nc.Subscribe(subject, func(m *nats.Msg) {
			got <- received{m.Subject, append([]byte(nil), m.Data...)}
			ack, _ := json.Marshal(proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
			_ = m.Respond(ack)
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sub.Unsubscribe() })
	}

	src, _ := wiringSource(t)
	w := wf(t)(build(store, inv, nc, src))
	push := workflowStep(t, w, "push")
	if _, err := push(newStepCtxNATS(`{"appId":"`+c.appID+`"}`, nc)); err != nil {
		t.Fatalf("push: %v", err)
	}
	r := receiveWithin(t, got, "the agent never received a deploy command")
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	if extra := len(got); extra != 0 {
		t.Fatalf("the agent received %d more deploy commands than the one push", extra)
	}
	sum := sha256.Sum256(r.data)
	return r.subject + "\n" + hex.EncodeToString(sum[:]) + "\n", r.data
}

// workflowStep returns the step of w named name, failing if there is none.
func workflowStep(t *testing.T, w jobs.Workflow, name string) jobs.DoFn {
	t.Helper()
	for _, s := range w.Steps {
		if s.Name == name {
			return s.Do
		}
	}
	t.Fatalf("workflow %s has no %q step", w.Kind, name)
	return nil
}

// pushFamilySteps lists the steps of the four sagas that push a deploy
// command, one "<kind>: <steps>" line each.
func pushFamilySteps(t *testing.T) string {
	t.Helper()
	src := testSource(t)
	var b strings.Builder
	for _, w := range []jobs.Workflow{
		wf(t)(DeployWorkflow(nil, nil, nil, nil, src, AppIdentity{})),
		wf(t)(RevertWorkflow(nil, nil, nil, nil, src, AppIdentity{})),
		wf(t)(EditWorkflow(nil, nil, nil, nil, nil, src, testSecretDeps(), AppIdentity{})),
		wf(t)(UpgradeWorkflow(nil, nil, nil, nil, nil, src, testSecretDeps(), AppIdentity{})),
	} {
		names := make([]string, 0, len(w.Steps))
		for _, s := range w.Steps {
			names = append(names, s.Name)
		}
		b.WriteString(w.Kind + ": " + strings.Join(names, ",") + "\n")
	}
	return b.String()
}

// checkGolden compares got with the golden file name, or rewrites the file
// under -update. It reports whether they matched.
func checkGolden(t *testing.T, name, got string) bool {
	t.Helper()
	path := filepath.Join(deployGoldenDir, name)
	if *updateDeployGolden {
		if err := os.MkdirAll(deployGoldenDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return true
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (regenerate with -update only against code that predates the change under test): %v", err)
	}
	if got != string(want) {
		t.Errorf("%s changed:\n got: %q\nwant: %q", path, got, want)
		return false
	}
	return true
}

// TC-1080-01: the subject and the exact AppDeployCmd bytes of a deploy, for a
// plain tile, a tile that uses secrets and a custom app.
func TestDeployGolden_WhatTheAgentReceives(t *testing.T) {
	build := func(store *Store, inv *inventory.Store, nc *nats.Conn, secrets SecretSource) (jobs.Workflow, error) {
		return DeployWorkflow(store, inv, nc, nil, secrets, AppIdentity{})
	}
	for _, c := range deployGoldenCases() {
		t.Run(c.name, func(t *testing.T) {
			got, data := deployGoldenWire(t, build, c)
			if !checkGolden(t, c.name+".golden", got) {
				t.Logf("the agent received: %s", data)
			}
		})
	}
}

// TC-1080-02: the job steps of deploy, revert, edit and upgrade.
func TestDeployGolden_PushFamilySteps(t *testing.T) {
	checkGolden(t, "steps.golden", pushFamilySteps(t))
}
