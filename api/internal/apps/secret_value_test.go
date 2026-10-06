package apps

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/nats-io/nats.go"
)

// The credentials the app workflows hold — the resolved compose and the
// per-app leaf key — are secret.Values from where they are made to the bus
// command that carries them (ADR-0009, geekdojo/geekdojo-brain#825).

// secretComposeV1 and secretComposeV2 are custom composes that ask for a
// derived secret, with the volume every compose change's gate expects.
const (
	secretComposeV1 = "services:\n  web:\n    image: me/web:1\n    environment:\n      DB_PASSWORD: ${secret:db-password}\n    volumes: [data:/data]\nvolumes:\n  data: {}\n"
	secretComposeV2 = "services:\n  web:\n    image: me/web:2\n    environment:\n      DB_PASSWORD: ${secret:db-password}\n    volumes: [data:/data]\nvolumes:\n  data: {}\n"
)

// realRunner is a jobs.Runner over a fresh ledger, with w registered.
func realRunner(t *testing.T, nc *nats.Conn, w jobs.Workflow) (*jobs.Runner, *jobs.Store) {
	t.Helper()
	jst, err := jobs.OpenStore(context.Background(), filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatalf("jobs.OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = jst.Close() })
	r := jobs.NewRunner(jst, nc)
	r.Register(w)
	return r, jst
}

// assertLedgerLacks fails if needle is in the job's stored spec or in any of
// its step results or errors.
func assertLedgerLacks(t *testing.T, jst *jobs.Store, jobID, needle string) {
	t.Helper()
	ctx := context.Background()
	j, err := jst.GetJob(ctx, jobID)
	if err != nil || j == nil {
		t.Fatalf("GetJob(%s): %v", jobID, err)
	}
	if bytes.Contains(j.Spec, []byte(needle)) {
		t.Errorf("the stored job spec carries the credential: %s", j.Spec)
	}
	steps, err := jst.ListSteps(ctx, jobID)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) == 0 {
		t.Fatal("the job recorded no steps; there is nothing to check")
	}
	for _, st := range steps {
		if bytes.Contains(st.Result, []byte(needle)) || strings.Contains(st.Error, needle) {
			t.Errorf("step %s carries the credential: result %s error %q", st.Name, st.Result, st.Error)
		}
	}
}

// seedComposeApp puts an app running compose on an online compute node n.
func seedComposeApp(t *testing.T, id, compose string) (*Store, *inventory.Store) {
	t.Helper()
	store, inv := newStore(t), newInventory(t)
	now := time.Now().UTC()
	if err := inv.Insert(context.Background(), &proto.Node{
		ID: "n", Role: proto.RoleCompute, Hostname: "n.test", FirstSeen: now, LastSeen: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(context.Background(), &App{
		ID: id, Name: "mine", ComposeYAML: compose, TargetNode: "n",
		PublishedPort: 8080, DeployBudgetSeconds: 300,
		LastStatus: proto.AppStatusRunning, CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return store, inv
}

// sourceCall is one ResolveCompose call, with the step that was running.
type sourceCall struct {
	step, appID, compose string
}

// recordingSource records every call to the source it wraps, labelled with
// the step *step names when the call was made.
type recordingSource struct {
	inner SecretSource
	step  *atomic.Value
	mu    sync.Mutex
	calls []sourceCall
}

func (r *recordingSource) ResolveCompose(ctx context.Context, appID, compose string) (secret.Value, error) {
	step, _ := r.step.Load().(string)
	r.mu.Lock()
	r.calls = append(r.calls, sourceCall{step: step, appID: appID, compose: compose})
	r.mu.Unlock()
	return r.inner.ResolveCompose(ctx, appID, compose)
}

// labelSteps wraps every step of w so that *step holds the running step's name
// while its Do runs.
func labelSteps(w jobs.Workflow, step *atomic.Value) jobs.Workflow {
	steps := make([]jobs.WorkflowStep, len(w.Steps))
	copy(steps, w.Steps)
	for i := range steps {
		name, do := steps[i].Name, steps[i].Do
		steps[i].Do = func(sc *jobs.StepCtx) (json.RawMessage, error) {
			step.Store(name)
			defer step.Store("")
			return do(sc)
		}
	}
	w.Steps = steps
	return w
}

// TC-825-03: on the real Runner, each workflow of the deploy family sends the
// derived value in AppDeployCmd and nowhere else: the app row keeps the
// placeholder, and neither the stored spec nor any step result carries the
// value.
//
// TC-692-04: the secret source is called exactly once per job, during the step
// named push, with the app's ID and the compose the row holds at push.
//
// TC-692-05: the derivation runs through the real HKDF adapter, and the
// expected value comes from the seed itself, independently of it.
func TestDeployFamily_DerivedSecretReachesOnlyTheBus(t *testing.T) {
	const id = "01J9ZK3Q0M8X7Y6W5V4T3S2R1P"

	for _, tc := range []struct {
		kind string
		// setup seeds the app and returns the workflow, the spec, the
		// prepare hook (or nil) and the compose the row holds afterwards.
		setup func(t *testing.T, nc *nats.Conn, src SecretSource) (*Store, jobs.Workflow, any, func(string) error, string)
	}{
		{"app.deploy", func(t *testing.T, nc *nats.Conn, src SecretSource) (*Store, jobs.Workflow, any, func(string) error, string) {
			store, inv := seedComposeApp(t, id, secretComposeV1)
			return store, wf(t)(DeployWorkflow(store, inv, nc, nil, src)), DeploySpec{AppID: id}, nil, secretComposeV1
		}},
		{"app.upgrade", func(t *testing.T, nc *nats.Conn, src SecretSource) (*Store, jobs.Workflow, any, func(string) error, string) {
			store, inv := seedUpgradeApp(t, id)
			fakePullAgent(t, nc, proto.AppPullAck{OK: true}, nil)
			tile := strings.Replace(composeV2, "    volumes:", "    environment:\n      DB_PASSWORD: ${secret:db-password}\n    volumes:", 1)
			return store, wf(t)(UpgradeWorkflow(store, inv, nc, nil, lookupOf(upgradeTile(tile), 2), src)), ComposeChangeSpec{AppID: id}, nil, tile
		}},
		{"app.edit", func(t *testing.T, nc *nats.Conn, src SecretSource) (*Store, jobs.Workflow, any, func(string) error, string) {
			store, inv := seedComposeApp(t, id, customV1)
			fakePullAgent(t, nc, proto.AppPullAck{OK: true}, nil)
			stash := NewComposeStash()
			put := func(jobID string) error { return stash.Put(jobID, secretComposeV2) }
			return store, wf(t)(EditWorkflow(store, inv, nc, nil, stash, src)), ComposeChangeSpec{AppID: id}, put, secretComposeV2
		}},
		{"app.revert", func(t *testing.T, nc *nats.Conn, src SecretSource) (*Store, jobs.Workflow, any, func(string) error, string) {
			store, inv := seedComposeApp(t, id, secretComposeV1)
			if err := store.EditCompose(context.Background(), id, ComposeHash(secretComposeV1), customV2, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			fakePullAgent(t, nc, proto.AppPullAck{OK: true}, nil)
			return store, wf(t)(RevertWorkflow(store, inv, nc, nil, src)), RevertSpec{AppID: id, ComposeSHA256: ComposeHash(secretComposeV1)}, nil, secretComposeV1
		}},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			ctx := context.Background()
			nc := startNATS(t)
			deploys := fakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
			inner, derived := wiringSource(t)
			var step atomic.Value
			step.Store("")
			src := &recordingSource{inner: inner, step: &step}
			store, w, spec, prepare, rowCompose := tc.setup(t, nc, src)
			if w.Kind != tc.kind {
				t.Fatalf("workflow kind %q, want %q", w.Kind, tc.kind)
			}
			runner, jst := realRunner(t, nc, labelSteps(w, &step))
			if prepare == nil {
				prepare = func(string) error { return nil }
			}
			j, err := runner.SubmitPrepared(ctx, tc.kind, spec, "test", prepare)
			if err != nil {
				t.Fatalf("submit: %v", err)
			}
			runner.Wait()
			if got, _ := jst.GetJob(ctx, j.ID); got == nil || got.Status != jobs.StatusSucceeded {
				t.Fatalf("job ended %+v", got)
			}

			src.mu.Lock()
			calls := append([]sourceCall(nil), src.calls...)
			src.mu.Unlock()
			if len(calls) != 1 {
				t.Fatalf("the secret source was called %d time(s), want exactly 1: %+v", len(calls), calls)
			}
			if c := calls[0]; c.step != "push" || c.appID != id || c.compose != rowCompose {
				t.Fatalf("the secret source was called during step %q with (%q, %q), want step push with (%q, %q)", c.step, c.appID, c.compose, id, rowCompose)
			}

			want := derived(id, "db-password")
			cmd := receiveWithin(t, deploys, "the agent never received the deploy command")
			if strings.Contains(cmd.ComposeYAML, "${secret:") || !strings.Contains(cmd.ComposeYAML, "DB_PASSWORD: "+want) {
				t.Fatalf("the deploy command does not carry the derived value in place of the token:\n%s", cmd.ComposeYAML)
			}
			row, err := store.Get(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if row.ComposeYAML != rowCompose || strings.Contains(row.ComposeYAML, want) {
				t.Fatalf("the app row does not hold the placeholder compose:\n%s", row.ComposeYAML)
			}
			assertLedgerLacks(t, jst, j.ID, want)
		})
	}
}

// failingSource refuses every compose with err and the zero Value.
type failingSource struct{ err error }

func (f failingSource) ResolveCompose(context.Context, string, string) (secret.Value, error) {
	return secret.Value{}, f.err
}

// TC-825-04, TC-692-06: a source that refuses fails the push step, with an
// error that wraps the source's and names the app, before anything is
// announced or sent.
func TestPushStep_RefusedResolvePublishesNothing(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedAppWithSecret(t, "n", testAppID)
	before, err := store.Get(ctx, testAppID)
	if err != nil {
		t.Fatal(err)
	}
	var deploys, changes atomic.Int32
	for subject, n := range map[string]*atomic.Int32{
		proto.AppDeploySubject("n"): &deploys,
		proto.AllAppsFilter:         &changes,
	} {
		sub, err := nc.Subscribe(subject, func(*nats.Msg) { n.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sub.Unsubscribe() })
	}

	sentinel := errors.New("test source: refused")
	_, err = deployPush(store, inv, nc, failingSource{err: sentinel})(newStepCtxNATS(`{"appId":"`+testAppID+`"}`, nc))
	if !errors.Is(err, sentinel) {
		t.Fatalf("push step error = %v, want one wrapping the source's %v", err, sentinel)
	}
	if !strings.Contains(err.Error(), "apps: resolve compose for "+testAppID) {
		t.Fatalf("push step error %q does not name the app", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	if deploys.Load() != 0 || changes.Load() != 0 {
		t.Errorf("a refused resolve published %d deploy command(s) and %d change event(s), want none", deploys.Load(), changes.Load())
	}
	after, err := store.Get(ctx, testAppID)
	if err != nil {
		t.Fatal(err)
	}
	if after.LastStatus != before.LastStatus || after.LastStatus == proto.AppStatusDeploying {
		t.Errorf("status moved to %q (was %q); a refused resolve must announce nothing", after.LastStatus, before.LastStatus)
	}
}

// keyedRotator returns a fresh (renewed) leaf whose key is key, and records
// whether commit ran and whether the node had already answered when it did.
type keyedRotator struct {
	key       []byte
	renewed   bool
	err       error
	held      secret.Value
	answered  *atomic.Bool
	committed atomic.Bool
	early     atomic.Bool
}

func (k *keyedRotator) rotate(app *App) (Leaf, bool, func() error, error) {
	k.held = secret.New(k.key)
	commit := func() error {
		if k.answered != nil && !k.answered.Load() {
			k.early.Store(true)
		}
		k.committed.Store(true)
		return nil
	}
	return Leaf{Cmd: proto.AppLeafCmd{AppID: app.ID, Name: app.Name, CertPEM: []byte("CERT")}, Key: k.held}, k.renewed, commit, k.err
}

// leafNode answers the app's leaf subject with ok, records the command, and
// sets answered before it responds.
func leafNode(t *testing.T, nc *nats.Conn, ok bool) (<-chan proto.AppLeafCmd, *atomic.Bool) {
	t.Helper()
	got := make(chan proto.AppLeafCmd, 4)
	var answered atomic.Bool
	sub, err := nc.Subscribe(proto.AppLeafSubject("n"), func(m *nats.Msg) {
		var cmd proto.AppLeafCmd
		_ = json.Unmarshal(m.Data, &cmd)
		got <- cmd
		answered.Store(true)
		ack, _ := json.Marshal(proto.AppLeafAck{OK: ok, Detail: "test"})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	return got, &answered
}

// TC-825-05: the deploy family's leaf. The key reaches AppLeafCmd.KeyPEM on
// the bus, commit runs only after the node has answered, and the holder's key
// is destroyed by the time provisionAppLeaf returns.
func TestProvisionAppLeaf_KeyReachesTheBusThenIsDestroyed(t *testing.T) {
	nc := startNATS(t)
	_, _ = seedAppWithPort(t, "n", testAppID, "jellyfin", 8096, false)
	got, answered := leafNode(t, nc, true)
	key := []byte("SENTINEL-LEAF-KEY-BYTES")
	rot := &keyedRotator{key: key, renewed: true, answered: answered}
	app := &App{ID: testAppID, Name: "jellyfin", TargetNode: "n", PublishedPort: 8096}

	ok, detail := provisionAppLeaf(context.Background(), nc, rot.rotate, app)
	if !ok {
		t.Fatalf("provisionAppLeaf: %s", detail)
	}
	cmd := receiveWithin(t, got, "the node never received the leaf")
	if !bytes.Equal(cmd.KeyPEM, key) {
		t.Fatalf("AppLeafCmd.KeyPEM = %q, want the minted key", cmd.KeyPEM)
	}
	if !rot.committed.Load() || rot.early.Load() {
		t.Errorf("commit ran=%v before the node answered=%v; it must run, and only after the ack", rot.committed.Load(), rot.early.Load())
	}
	if rot.held.Len() != 0 {
		t.Errorf("the leaf key still holds %d bytes after provisionAppLeaf returned", rot.held.Len())
	}
}

// TC-825-06: the leaf key is destroyed on every outcome, and none of these
// outcomes commits: a rotator error, a delivery error, a refusing node, an
// offline node (RotateAppLeaf) and a leaf that is not renewed.
func TestLeafKey_DestroyedOnEveryOutcome(t *testing.T) {
	key := []byte("LEAF-KEY")
	for _, tc := range []struct {
		name     string
		renewed  bool
		rotErr   error
		node     string // "accept", "refuse", "none"
		offline  bool
		rotation bool // RotateAppLeaf rather than provisionAppLeaf
	}{
		{name: "rotator error", renewed: true, rotErr: os.ErrInvalid, node: "accept"},
		{name: "rotator error (rotation)", renewed: true, rotErr: os.ErrInvalid, node: "accept", rotation: true},
		{name: "deliver error", renewed: true, node: "none"},
		{name: "deliver error (rotation)", renewed: true, node: "none", rotation: true},
		{name: "node rejected", renewed: true, node: "refuse"},
		{name: "node rejected (rotation)", renewed: true, node: "refuse", rotation: true},
		{name: "node offline (rotation)", renewed: true, node: "accept", offline: true, rotation: true},
		{name: "not renewed", renewed: false, node: "accept"},
		{name: "not renewed (rotation)", renewed: false, node: "accept", rotation: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nc := startNATS(t)
			ctx := context.Background()
			inv := newInventory(t)
			seen := time.Now().UTC()
			if tc.offline {
				seen = seen.Add(-10 * time.Minute)
			}
			if err := inv.Insert(ctx, &proto.Node{ID: "n", Role: proto.RoleCompute, Hostname: "n.test", FirstSeen: seen, LastSeen: seen}); err != nil {
				t.Fatal(err)
			}
			switch tc.node {
			case "accept":
				leafNode(t, nc, true)
			case "refuse":
				leafNode(t, nc, false)
			}
			rot := &keyedRotator{key: key, renewed: tc.renewed, err: tc.rotErr}
			app := &App{ID: testAppID, Name: "jellyfin", TargetNode: "n", PublishedPort: 8096}
			if tc.rotation {
				RotateAppLeaf(ctx, inv, nc, rot.rotate, app)
			} else {
				provisionAppLeaf(ctx, nc, rot.rotate, app)
			}
			if tc.renewed && rot.committed.Load() {
				t.Error("commit ran on an outcome that must not commit")
			}
			if !tc.renewed && rot.committed.Load() {
				t.Error("an unrenewed leaf was committed")
			}
			if rot.held.Len() != 0 {
				t.Errorf("the leaf key still holds %d bytes after return", rot.held.Len())
			}
		})
	}
}

// TC-825-07: apps.reconcile and apps.leaf_rotate, on the real Runner with the
// rotator main wires (realRotator). The rotated key reaches AppLeafCmd.KeyPEM,
// is committed only after the node answers, the committed key file is exactly
// the bus key, and no step result carries it.
func TestLeafSweeps_RotatedKeyReachesTheBusAndTheDiskOnly(t *testing.T) {
	for _, tc := range []struct {
		kind string
		// setup seeds an app due for a leaf and returns the workflow.
		setup func(t *testing.T, nc *nats.Conn, rotate LeafRotator) jobs.Workflow
	}{
		{"apps.reconcile", func(t *testing.T, nc *nats.Conn, rotate LeafRotator) jobs.Workflow {
			store, inv := seedRoutableFailedApp(t, "n", "a")
			agentReports(t, nc, "n", "a", proto.AppStatusRunning)
			return ReconcileWorkflow(store, inv, nc, rotate)
		}},
		{"apps.leaf_rotate", func(t *testing.T, nc *nats.Conn, rotate LeafRotator) jobs.Workflow {
			store, inv := seedAppWithPort(t, "n", "a", "jellyfin", 8096, true)
			return RotateLeavesWorkflow(store, inv, nc, rotate)
		}},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			ctx := context.Background()
			nc := startNATS(t)
			ca, err := mesh.EnsureMeshCA(t.TempDir(), "home1")
			if err != nil {
				t.Fatal(err)
			}
			leafRoot := t.TempDir()
			keyPath := mesh.LeafPathsIn(filepath.Join(leafRoot, "a")).KeyPath

			var onDiskAtAck atomic.Bool
			got := make(chan proto.AppLeafCmd, 2)
			sub, err := nc.Subscribe(proto.AppLeafSubject("n"), func(m *nats.Msg) {
				var cmd proto.AppLeafCmd
				_ = json.Unmarshal(m.Data, &cmd)
				if _, statErr := os.Stat(keyPath); statErr == nil {
					onDiskAtAck.Store(true)
				}
				got <- cmd
				ack, _ := json.Marshal(proto.AppLeafAck{OK: true})
				_ = m.Respond(ack)
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = sub.Unsubscribe() })

			w := tc.setup(t, nc, realRotator(t, ca, leafRoot, "home1"))
			runner, jst := realRunner(t, nc, w)
			j, err := runner.Submit(ctx, tc.kind, nil, "test")
			if err != nil {
				t.Fatalf("submit: %v", err)
			}
			runner.Wait()

			cmd := receiveWithin(t, got, "the node never received the rotated leaf")
			if len(cmd.KeyPEM) == 0 {
				t.Fatal("the leaf command carried no key")
			}
			if onDiskAtAck.Load() {
				t.Error("the key was committed before the node answered")
			}
			onDisk, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatalf("the rotated key was not committed: %v", err)
			}
			if !bytes.Equal(onDisk, cmd.KeyPEM) {
				t.Error("the committed key file is not the key the node was sent")
			}
			assertLedgerLacks(t, jst, j.ID, string(cmd.KeyPEM))
			// The PEM body alone, in case a result ever re-encodes the armour.
			body := strings.Split(strings.TrimSpace(string(cmd.KeyPEM)), "\n")[1]
			assertLedgerLacks(t, jst, j.ID, body)
		})
	}
}
