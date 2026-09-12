package apps

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// The compose as one resource (geekdojo/geekdojo-brain#410), below the HTTP
// layer: a custom app's owner-supplied compose redeployed in place without the
// compose ever reaching a spec, a step result or a log line, and a re-apply
// that names its target by hash and so cannot bounce.

// secretMarker is inlined in the composes a custom app is edited to, standing
// for whatever secret a real one carries. It must never appear anywhere a job
// is persisted or rendered.
const secretMarker = "hunter2-DO-NOT-LEAK-7f3a"

const customV1 = "services:\n  web:\n    image: me/web:1\n    volumes: [data:/data]\nvolumes:\n  data: {}\n"

var customV2 = "services:\n  web:\n    image: me/web:2\n    environment:\n      DB_PASSWORD: " + secretMarker + "\n    volumes: [data:/data]\nvolumes:\n  data: {}\n"

// seedCustomApp puts a custom-compose app (no source tile) on an online
// compute node, running customV1 with a port, scheme and budget an edit must
// leave alone.
func seedCustomApp(t *testing.T, id string) (*Store, *inventory.Store) {
	t.Helper()
	store, inv := newStore(t), newInventory(t)
	if err := inv.Insert(context.Background(), &proto.Node{
		ID: "n", Role: proto.RoleCompute, Hostname: "n.test", FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-time.Hour)
	if err := store.Create(context.Background(), &App{
		ID: id, Name: "mine", ComposeYAML: customV1, TargetNode: "n",
		PublishedPort: 8080, WebTLS: true, DeployBudgetSeconds: 300, ExposeLAN: true,
		LastStatus: proto.AppStatusRunning, CreatedAt: now, UpdatedAt: now,
		BackupAck: &BackupAck{At: now.Truncate(time.Millisecond), By: "alice"},
	}); err != nil {
		t.Fatal(err)
	}
	return store, inv
}

func runRevert(t *testing.T, store *Store, inv *inventory.Store, nc *nats.Conn, mint LeafMinter, appID, targetCompose string) (string, error) {
	t.Helper()
	r := runWorkflow(t, RevertWorkflow(store, inv, nc, mint), nc, revertSpec(appID, targetCompose), "job-test")
	return r.failedAt, r.err
}

func revertSpec(appID, targetCompose string) string {
	b, _ := json.Marshal(RevertSpec{AppID: appID, ComposeSHA256: ComposeHash(targetCompose)})
	return string(b)
}

// assertNoCompose fails if the secret-bearing compose, or the marker in it,
// appears in any step result or log line of run.
func assertNoCompose(t *testing.T, run workflowRun) {
	t.Helper()
	for step, raw := range run.results {
		if strings.Contains(string(raw), secretMarker) || strings.Contains(string(raw), "me/web:2") {
			t.Errorf("step %s result carries the submitted compose: %s", step, raw)
		}
	}
	for _, line := range run.logs {
		if strings.Contains(line, secretMarker) || strings.Contains(line, "me/web:2") {
			t.Errorf("log line carries the submitted compose: %s", line)
		}
	}
	if run.err != nil && strings.Contains(run.err.Error(), secretMarker) {
		t.Errorf("job error carries the submitted compose: %v", run.err)
	}
}

func TestComposeStash(t *testing.T) {
	s := NewComposeStash()
	if err := s.Put("", "x"); err == nil {
		t.Error("an empty job id must be refused")
	}
	if err := s.Put("j", "one"); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("j", "two"); err == nil {
		t.Error("a second compose for the same job must be refused")
	}
	if got, ok := s.Get("j"); !ok || got != "one" {
		t.Errorf("Get = %q %v, want the first compose kept", got, ok)
	}
	s.Discard("j")
	s.Discard("j") // idempotent, as an OnTerminal hook must be
	if _, ok := s.Get("j"); ok || s.Len() != 0 {
		t.Errorf("Discard left the compose held (len %d)", s.Len())
	}
}

func TestEditWorkflowShape(t *testing.T) {
	w := EditWorkflow(nil, nil, nil, nil, nil)
	var names []string
	for _, s := range w.Steps {
		names = append(names, s.Name)
	}
	if w.Kind != "app.edit" || strings.Join(names, ",") != "load,pull,persist,push,leaf" {
		t.Errorf("workflow = %s %v, want app.edit load,pull,persist,push,leaf", w.Kind, names)
	}
	if w.OnTerminal == nil {
		t.Fatal("app.edit must discard the held compose when the job ends")
	}
	w.OnTerminal(context.Background(), "j", true, "") // a nil stash must not panic
}

// The done-means of #410 on the wire: the agent pulls, then is sent, the
// submitted compose for the SAME app id — so the Compose project and every
// named volume are the ones the app already has — and the row keeps its
// identity, port, scheme and budget, with the replaced compose kept. None of
// it reaches a step result or a log line.
func TestEditSaga_DeploysTheSubmittedComposeToTheSameULIDWithoutRecordingIt(t *testing.T) {
	ctx := context.Background()
	const id = "01J9ZK3Q0M8X7Y6W5V4T3S2R1P"
	nc := startNATS(t)
	store, inv := seedCustomApp(t, id)
	before, _ := store.Get(ctx, id)
	pulls := fakePullAgent(t, nc, proto.AppPullAck{OK: true}, nil)
	deploys := fakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
	stash := NewComposeStash()
	const jobID = "01JOBEDIT0000000000000000A"
	if err := stash.Put(jobID, customV2); err != nil {
		t.Fatal(err)
	}

	run := runWorkflow(t, EditWorkflow(store, inv, nc, nil, stash), nc, `{"appId":"`+id+`"}`, jobID)
	if run.err != nil {
		t.Fatalf("step %s: %v", run.failedAt, run.err)
	}
	assertNoCompose(t, run)

	select {
	case cmd := <-pulls:
		if cmd.AppID != id || cmd.ComposeYAML != customV2 || cmd.WorkBudgetSeconds != 300 {
			t.Errorf("pull = %s %q budget %d, want the submitted compose for the same app under its budget", cmd.AppID, cmd.ComposeYAML, cmd.WorkBudgetSeconds)
		}
	default:
		t.Fatal("the edit deployed without pulling first")
	}
	select {
	case cmd := <-deploys:
		if cmd.AppID != id || cmd.ComposeYAML != customV2 {
			t.Errorf("push = %s %q, want the submitted compose for the same app", cmd.AppID, cmd.ComposeYAML)
		}
		if proto.AppProjectName(cmd.AppID) != proto.AppProjectName(before.ID) ||
			proto.AppVolumeName(cmd.AppID, "data") != proto.AppVolumeName(before.ID, "data") {
			t.Error("project/volume naming changed across the edit")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent never received the edit's deploy")
	}

	after, _ := store.Get(ctx, id)
	if after.ComposeYAML != customV2 || after.ComposeSHA256 != ComposeHash(customV2) || after.PreviousComposeYAML != customV1 {
		t.Errorf("row compose = %q previous = %q", after.ComposeYAML, after.PreviousComposeYAML)
	}
	if after.ID != id || after.Name != "mine" || after.TargetNode != "n" || !after.ExposeLAN || after.SourceTile != "" ||
		after.BackupAck == nil || after.BackupAck.By != "alice" {
		t.Errorf("identity or an owner choice changed: %+v", after)
	}
	if after.PublishedPort != 8080 || !after.WebTLS || after.DeployBudgetSeconds != 300 || after.ComposeCatalogVersion != 0 {
		t.Errorf("port=%d tls=%v budget=%d version=%d, want the custom app's own kept", after.PublishedPort, after.WebTLS, after.DeployBudgetSeconds, after.ComposeCatalogVersion)
	}
	if after.PreviousPublishedPort != 8080 || !after.PreviousWebTLS || after.PreviousDeployBudgetSeconds != 300 {
		t.Errorf("previous record = %+v, want the same port, scheme and budget", after)
	}
	if after.LastStatus != proto.AppStatusRunning {
		t.Errorf("status = %s, want running", after.LastStatus)
	}
}

// A failed pull is #411's first branch for an edit too: the row and the
// running app are as they were, the status is put back with the reason, and
// the submitted compose is not in the reason.
func TestEditSaga_AFailedPullChangesNothing(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedCustomApp(t, "a")
	before, _ := store.Get(ctx, "a")
	deploys := fakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
	fakePullAgent(t, nc, proto.AppPullAck{OK: false, Detail: "docker compose pull: manifest unknown"}, nil)
	stash := NewComposeStash()
	_ = stash.Put("j", customV2)

	run := runWorkflow(t, EditWorkflow(store, inv, nc, nil, stash), nc, `{"appId":"a"}`, "j")
	if run.failedAt != "pull" || !strings.Contains(run.err.Error(), "manifest unknown") {
		t.Fatalf("want the pull to fail with the agent's reason, got step=%q err=%v", run.failedAt, run.err)
	}
	assertNoCompose(t, run)
	select {
	case cmd := <-deploys:
		t.Fatalf("a failed pull went on to push: %+v", cmd)
	case <-time.After(100 * time.Millisecond):
	}
	after, _ := store.Get(ctx, "a")
	if field := sameRecord(before, after); field != "" {
		t.Errorf("a failed pull changed the row's %s", field)
	}
	if after.LastStatus != proto.AppStatusRunning || !strings.Contains(after.LastDetail, "compose edit not applied") {
		t.Errorf("status = %s %q", after.LastStatus, after.LastDetail)
	}
	if strings.Contains(after.LastDetail, secretMarker) {
		t.Error("the recorded reason carries the submitted compose")
	}
}

// The saga refuses on its own, not only behind the handler: a job submitted
// some other way (POST /api/jobs names any kind) finds no compose held and
// changes nothing, and a catalog app is refused before anything is asked.
func TestEditSaga_Refusals(t *testing.T) {
	t.Run("no compose held", func(t *testing.T) {
		ctx := context.Background()
		nc := startNATS(t)
		store, inv := seedCustomApp(t, "a")
		before, _ := store.Get(ctx, "a")
		pulls := fakePullAgent(t, nc, proto.AppPullAck{OK: true}, nil)
		run := runWorkflow(t, EditWorkflow(store, inv, nc, nil, NewComposeStash()), nc, `{"appId":"a"}`, "j")
		if run.failedAt != "pull" || !errors.Is(run.err, errEditComposeNotHeld) {
			t.Fatalf("got step=%q err=%v", run.failedAt, run.err)
		}
		select {
		case cmd := <-pulls:
			t.Fatalf("the node was asked to pull with nothing held: %+v", cmd)
		case <-time.After(100 * time.Millisecond):
		}
		after, _ := store.Get(ctx, "a")
		if field := sameRecord(before, after); field != "" || after.LastStatus != proto.AppStatusRunning {
			t.Errorf("row changed (%s) or status %s", field, after.LastStatus)
		}
	})
	t.Run("catalog app", func(t *testing.T) {
		nc := startNATS(t)
		store, inv := seedUpgradeApp(t, "a")
		stash := NewComposeStash()
		_ = stash.Put("j", customV2)
		run := runWorkflow(t, EditWorkflow(store, inv, nc, nil, stash), nc, `{"appId":"a"}`, "j")
		if run.failedAt != "load" || !errors.Is(run.err, ErrEditCatalogApp) {
			t.Fatalf("got step=%q err=%v", run.failedAt, run.err)
		}
	})
	t.Run("spec carrying a compose", func(t *testing.T) {
		nc := startNATS(t)
		store, inv := seedCustomApp(t, "a")
		run := runWorkflow(t, EditWorkflow(store, inv, nc, nil, NewComposeStash()), nc, `{"appId":"a","composeYaml":"x"}`, "j")
		if run.failedAt != "load" || run.err == nil {
			t.Fatalf("a spec with a compose in it must be refused, got step=%q err=%v", run.failedAt, run.err)
		}
	})
}

func TestStore_EditCompose(t *testing.T) {
	ctx := context.Background()
	store, _ := seedCustomApp(t, "a")
	if err := store.Create(ctx, installedApp("cat")); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()

	if err := store.EditCompose(ctx, "a", ComposeHash("stale"), customV2, now); !errors.Is(err, ErrComposeChanged) {
		t.Errorf("stale hash: want ErrComposeChanged, got %v", err)
	}
	if err := store.EditCompose(ctx, "cat", ComposeHash(composeV1), customV2, now); !errors.Is(err, ErrEditCatalogApp) {
		t.Errorf("catalog app: want ErrEditCatalogApp, got %v", err)
	}
	if err := store.EditCompose(ctx, "ghost", ComposeHash(customV1), customV2, now); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("unknown app: want sql.ErrNoRows, got %v", err)
	}
	if got, _ := store.Get(ctx, "cat"); got.ComposeYAML != composeV1 || got.PreviousComposeYAML != "" {
		t.Error("a refused edit wrote a catalog app's row")
	}
	if err := store.EditCompose(ctx, "a", ComposeHash(customV1), customV2, now); err != nil {
		t.Fatalf("EditCompose: %v", err)
	}
	got, _ := store.Get(ctx, "a")
	if got.ComposeYAML != customV2 || got.PreviousComposeYAML != customV1 || got.ComposeSHA256 != ComposeHash(customV2) {
		t.Errorf("row = %+v", got)
	}
}

func TestResolveReapply(t *testing.T) {
	a := installedApp("a")
	a.ComposeSHA256 = ComposeHash(composeV1)
	if current, err := ResolveReapply(a, ComposeHash(composeV1)); !current || err != nil {
		t.Errorf("installed hash: current=%v err=%v, want the no-op", current, err)
	}
	if _, err := ResolveReapply(a, ComposeHash(composeV2)); !errors.Is(err, ErrUnknownComposeHash) {
		t.Errorf("no previous compose: want ErrUnknownComposeHash, got %v", err)
	}
	a.PreviousComposeYAML = composeV2
	if current, err := ResolveReapply(a, ComposeHash(composeV2)); current || err != nil {
		t.Errorf("previous hash: current=%v err=%v, want something to do", current, err)
	}
	if _, err := ResolveReapply(a, ComposeHash(composeV3)); !errors.Is(err, ErrUnknownComposeHash) {
		t.Errorf("a hash that is neither: want ErrUnknownComposeHash, got %v", err)
	}
}

func TestParseRevertSpec_IsStrict(t *testing.T) {
	good := ComposeHash(composeV1)
	for _, c := range []struct {
		spec string
		ok   bool
	}{
		{`{"appId":"a","sha256":"` + good + `"}`, true},
		{`{"appId":"a"}`, false},
		{`{"appId":"a","sha256":"` + strings.ToUpper(good) + `"}`, false},
		{`{"appId":"a","sha256":"abc"}`, false},
		{`{"sha256":"` + good + `"}`, false},
		{`{"appId":"a","sha256":"` + good + `","deleteVolumes":true}`, false},
	} {
		if _, err := parseRevertSpec(json.RawMessage(c.spec)); (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", c.spec, err, c.ok)
		}
	}
}

// Re-apply by hash, then the same request again. The first goes to the named
// compose; the second finds it installed and ends at load, successfully, with
// nothing pulled, written or pushed. The route this replaced swapped on every
// request, so the second one went back.
func TestRevertSaga_ARepeatedReapplyIsANoOpNotABounce(t *testing.T) {
	ctx := context.Background()
	store, inv, v2, row := upgradedToV2(t)
	nc := startNATS(t)
	pulls := fakePullAgent(t, nc, proto.AppPullAck{OK: true}, nil)
	deploys := fakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})

	if step, err := runRevert(t, store, inv, nc, nil, "a", composeV1); err != nil {
		t.Fatalf("first re-apply failed at %s: %v", step, err)
	}
	<-pulls
	<-deploys
	first := row()
	if first.ComposeYAML != composeV1 || first.PreviousComposeYAML != composeV2 {
		t.Fatalf("after the re-apply: compose=%q previous=%q", first.ComposeYAML, first.PreviousComposeYAML)
	}

	run := runWorkflow(t, RevertWorkflow(store, inv, nc, nil), nc, revertSpec("a", composeV1), "job-2")
	if run.failedAt != "load" || !errors.Is(run.err, jobs.ErrStopWorkflow) {
		t.Fatalf("the repeat must end at load as a successful no-op, got step=%q err=%v", run.failedAt, run.err)
	}
	select {
	case cmd := <-pulls:
		t.Fatalf("the repeat asked the node to pull: %+v", cmd)
	case cmd := <-deploys:
		t.Fatalf("the repeat pushed: %+v", cmd)
	case <-time.After(100 * time.Millisecond):
	}
	if field := sameRecord(first, row()); field != "" {
		t.Errorf("the repeat changed the row's %s", field)
	}

	// Going forward again is its own request, naming the other hash.
	if step, err := runRevert(t, store, inv, nc, nil, "a", composeV2); err != nil {
		t.Fatalf("forward re-apply failed at %s: %v", step, err)
	}
	if got, _ := store.Get(ctx, "a"); sameRecord(v2, got) != "" {
		t.Errorf("naming the v2 hash did not return the record to v2")
	}
}

// A re-apply whose target is installed by another job during its pull does not
// fail and does not write: it deploys what the row holds.
func TestRevertSaga_TargetInstalledDuringThePullDeploysTheRow(t *testing.T) {
	store, inv, v2, row := upgradedToV2(t)
	nc := startNATS(t)
	deploys := fakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
	fakePullAgent(t, nc, proto.AppPullAck{OK: true}, func() {
		_ = store.RevertCompose(context.Background(), "a", v2.ComposeSHA256, v2.PreviousComposeYAML, time.Now().UTC())
	})
	if step, err := runRevert(t, store, inv, nc, nil, "a", composeV1); err != nil {
		t.Fatalf("failed at %s: %v", step, err)
	}
	if cmd := <-deploys; cmd.ComposeYAML != composeV1 {
		t.Errorf("pushed %q, want v1", cmd.ComposeYAML)
	}
	if got := row(); got.ComposeYAML != composeV1 || got.PreviousComposeYAML != composeV2 {
		t.Errorf("row compose=%q previous=%q, want one re-apply's worth of change", got.ComposeYAML, got.PreviousComposeYAML)
	}
}

// A custom app goes back by hash like a catalog app: after an edit, naming the
// original compose's hash re-applies it — its text came from the row, not the
// request — and the edited one is retained.
func TestRevertSaga_ACustomAppReappliesItsPreviousCompose(t *testing.T) {
	ctx := context.Background()
	store, inv := seedCustomApp(t, "a")
	nc := startNATS(t)
	fakePullAgent(t, nc, proto.AppPullAck{OK: true}, nil)
	deploys := fakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
	if err := store.EditCompose(ctx, "a", ComposeHash(customV1), customV2, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if step, err := runRevert(t, store, inv, nc, nil, "a", customV1); err != nil {
		t.Fatalf("failed at %s: %v", step, err)
	}
	if cmd := <-deploys; cmd.AppID != "a" || cmd.ComposeYAML != customV1 {
		t.Errorf("pushed %s %q, want v1 to the same app", cmd.AppID, cmd.ComposeYAML)
	}
	got, _ := store.Get(ctx, "a")
	if got.ComposeYAML != customV1 || got.PreviousComposeYAML != customV2 || got.PublishedPort != 8080 || got.SourceTile != "" {
		t.Errorf("row = %+v", got)
	}
}
