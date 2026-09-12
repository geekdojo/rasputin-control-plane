package apps

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
	"github.com/nats-io/nats.go"
)

// Pull, then up (geekdojo/geekdojo-brain#411): a failed pull changes nothing,
// a failure after the pull is not reverted, the owner's explicit re-apply of
// the previous compose, and what the reconcile sweep makes of the survivor an
// `up` that failed early leaves behind.

const composeV3 = "services:\n  web:\n    image: e/kuma:3@sha256:" + "3333333333333333333333333333333333333333333333333333333333333333" + "\n    volumes: [data:/data]\nvolumes:\n  data: {}\n"

// tileV3 is a third catalog version of the tile: a new compose again, and a
// port and budget different from both earlier ones.
func tileV3() tileschema.Tile {
	t := upgradeTile(composeV3)
	t.DeployBudgetSeconds = 900
	t.Ports = []tileschema.Port{{Name: "web", Container: 3001, Published: 4000, Web: true}}
	return t
}

// sameRecord reports the first compose-record field on which a and b differ,
// or "" — everything an upgrade or a re-apply writes, and nothing about status.
func sameRecord(a, b *App) string {
	switch {
	case a.ComposeYAML != b.ComposeYAML:
		return "compose_yaml"
	case a.ComposeSHA256 != b.ComposeSHA256:
		return "compose_sha256"
	case a.ComposeCatalogVersion != b.ComposeCatalogVersion:
		return "compose_catalog_version"
	case a.PublishedPort != b.PublishedPort:
		return "published_port"
	case a.WebTLS != b.WebTLS:
		return "web_tls"
	case a.DeployBudgetSeconds != b.DeployBudgetSeconds:
		return "deploy_budget_s"
	case a.PreviousComposeYAML != b.PreviousComposeYAML:
		return "previous_compose_yaml"
	case a.PreviousComposeCatalogVersion != b.PreviousComposeCatalogVersion:
		return "previous_compose_catalog_version"
	case a.PreviousPublishedPort != b.PreviousPublishedPort:
		return "previous_published_port"
	case a.PreviousWebTLS != b.PreviousWebTLS:
		return "previous_web_tls"
	case a.PreviousDeployBudgetSeconds != b.PreviousDeployBudgetSeconds:
		return "previous_deploy_budget_s"
	case a.ID != b.ID || a.Name != b.Name || a.TargetNode != b.TargetNode || a.ExposeLAN != b.ExposeLAN:
		return "identity"
	}
	return ""
}

// upgradedToV2 is an app already upgraded once, v1 → v2, and running — so it
// has a previous compose of its own, which a failed later change must not lose.
func upgradedToV2(t *testing.T) (*Store, *inventory.Store, *App, func() *App) {
	t.Helper()
	ctx := context.Background()
	store, inv := seedUpgradeApp(t, "a")
	if err := store.UpgradeCompose(ctx, "a", ComposeHash(composeV1), UpgradeTarget{Tile: upgradeTile(composeV2), CatalogVersion: 2}.ComposeUpgrade(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordStatus(ctx, "a", proto.AppStatusRunning, "", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	before, _ := store.Get(ctx, "a")
	return store, inv, before, func() *App {
		got, err := store.Get(ctx, "a")
		if err != nil || got == nil {
			t.Fatalf("Get: %v %v", got, err)
		}
		return got
	}
}

// The done-means of #411: a bad digest leaves the running app and its row
// exactly as they were. The pull fails, nothing is pushed, the record —
// previous compose included — is untouched, the status is back to running with
// the registry's reason on it, and the upgrade is still on offer.
func TestUpgradeSaga_AFailedPullChangesNothingAndPutsTheStatusBack(t *testing.T) {
	store, inv, before, row := upgradedToV2(t)
	nc := startNATS(t)
	deploys := fakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
	var sawDeploying atomic.Bool
	pulls := fakePullAgent(t, nc, proto.AppPullAck{OK: false, Detail: "docker compose pull: exit status 1 — manifest unknown"}, func() {
		if got, _ := store.Get(context.Background(), "a"); got.LastStatus == proto.AppStatusDeploying {
			sawDeploying.Store(true)
		}
	})
	lookup := lookupOf(tileV3(), 3)

	step, err := runUpgrade(t, store, inv, nc, lookup, "a")
	if step != "pull" || err == nil || !strings.Contains(err.Error(), "manifest unknown") {
		t.Fatalf("want the pull step to fail with the agent's reason, got step=%q err=%v", step, err)
	}

	select {
	case cmd := <-pulls:
		if cmd.AppID != "a" || cmd.ComposeYAML != composeV3 || cmd.WorkBudgetSeconds != 900 {
			t.Errorf("pull cmd = %+v, want the v3 tile's compose under its budget", cmd)
		}
	default:
		t.Fatal("the node was never asked to pull")
	}
	select {
	case cmd := <-deploys:
		t.Fatalf("a failed pull went on to push: %+v", cmd)
	case <-time.After(100 * time.Millisecond):
	}
	if !sawDeploying.Load() {
		t.Error("the app was not shown deploying while the pull ran")
	}

	after := row()
	if field := sameRecord(before, after); field != "" {
		t.Errorf("a failed pull changed the row's %s:\nbefore %+v\nafter  %+v", field, before, after)
	}
	if after.LastStatus != proto.AppStatusRunning {
		t.Errorf("status = %s, want running — the old app never stopped", after.LastStatus)
	}
	if !strings.Contains(after.LastDetail, "manifest unknown") || !strings.Contains(after.LastDetail, "not applied") {
		t.Errorf("detail = %q, want the pull error recorded as why the upgrade did not apply", after.LastDetail)
	}
	if _, err := ResolveUpgrade(after, lookup); err != nil {
		t.Errorf("upgradeAvailable must still be true after a failed pull: %v", err)
	}
}

// A node that does not answer docker.pull at all — offline, or an agent that
// predates the verb — is the same branch: nothing ran, so nothing changed, and
// the reason names which of those it is.
func TestUpgradeSaga_APullNobodyAnswersChangesNothing(t *testing.T) {
	store, inv, before, row := upgradedToV2(t)
	nc := startNATS(t)
	fakeVolumeCheckAgent(t, nc)
	deploys := fakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})

	step, err := runUpgrade(t, store, inv, nc, lookupOf(tileV3(), 3), "a")
	if step != "pull" || err == nil || !strings.Contains(err.Error(), "docker.pull") {
		t.Fatalf("want the pull step to fail naming docker.pull, got step=%q err=%v", step, err)
	}
	select {
	case cmd := <-deploys:
		t.Fatalf("an unanswered pull went on to push: %+v", cmd)
	case <-time.After(100 * time.Millisecond):
	}
	after := row()
	if field := sameRecord(before, after); field != "" {
		t.Errorf("an unanswered pull changed the row's %s", field)
	}
	if after.LastStatus != proto.AppStatusRunning || !strings.Contains(after.LastDetail, "docker.pull") {
		t.Errorf("status = %s %q, want running with the no-responder reading", after.LastStatus, after.LastDetail)
	}
}

// The tile is resolved at the pull and again at persist. If the catalog moves
// between the two, persist would install a compose nobody pulled; it refuses,
// and the refusal changes nothing either.
func TestUpgradeSaga_TheCatalogMovingDuringThePullIsRefused(t *testing.T) {
	store, inv, before, row := upgradedToV2(t)
	nc := startNATS(t)
	deploys := fakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})

	var moved atomic.Bool
	lookup := func(id string) (tileschema.Tile, int, bool) {
		if moved.Load() {
			tl := tileV3()
			tl.ComposeYAML += "# v4\n"
			return tl, 4, true
		}
		return tileV3(), 3, true
	}
	fakePullAgent(t, nc, proto.AppPullAck{OK: true}, func() { moved.Store(true) })

	step, err := runUpgrade(t, store, inv, nc, lookup, "a")
	if step != "persist" || !errors.Is(err, errCatalogMovedDuringPull) {
		t.Fatalf("want persist to refuse a compose that was not pulled, got step=%q err=%v", step, err)
	}
	select {
	case cmd := <-deploys:
		t.Fatalf("a refused persist pushed: %+v", cmd)
	case <-time.After(100 * time.Millisecond):
	}
	after := row()
	if field := sameRecord(before, after); field != "" {
		t.Errorf("a refused persist changed the row's %s", field)
	}
	if after.LastStatus != proto.AppStatusRunning || !strings.Contains(after.LastDetail, "catalog changed") {
		t.Errorf("status = %s %q, want running, with why", after.LastStatus, after.LastDetail)
	}
}

// Putting the status back never overwrites a status recorded after the pull
// marked the app deploying: that one is newer news.
func TestUpgradeSaga_AFailedPullLeavesANewerStatusAlone(t *testing.T) {
	store, inv, _, row := upgradedToV2(t)
	nc := startNATS(t)
	fakePullAgent(t, nc, proto.AppPullAck{OK: false, Detail: "manifest unknown"}, func() {
		_ = store.RecordStatus(context.Background(), "a", proto.AppStatusStopped, "stopped by the owner", time.Now().UTC().Add(time.Millisecond))
	})

	if step, _ := runUpgrade(t, store, inv, nc, lookupOf(tileV3(), 3), "a"); step != "pull" {
		t.Fatalf("want the pull to fail, failed at %q", step)
	}
	if got := row(); got.LastStatus != proto.AppStatusStopped || got.LastDetail != "stopped by the owner" {
		t.Errorf("status = %s %q, want the stop recorded during the pull left in place", got.LastStatus, got.LastDetail)
	}
}

func TestStore_RestoreStatusOnlyOverTheStepsOwnMark(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.Create(ctx, installedApp("a")); err != nil {
		t.Fatal(err)
	}
	deployedAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	_ = s.RecordStatus(ctx, "a", proto.AppStatusRunning, "", deployedAt)
	mark := time.Now().UTC().Truncate(time.Millisecond)
	_ = s.RecordStatus(ctx, "a", proto.AppStatusDeploying, "", mark)

	if ok, err := s.RestoreStatus(ctx, "a", mark.Add(-time.Second), proto.AppStatusRunning, "x", time.Now().UTC()); ok || err != nil {
		t.Fatalf("a mark other than the step's own must not restore: ok=%v err=%v", ok, err)
	}
	if ok, err := s.RestoreStatus(ctx, "a", mark, proto.AppStatusRunning, "upgrade not applied", time.Now().UTC()); !ok || err != nil {
		t.Fatalf("restore over the step's own mark: ok=%v err=%v", ok, err)
	}
	got, _ := s.Get(ctx, "a")
	if got.LastStatus != proto.AppStatusRunning || got.LastDetail != "upgrade not applied" {
		t.Errorf("status = %s %q", got.LastStatus, got.LastDetail)
	}
	if got.LastDeployed == nil || !got.LastDeployed.Equal(deployedAt) {
		t.Errorf("last_deployed moved to %v; nothing was deployed", got.LastDeployed)
	}
	if ok, _ := s.RestoreStatus(ctx, "a", mark, proto.AppStatusFailed, "again", time.Now().UTC()); ok {
		t.Error("a second restore over a status that is no longer deploying must not land")
	}
}

// The previous record is installed whole, in one write, and the record left is
// retained as the previous one, so the owner can name it to go forward again.
func TestStore_RevertComposeInstallsThePreviousRecordAndKeepsTheOneItLeaves(t *testing.T) {
	ctx := context.Background()
	s, _, v2, _ := upgradedToV2(t)

	if err := s.RevertCompose(ctx, "a", v2.ComposeSHA256, v2.PreviousComposeYAML, time.Now().UTC()); err != nil {
		t.Fatalf("RevertCompose: %v", err)
	}
	got, _ := s.Get(ctx, "a")
	if got.ComposeYAML != composeV1 || got.ComposeSHA256 != ComposeHash(composeV1) || got.ComposeCatalogVersion != 1 ||
		got.PublishedPort != 3001 || got.WebTLS || got.DeployBudgetSeconds != 0 {
		t.Errorf("installed record after re-apply = %+v, want v1's", got)
	}
	if got.PreviousComposeYAML != composeV2 || got.PreviousComposeCatalogVersion != 2 ||
		got.PreviousPublishedPort != 3443 || !got.PreviousWebTLS || got.PreviousDeployBudgetSeconds != 600 {
		t.Errorf("previous record after re-apply = %+v, want v2's", got)
	}
	if got.SourceTile != "uptime-kuma" || got.BackupAck == nil || got.BackupAck.By != "alice" || !got.ExposeLAN {
		t.Errorf("a re-apply changed identity or an owner choice: %+v", got)
	}

	if err := s.RevertCompose(ctx, "a", got.ComposeSHA256, got.PreviousComposeYAML, time.Now().UTC()); err != nil {
		t.Fatalf("re-apply again: %v", err)
	}
	back, _ := s.Get(ctx, "a")
	if field := sameRecord(v2, back); field != "" {
		t.Errorf("two re-applies did not return the record to where it started (%s)", field)
	}
}

func TestStore_RevertComposeRefusals(t *testing.T) {
	ctx := context.Background()
	s, _, v2, _ := upgradedToV2(t)
	if err := s.Create(ctx, &App{ID: "never", Name: "never", ComposeYAML: composeV1, TargetNode: "n", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()

	if err := s.RevertCompose(ctx, "a", ComposeHash("stale"), v2.PreviousComposeYAML, now); !errors.Is(err, ErrComposeChanged) {
		t.Errorf("stale installed hash: want ErrComposeChanged, got %v", err)
	}
	if err := s.RevertCompose(ctx, "a", v2.ComposeSHA256, composeV3, now); !errors.Is(err, ErrComposeChanged) {
		t.Errorf("a previous compose other than the one read (and pulled): want ErrComposeChanged, got %v", err)
	}
	if err := s.RevertCompose(ctx, "never", ComposeHash(composeV1), "", now); !errors.Is(err, ErrNoPreviousCompose) {
		t.Errorf("never replaced: want ErrNoPreviousCompose, got %v", err)
	}
	if err := s.RevertCompose(ctx, "never", ComposeHash(composeV1), composeV2, now); !errors.Is(err, ErrNoPreviousCompose) {
		t.Errorf("never replaced, caller claims a previous: want ErrNoPreviousCompose, got %v", err)
	}
	if err := s.RevertCompose(ctx, "ghost", v2.ComposeSHA256, v2.PreviousComposeYAML, now); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("unknown app: want sql.ErrNoRows, got %v", err)
	}
	if got, _ := s.Get(ctx, "a"); sameRecord(v2, got) != "" {
		t.Errorf("a refused re-apply wrote the row")
	}
}

func TestRevertWorkflowShape(t *testing.T) {
	w := RevertWorkflow(nil, nil, nil, nil)
	var names []string
	for _, s := range w.Steps {
		names = append(names, s.Name)
	}
	if w.Kind != "app.revert" || strings.Join(names, ",") != "load,pull,apply,push,leaf,drop_volumes" {
		t.Errorf("workflow = %s %v, want app.revert load,pull,apply,push,leaf,drop_volumes", w.Kind, names)
	}
}

// The owner's recovery after #411's second branch: an upgrade whose pull
// succeeded and whose `up` failed, re-applied. The previous compose is pulled
// and pushed under its own budget, the proxy is pointed at its own port, the
// row's record swaps whole, and the upgrade is offered again.
func TestRevertSaga_AfterAFailedUpReappliesThePreviousComposeAndItsRoute(t *testing.T) {
	ctx := context.Background()
	store, inv := seedUpgradeApp(t, "a")

	// The upgrade: pull fine, up fails.
	nc := startNATS(t)
	fakePullAgent(t, nc, proto.AppPullAck{OK: true}, nil)
	fakeDeployAgent(t, nc, proto.AppDeployAck{OK: false, Status: proto.AppStatusFailed, Detail: "up: failed to create network"})
	lookup := lookupOf(upgradeTile(composeV2), 2)
	if step, _ := runUpgrade(t, store, inv, nc, lookup, "a"); step != "push" {
		t.Fatalf("setup: want the upgrade to fail at push, failed at %q", step)
	}

	// The re-apply, on a fresh bus with an agent that succeeds.
	nc2 := startNATS(t)
	pulls := fakePullAgent(t, nc2, proto.AppPullAck{OK: true}, nil)
	deploys := fakeDeployAgent(t, nc2, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
	delivered := countingLeafNode(t, nc2, "n", true)
	routed := make(chan [2]any, 1)
	mint := func(app *App) (proto.AppLeafCmd, error) {
		routed <- [2]any{app.PublishedPort, app.WebTLS}
		return proto.AppLeafCmd{AppID: app.ID, UpstreamPort: app.PublishedPort, UpstreamTLS: app.WebTLS}, nil
	}
	if step, err := runRevert(t, store, inv, nc2, mint, "a", composeV1); err != nil {
		t.Fatalf("re-apply failed at %s: %v", step, err)
	}

	if cmd := <-pulls; cmd.ComposeYAML != composeV1 || cmd.WorkBudgetSeconds != 0 {
		t.Errorf("pull = %q budget %d, want v1 under v1's budget", cmd.ComposeYAML, cmd.WorkBudgetSeconds)
	}
	if cmd := <-deploys; cmd.AppID != "a" || cmd.ComposeYAML != composeV1 || cmd.WorkBudgetSeconds != 0 {
		t.Errorf("push = %s %q budget %d, want v1 to the same app", cmd.AppID, cmd.ComposeYAML, cmd.WorkBudgetSeconds)
	}
	select {
	case r := <-routed:
		if r[0] != 3001 || r[1] != false {
			t.Errorf("leaf minted for port=%v tls=%v, want v1's 3001 over plain HTTP", r[0], r[1])
		}
	default:
		t.Error("the re-apply did not re-route the proxy")
	}
	if atomic.LoadInt32(delivered) != 1 {
		t.Errorf("leaf delivered %d times, want 1", atomic.LoadInt32(delivered))
	}

	got, _ := store.Get(ctx, "a")
	if got.ComposeYAML != composeV1 || got.ComposeCatalogVersion != 1 || got.PublishedPort != 3001 || got.WebTLS || got.DeployBudgetSeconds != 0 {
		t.Errorf("installed record = %+v, want v1's", got)
	}
	if got.PreviousComposeYAML != composeV2 || got.PreviousComposeCatalogVersion != 2 || got.PreviousPublishedPort != 3443 {
		t.Errorf("previous record = %+v, want v2's", got)
	}
	if got.LastStatus != proto.AppStatusRunning {
		t.Errorf("status = %s, want running", got.LastStatus)
	}
	// compose_catalog_version swapped back to 1, so the v2 tile is an upgrade
	// again — not an "already current", and not a "downgrade".
	if target, err := ResolveUpgrade(got, lookup); err != nil || target.CatalogVersion != 2 {
		t.Errorf("after re-applying v1 the v2 upgrade must be offered again: %+v %v", target, err)
	}
}

func TestRevertSaga_RefusesAnAppWithNoPreviousCompose(t *testing.T) {
	store, inv := seedUpgradeApp(t, "a")
	nc := startNATS(t)
	pulls := fakePullAgent(t, nc, proto.AppPullAck{OK: true}, nil)

	step, err := runRevert(t, store, inv, nc, nil, "a", composeV2)
	if step != "load" || !errors.Is(err, ErrUnknownComposeHash) {
		t.Fatalf("want load to refuse, got step=%q err=%v", step, err)
	}
	select {
	case cmd := <-pulls:
		t.Fatalf("a refused re-apply asked the node to pull: %+v", cmd)
	case <-time.After(100 * time.Millisecond):
	}
}

// A re-apply whose pull fails is the first branch again: nothing changes.
func TestRevertSaga_AFailedPullChangesNothing(t *testing.T) {
	store, inv, before, row := upgradedToV2(t)
	nc := startNATS(t)
	deploys := fakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
	fakePullAgent(t, nc, proto.AppPullAck{OK: false, Detail: "registry unreachable"}, nil)

	step, err := runRevert(t, store, inv, nc, nil, "a", composeV1)
	if step != "pull" || err == nil {
		t.Fatalf("want the pull to fail, got step=%q err=%v", step, err)
	}
	select {
	case cmd := <-deploys:
		t.Fatalf("a failed pull went on to push: %+v", cmd)
	case <-time.After(100 * time.Millisecond):
	}
	after := row()
	if field := sameRecord(before, after); field != "" {
		t.Errorf("a failed re-apply pull changed the row's %s", field)
	}
	if after.LastStatus != proto.AppStatusRunning || !strings.Contains(after.LastDetail, "registry unreachable") {
		t.Errorf("status = %s %q", after.LastStatus, after.LastDetail)
	}
}

// The write is conditional on the previous compose still being the one that
// was pulled. Another change landing during the pull makes this job's view
// stale, and it stops without writing.
func TestRevertSaga_AChangeDuringThePullIsRefusedAtApply(t *testing.T) {
	store, inv, _, row := upgradedToV2(t)
	nc := startNATS(t)
	deploys := fakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
	fakePullAgent(t, nc, proto.AppPullAck{OK: true}, func() {
		// An upgrade to v3 lands while the re-apply is pulling v1: the
		// previous compose is now v2.
		_ = store.UpgradeCompose(context.Background(), "a", ComposeHash(composeV2), UpgradeTarget{Tile: tileV3(), CatalogVersion: 3}.ComposeUpgrade(), time.Now().UTC())
	})

	step, err := runRevert(t, store, inv, nc, nil, "a", composeV1)
	if step != "apply" || !errors.Is(err, ErrComposeChanged) {
		t.Fatalf("want apply to refuse, got step=%q err=%v", step, err)
	}
	select {
	case cmd := <-deploys:
		t.Fatalf("a refused apply pushed: %+v", cmd)
	case <-time.After(100 * time.Millisecond):
	}
	if got := row(); got.ComposeYAML != composeV3 || got.PreviousComposeYAML != composeV2 {
		t.Errorf("the refused apply wrote over the change that landed: compose=%q previous=%q", got.ComposeYAML, got.PreviousComposeYAML)
	}
}

// #411's reconcile half. An `up` that failed before reaching a service leaves
// its old container running under the new compose; the agent flags it
// outdated. The sweep must not read that as the failed upgrade recovering:
// the status and its reason stay, and no leaf is minted for the new route.
func TestReconcileSweep_AnOutdatedSurvivorDoesNotRecoverAFailedApp(t *testing.T) {
	nc := startNATS(t)
	store, inv := seedRoutableFailedApp(t, "n", "a")
	sub, err := nc.Subscribe(proto.AppStatusSubject("n"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.AppStatusAck{AppID: "a", Status: proto.AppStatusRunning,
			Services: []proto.AppServiceStatus{{Name: "web", State: "running", Outdated: true}}})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	delivered := countingLeafNode(t, nc, "n", true)
	var minted int32
	mint := func(app *App) (proto.AppLeafCmd, error) {
		atomic.AddInt32(&minted, 1)
		return proto.AppLeafCmd{AppID: app.ID}, nil
	}

	out, err := reconcileSweep(store, inv, nc, mint)(newStepCtxNATS(`{}`, nc))
	if err != nil {
		t.Fatalf("reconcileSweep: %v", err)
	}
	var counts map[string]int
	_ = json.Unmarshal(out, &counts)
	if counts["drifted"] != 0 || counts["recovered"] != 0 {
		t.Errorf("counts = %+v, want no drift and no recovery", counts)
	}
	if atomic.LoadInt32(&minted) != 0 || atomic.LoadInt32(delivered) != 0 {
		t.Errorf("minted=%d delivered=%d, want no leaf for a compose that is not running", minted, atomic.LoadInt32(delivered))
	}
	if got, _ := store.Get(context.Background(), "a"); got.LastStatus != proto.AppStatusFailed || got.LastDetail == "" {
		t.Errorf("status = %s %q, want the failure and its reason kept", got.LastStatus, got.LastDetail)
	}
}

// A pull whose reply never arrives, or arrives unreadable, is the failed-pull
// branch too. The timeout case pins why the status write is detached: the
// step's own context is spent by the time the status goes back, and a write on
// it would silently leave the app DEPLOYING.
func TestPullStep_ATimedOutOrUnreadableReplyChangesNothing(t *testing.T) {
	cases := []struct {
		name  string
		agent func(t *testing.T, nc *nats.Conn)
		ctx   func() (context.Context, context.CancelFunc)
		says  string
	}{
		{"rpc times out", func(t *testing.T, nc *nats.Conn) {
			fakeVolumeCheckAgent(t, nc)
			sub, err := nc.Subscribe(proto.AppPullSubject("n"), func(m *nats.Msg) {}) // never answers
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = sub.Unsubscribe() })
		}, func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 200*time.Millisecond)
		}, "pull rpc"},
		{"ack is not json", func(t *testing.T, nc *nats.Conn) {
			fakeVolumeCheckAgent(t, nc)
			sub, err := nc.Subscribe(proto.AppPullSubject("n"), func(m *nats.Msg) { _ = m.Respond([]byte("not-json")) })
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = sub.Unsubscribe() })
		}, func() (context.Context, context.CancelFunc) {
			return context.WithCancel(context.Background())
		}, "decode pull ack"},
		{"ack fails with no detail", func(t *testing.T, nc *nats.Conn) {
			fakePullAgent(t, nc, proto.AppPullAck{OK: false}, nil)
		}, func() (context.Context, context.CancelFunc) {
			return context.WithCancel(context.Background())
		}, "agent reported the pull failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store, inv, before, row := upgradedToV2(t)
			nc := startNATS(t)
			c.agent(t, nc)
			ctx, cancel := c.ctx()
			defer cancel()
			sc := newStepCtxNATS(`{"appId":"a"}`, nc)
			sc.Ctx = ctx

			_, err := pullStep(store, inv, nc, "upgrade", composeChangeSpecAppID, composeChangeSpecDeleteVolumes, upgradePullSource(lookupOf(tileV3(), 3)))(sc)
			if err == nil || !strings.Contains(err.Error(), c.says) {
				t.Fatalf("err = %v, want one saying %q", err, c.says)
			}
			after := row()
			if field := sameRecord(before, after); field != "" {
				t.Errorf("the row's %s changed", field)
			}
			if after.LastStatus != proto.AppStatusRunning || !strings.Contains(after.LastDetail, c.says) {
				t.Errorf("status = %s %q, want running with the reason", after.LastStatus, after.LastDetail)
			}
		})
	}
}
