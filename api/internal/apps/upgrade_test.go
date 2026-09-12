package apps

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
	"github.com/nats-io/nats.go"
)

// In-place catalog upgrade (geekdojo/geekdojo-brain#409): the store mutation,
// the hash backfill, the one resolver the badge, the route and the saga share,
// and the saga end to end against a fake agent.

const (
	composeV1 = "services:\n  web:\n    image: e/kuma:1@sha256:" + "1111111111111111111111111111111111111111111111111111111111111111" + "\n    volumes: [data:/data]\nvolumes:\n  data: {}\n"
	composeV2 = "services:\n  web:\n    image: e/kuma:2@sha256:" + "2222222222222222222222222222222222222222222222222222222222222222" + "\n    volumes: [data:/data]\nvolumes:\n  data: {}\n"
)

// upgradeTile is the tile as a later catalog carries it: a new compose, and a
// web port, scheme and budget that all differ from what the app was installed
// with, so a field that is not re-copied shows up as a wrong value rather than
// an accidentally-equal one.
func upgradeTile(compose string) tileschema.Tile {
	return tileschema.Tile{
		ID:                  "uptime-kuma",
		ComposeYAML:         compose,
		DeployBudgetSeconds: 600,
		Ports:               []tileschema.Port{{Name: "web", Container: 3001, Published: 3443, Web: true, TLS: true}},
	}
}

func lookupOf(t tileschema.Tile, version int) TileLookup {
	return func(id string) (tileschema.Tile, int, bool) {
		if id != t.ID {
			return tileschema.Tile{}, 0, false
		}
		return t, version, true
	}
}

// installedApp is an app as install left it from catalog v1: every carried-over
// field set to something distinguishable.
func installedApp(id string) *App {
	now := time.Now().UTC().Add(-time.Hour)
	return &App{
		ID: id, Name: "kuma", ComposeYAML: composeV1, TargetNode: "n",
		PublishedPort: 3001, WebTLS: false, SourceTile: "uptime-kuma", DeployBudgetSeconds: 0,
		ComposeCatalogVersion: 1, ExposeLAN: true, LastStatus: proto.AppStatusRunning,
		CreatedAt: now, UpdatedAt: now,
		BackupAck: &BackupAck{At: now.Truncate(time.Millisecond), By: "alice"},
	}
}

func TestStore_CreateStampsTheComposeHashItself(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	a := makeApp("a", "kuma")
	a.ComposeSHA256 = "not-a-hash-anyone-computed"
	if err := s.Create(ctx, a); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(ctx, "a")
	if got.ComposeSHA256 != ComposeHash("services: {}") {
		t.Errorf("stored hash = %q, want the hash of the stored compose", got.ComposeSHA256)
	}
	if a.ComposeSHA256 != got.ComposeSHA256 {
		t.Errorf("Create left the caller's struct saying %q while the row says %q", a.ComposeSHA256, got.ComposeSHA256)
	}
}

func TestStore_UpgradeComposeCarriesOverIdentityAndReCopiesTheTileFields(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	before := installedApp("01J0000000000000000000KUMA")
	if err := s.Create(ctx, before); err != nil {
		t.Fatal(err)
	}

	target := UpgradeTarget{Tile: upgradeTile(composeV2), CatalogVersion: 2}
	if err := s.UpgradeCompose(ctx, before.ID, ComposeHash(composeV1), target.ComposeUpgrade(), time.Now().UTC()); err != nil {
		t.Fatalf("UpgradeCompose: %v", err)
	}
	got, err := s.Get(ctx, before.ID)
	if err != nil || got == nil {
		t.Fatalf("Get: %v %v", got, err)
	}

	// Carried over: identity and the owner's choices.
	if got.ID != before.ID || got.Name != "kuma" || got.TargetNode != "n" || !got.ExposeLAN || got.SourceTile != "uptime-kuma" {
		t.Errorf("an upgrade changed identity or an owner choice: %+v", got)
	}
	if got.BackupAck == nil || got.BackupAck.By != "alice" || !got.BackupAck.At.Equal(before.BackupAck.At) {
		t.Errorf("BackupAck = %+v, want the install-time acknowledgement kept", got.BackupAck)
	}
	if !got.CreatedAt.Equal(before.CreatedAt.Truncate(time.Millisecond)) {
		t.Errorf("CreatedAt moved: %s → %s", before.CreatedAt, got.CreatedAt)
	}

	// Re-copied from the tile, as install does.
	if got.PublishedPort != 3443 || !got.WebTLS || got.DeployBudgetSeconds != 600 {
		t.Errorf("tile fields not re-copied: port=%d tls=%v budget=%d", got.PublishedPort, got.WebTLS, got.DeployBudgetSeconds)
	}

	// The compose record.
	if got.ComposeYAML != composeV2 || got.ComposeSHA256 != ComposeHash(composeV2) || got.ComposeCatalogVersion != 2 {
		t.Errorf("compose record = %q / %q / v%d", got.ComposeYAML, got.ComposeSHA256, got.ComposeCatalogVersion)
	}
	if got.PreviousComposeYAML != composeV1 {
		t.Errorf("PreviousComposeYAML = %q, want the compose the upgrade replaced", got.PreviousComposeYAML)
	}
	// And the record that went with it (#411), so re-applying it restores the
	// route and budget it actually ran with.
	if got.PreviousComposeCatalogVersion != 1 || got.PreviousPublishedPort != 3001 || got.PreviousWebTLS || got.PreviousDeployBudgetSeconds != 0 {
		t.Errorf("previous record = v%d port=%d tls=%v budget=%d, want v1 3001 false 0",
			got.PreviousComposeCatalogVersion, got.PreviousPublishedPort, got.PreviousWebTLS, got.PreviousDeployBudgetSeconds)
	}
}

// The write is conditional on the hash the caller read. Without that, two
// upgrades racing would both succeed and the second would shift the first's
// compose into previous_compose_yaml, losing the one that was really running.
func TestStore_UpgradeComposeRefusesAStaleReadAndAnUnknownApp(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.Create(ctx, installedApp("a")); err != nil {
		t.Fatal(err)
	}
	up := UpgradeTarget{Tile: upgradeTile(composeV2), CatalogVersion: 2}.ComposeUpgrade()

	if err := s.UpgradeCompose(ctx, "a", ComposeHash("some other compose"), up, time.Now().UTC()); !errors.Is(err, ErrComposeChanged) {
		t.Fatalf("stale hash: want ErrComposeChanged, got %v", err)
	}
	if got, _ := s.Get(ctx, "a"); got.ComposeYAML != composeV1 || got.PreviousComposeYAML != "" {
		t.Fatalf("a refused upgrade wrote the row: %+v", got)
	}
	if err := s.UpgradeCompose(ctx, "nope", ComposeHash(composeV1), up, time.Now().UTC()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unknown app: want sql.ErrNoRows, got %v", err)
	}

	// The real read succeeds, and the same read a second time is now stale.
	if err := s.UpgradeCompose(ctx, "a", ComposeHash(composeV1), up, time.Now().UTC()); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if err := s.UpgradeCompose(ctx, "a", ComposeHash(composeV1), up, time.Now().UTC()); !errors.Is(err, ErrComposeChanged) {
		t.Fatalf("replayed upgrade: want ErrComposeChanged, got %v", err)
	}
	if got, _ := s.Get(ctx, "a"); got.PreviousComposeYAML != composeV1 {
		t.Fatalf("a replay overwrote previous_compose_yaml: %q", got.PreviousComposeYAML)
	}
}

// Every app on an existing cluster was installed before the hash column. The
// migration must leave them in a known state — hashed from the compose that is
// by definition installed — rather than blank, which would read as "an upgrade
// is available" for every catalog app on the cluster.
func TestOpenStore_BackfillsTheComposeHashOfExistingApps(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")

	// The apps table exactly as it shipped before #409.
	const oldSchema = `
CREATE TABLE apps (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    compose_yaml    TEXT NOT NULL,
    target_node     TEXT NOT NULL,
    published_port  INTEGER NOT NULL DEFAULT 0,
    source_tile     TEXT NOT NULL DEFAULT '',
    deploy_budget_s INTEGER NOT NULL DEFAULT 0,
    expose_lan      INTEGER NOT NULL DEFAULT 0,
    web_tls         INTEGER NOT NULL DEFAULT 0,
    last_status     TEXT NOT NULL DEFAULT 'stopped',
    last_detail     TEXT NOT NULL DEFAULT '',
    last_deployed   INTEGER,
    last_stopped    INTEGER,
    last_status_at  INTEGER,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    backup_ack_at   INTEGER,
    backup_ack_by   TEXT NOT NULL DEFAULT ''
);`
	db, err := dbutil.Open(ctx, path, oldSchema, "apps-old")
	if err != nil {
		t.Fatalf("open old db: %v", err)
	}
	now := time.Now().UTC().UnixMilli()
	for _, row := range []struct{ id, name, compose, tile string }{
		{"old-catalog", "kuma", composeV1, "uptime-kuma"},
		{"old-custom", "mine", "services: {}", ""},
	} {
		if _, err := db.ExecContext(ctx, `
            INSERT INTO apps (id, name, compose_yaml, target_node, source_tile, created_at, updated_at)
            VALUES (?, ?, ?, 'n', ?, ?, ?)`, row.id, row.name, row.compose, row.tile, now, now); err != nil {
			t.Fatalf("seed %s: %v", row.id, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatalf("OpenStore (migrating): %v", err)
	}
	for id, compose := range map[string]string{"old-catalog": composeV1, "old-custom": "services: {}"} {
		got, err := s.Get(ctx, id)
		if err != nil || got == nil {
			t.Fatalf("pre-existing row %s must still read: %v", id, err)
		}
		if got.ComposeSHA256 != ComposeHash(compose) {
			t.Errorf("%s: hash = %q, want the hash of its installed compose", id, got.ComposeSHA256)
		}
		// Nothing recorded which catalog these came from; 0 says so rather
		// than inventing a version.
		if got.ComposeCatalogVersion != 0 || got.PreviousComposeYAML != "" {
			t.Errorf("%s: version=%d previous=%q, want unknown and never-upgraded", id, got.ComposeCatalogVersion, got.PreviousComposeYAML)
		}
	}

	// A backfilled app whose tile has not changed is current, not upgradable.
	old, _ := s.Get(ctx, "old-catalog")
	if _, err := ResolveUpgrade(old, lookupOf(upgradeTile(composeV1), 5)); !errors.Is(err, ErrUpgradeAlreadyCurrent) {
		t.Errorf("backfilled app on an unchanged tile: want ErrUpgradeAlreadyCurrent, got %v", err)
	}

	// Re-opening is a no-op, and the backfill never touches a hash that is set.
	if err := s.UpgradeCompose(ctx, "old-catalog", ComposeHash(composeV1), UpgradeTarget{Tile: upgradeTile(composeV2), CatalogVersion: 6}.ComposeUpgrade(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(ctx, path)
	if err != nil {
		t.Fatalf("re-open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if got, _ := s.Get(ctx, "old-catalog"); got.ComposeSHA256 != ComposeHash(composeV2) {
		t.Errorf("re-open changed a set hash: %q", got.ComposeSHA256)
	}
}

func TestResolveUpgrade(t *testing.T) {
	changed := lookupOf(upgradeTile(composeV2), 2)

	t.Run("tile changed", func(t *testing.T) {
		a := installedApp("a")
		a.ComposeSHA256 = ComposeHash(a.ComposeYAML)
		target, err := ResolveUpgrade(a, changed)
		if err != nil {
			t.Fatalf("want an upgrade, got %v", err)
		}
		if target.CatalogVersion != 2 || target.Tile.ComposeYAML != composeV2 {
			t.Errorf("target = v%d %q", target.CatalogVersion, target.Tile.ComposeYAML)
		}
	})
	t.Run("version not recorded falls through to the hash", func(t *testing.T) {
		a := installedApp("a")
		a.ComposeSHA256 = ComposeHash(a.ComposeYAML)
		a.ComposeCatalogVersion = 0
		if _, err := ResolveUpgrade(a, changed); err != nil {
			t.Fatalf("want an upgrade, got %v", err)
		}
	})

	refusals := []struct {
		name   string
		mutate func(*App)
		lookup TileLookup
		want   error
	}{
		{"custom app", func(a *App) { a.SourceTile = "" }, changed, ErrUpgradeCustomApp},
		{"no live catalog", nil, nil, ErrUpgradeTileUnavailable},
		{"tile withdrawn", func(a *App) { a.SourceTile = "gone" }, changed, ErrUpgradeTileUnavailable},
		{"tile is a preview", nil, func() TileLookup {
			tl := upgradeTile(composeV2)
			tl.Status = tileschema.StatusPreview
			return lookupOf(tl, 2)
		}(), ErrUpgradeTileUnavailable},
		{"already current", nil, lookupOf(upgradeTile(composeV1), 2), ErrUpgradeAlreadyCurrent},
		{"catalog went backwards", func(a *App) { a.ComposeCatalogVersion = 9 }, changed, ErrUpgradeCatalogOlder},
	}
	for _, c := range refusals {
		t.Run(c.name, func(t *testing.T) {
			a := installedApp("a")
			a.ComposeSHA256 = ComposeHash(a.ComposeYAML)
			if c.mutate != nil {
				c.mutate(a)
			}
			if _, err := ResolveUpgrade(a, c.lookup); !errors.Is(err, c.want) {
				t.Fatalf("want %v, got %v", c.want, err)
			}
		})
	}
}

func TestUpgradeWorkflowShape(t *testing.T) {
	w := UpgradeWorkflow(nil, nil, nil, nil, nil)
	if w.Kind != "app.upgrade" {
		t.Errorf("Kind = %q", w.Kind)
	}
	var names []string
	for _, s := range w.Steps {
		names = append(names, s.Name)
	}
	// #411: the pull runs before anything is written, and the push is still
	// after the row write.
	if got := strings.Join(names, ","); got != "load,pull,persist,push,leaf,drop_volumes" {
		t.Errorf("steps = %s, want load,pull,persist,push,leaf,drop_volumes", got)
	}
}

// seedUpgradeApp puts installedApp on an online compute node.
func seedUpgradeApp(t *testing.T, id string) (*Store, *inventory.Store) {
	t.Helper()
	store, inv := newStore(t), newInventory(t)
	if err := inv.Insert(context.Background(), &proto.Node{
		ID: "n", Role: proto.RoleCompute, Hostname: "n.test", FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(context.Background(), installedApp(id)); err != nil {
		t.Fatal(err)
	}
	return store, inv
}

// fakeDeployAgent answers docker.deploy on node n with ack, and hands every
// command it received to the test.
func fakeDeployAgent(t *testing.T, nc *nats.Conn, ack proto.AppDeployAck) <-chan proto.AppDeployCmd {
	t.Helper()
	got := make(chan proto.AppDeployCmd, 4)
	sub, err := nc.Subscribe(proto.AppDeploySubject("n"), func(m *nats.Msg) {
		var cmd proto.AppDeployCmd
		_ = json.Unmarshal(m.Data, &cmd)
		got <- cmd
		b, _ := json.Marshal(ack)
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	return got
}

// fakePullAgent answers docker.pull on node n with ack, and hands every
// command it received to the test. during, when set, runs inside the agent
// before it answers — the window in which the node is pulling.
//
// It also answers docker.volumes.check on n with nothing dropped, as a node
// whose app has no volume the new compose leaves undeclared: every compose
// change asks that before it pulls (#412). A test about the gate itself uses
// fakeVolumeCheckAgent on its own instead.
func fakePullAgent(t *testing.T, nc *nats.Conn, ack proto.AppPullAck, during func()) <-chan proto.AppPullCmd {
	t.Helper()
	fakeVolumeCheckAgent(t, nc)
	return fakePullOnly(t, nc, ack, during)
}

// fakePullOnly is fakePullAgent without the volumes check.
func fakePullOnly(t *testing.T, nc *nats.Conn, ack proto.AppPullAck, during func()) <-chan proto.AppPullCmd {
	t.Helper()
	got := make(chan proto.AppPullCmd, 4)
	sub, err := nc.Subscribe(proto.AppPullSubject("n"), func(m *nats.Msg) {
		var cmd proto.AppPullCmd
		_ = json.Unmarshal(m.Data, &cmd)
		got <- cmd
		if during != nil {
			during()
		}
		b, _ := json.Marshal(ack)
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	return got
}

// runSteps runs a workflow's steps in order, as the runner does — each step
// sees the results of the ones before it — stopping at the first failure. It
// returns the name of the step that failed, or "".
func runSteps(t *testing.T, w jobs.Workflow, nc *nats.Conn, appID string) (string, error) {
	t.Helper()
	r := runWorkflow(t, w, nc, `{"appId":"`+appID+`"}`, "job-test")
	return r.failedAt, r.err
}

// workflowRun is what runWorkflow saw: the step that ended the run and why
// (jobs.ErrStopWorkflow for a step that ended it successfully), every recorded
// step result, and every log line — the three places a job's content is
// persisted and rendered.
type workflowRun struct {
	failedAt string
	err      error
	results  map[string]json.RawMessage
	logs     []string
}

// runWorkflow runs w's steps in order against spec under jobID, as the runner
// does, stopping at the first error.
func runWorkflow(t *testing.T, w jobs.Workflow, nc *nats.Conn, spec, jobID string) workflowRun {
	t.Helper()
	run := workflowRun{results: map[string]json.RawMessage{}}
	for _, s := range w.Steps {
		sc := newStepCtxNATS(spec, nc)
		sc.JobID = jobID
		sc.PriorResults = run.results
		sc.Log = func(level, message string) { run.logs = append(run.logs, level+": "+message) }
		out, err := s.Do(sc)
		if out != nil {
			run.results[s.Name] = out
		}
		if err != nil {
			run.failedAt, run.err = s.Name, err
			return run
		}
	}
	return run
}

// runUpgrade runs the app.upgrade steps in order, stopping at the first
// failure. It returns the name of the step that failed, or "".
func runUpgrade(t *testing.T, store *Store, inv *inventory.Store, nc *nats.Conn, lookup TileLookup, appID string) (string, error) {
	t.Helper()
	return runSteps(t, UpgradeWorkflow(store, inv, nc, nil, lookup), nc, appID)
}

// The done-means of #409, on the wire: the agent is sent the tile's new compose
// for the SAME app id, so the Compose project and every named volume it derives
// are the ones the app already has.
func TestUpgradeSaga_DeploysTheTilesComposeToTheSameULID(t *testing.T) {
	ctx := context.Background()
	const id = "01J9ZK3Q0M8X7Y6W5V4T3S2R1P"
	nc := startNATS(t)
	store, inv := seedUpgradeApp(t, id)
	before, _ := store.Get(ctx, id)
	pulls := fakePullAgent(t, nc, proto.AppPullAck{OK: true}, nil)
	got := fakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})

	if step, err := runUpgrade(t, store, inv, nc, lookupOf(upgradeTile(composeV2), 2), id); err != nil {
		t.Fatalf("step %s: %v", step, err)
	}

	select {
	case cmd := <-got:
		if cmd.AppID != id {
			t.Fatalf("agent was sent app id %q, want %q — a new id is a new project and empty volumes", cmd.AppID, id)
		}
		if proto.AppProjectName(cmd.AppID) != proto.AppProjectName(before.ID) ||
			proto.AppVolumeName(cmd.AppID, "data") != proto.AppVolumeName(before.ID, "data") {
			t.Errorf("project/volume naming changed across the upgrade")
		}
		if cmd.ComposeYAML != composeV2 {
			t.Errorf("agent was sent compose %q, want the tile's", cmd.ComposeYAML)
		}
		if cmd.Name != "kuma" || cmd.WorkBudgetSeconds != 600 {
			t.Errorf("agent was sent name=%q budget=%d, want the kept name and the tile's budget", cmd.Name, cmd.WorkBudgetSeconds)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent never received a deploy command")
	}
	select {
	case cmd := <-pulls:
		if cmd.AppID != id || cmd.ComposeYAML != composeV2 || cmd.WorkBudgetSeconds != 600 {
			t.Errorf("agent was asked to pull app=%q compose=%q budget=%d, want the tile's compose under its budget", cmd.AppID, cmd.ComposeYAML, cmd.WorkBudgetSeconds)
		}
	default:
		t.Fatal("the upgrade deployed without pulling first")
	}

	after, _ := store.Get(ctx, id)
	if after.ID != before.ID || after.Name != before.Name || after.TargetNode != before.TargetNode ||
		after.ExposeLAN != before.ExposeLAN || after.BackupAck == nil || after.BackupAck.By != "alice" {
		t.Errorf("carried-over fields changed: before %+v after %+v", before, after)
	}
	if after.ComposeYAML != composeV2 || after.PreviousComposeYAML != composeV1 || after.ComposeCatalogVersion != 2 {
		t.Errorf("row does not reflect the upgrade: %+v", after)
	}
	if after.LastStatus != proto.AppStatusRunning {
		t.Errorf("status = %s, want running", after.LastStatus)
	}
	if _, err := ResolveUpgrade(after, lookupOf(upgradeTile(composeV2), 2)); !errors.Is(err, ErrUpgradeAlreadyCurrent) {
		t.Errorf("upgradeAvailable must clear after the upgrade: %v", err)
	}
}

// The ordering decision, pinned: the row is written before the push, so a push
// the agent fails leaves the row naming the compose the node was last sent,
// with the replaced one kept for going back and the agent's reason recorded.
//
// #411's second branch: the pull SUCCEEDED, so this is `up` failing, and it is
// not reverted — the new containers may have migrated the data.
func TestUpgradeSaga_AFailedPushLeavesTheNewComposeOnTheRowAndTheOldOneKept(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedUpgradeApp(t, testAppID)
	fakePullAgent(t, nc, proto.AppPullAck{OK: true}, nil)
	fakeDeployAgent(t, nc, proto.AppDeployAck{OK: false, Status: proto.AppStatusFailed, Detail: "up: port is already allocated"})

	step, err := runUpgrade(t, store, inv, nc, lookupOf(upgradeTile(composeV2), 2), testAppID)
	if err == nil || step != "push" {
		t.Fatalf("want the push step to fail, got step=%q err=%v", step, err)
	}
	got, _ := store.Get(ctx, testAppID)
	if got.ComposeYAML != composeV2 || got.PreviousComposeYAML != composeV1 {
		t.Errorf("row compose = %q previous = %q", got.ComposeYAML, got.PreviousComposeYAML)
	}
	if got.LastStatus != proto.AppStatusFailed || got.LastDetail != "up: port is already allocated" {
		t.Errorf("status = %s %q, want failed with the agent's reason", got.LastStatus, got.LastDetail)
	}
	if got.PreviousPublishedPort != 3001 || got.PublishedPort != 3443 {
		t.Errorf("route: port=%d previous=%d, want the new port installed and the old one kept", got.PublishedPort, got.PreviousPublishedPort)
	}
	if err := CanRevert(got); err != nil {
		t.Errorf("the owner's way back must be open after a failed up: %v", err)
	}
}

// An app.upgrade job for an app that already runs its tile's current compose
// — submitted without the handler, which would have answered 200 and started
// nothing — ends successfully at load: no pull, no persist, no push, and the
// row, previous compose included, untouched.
func TestUpgradeSaga_SubmittedDirectlyForACurrentAppChangesNothing(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedUpgradeApp(t, testAppID)
	checks := fakeVolumeCheckAgent(t, nc)
	pulls := fakePullOnly(t, nc, proto.AppPullAck{OK: true}, nil)
	got := fakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
	lookup := lookupOf(upgradeTile(composeV2), 2)

	if _, err := runUpgrade(t, store, inv, nc, lookup, testAppID); err != nil {
		t.Fatal(err)
	}
	<-got
	<-pulls
	<-checks
	before, _ := store.Get(ctx, testAppID)

	r := runWorkflow(t, UpgradeWorkflow(store, inv, nc, nil, lookup), nc, `{"appId":"`+testAppID+`"}`, "job-direct")
	if !errors.Is(r.err, jobs.ErrStopWorkflow) || r.failedAt != "load" {
		t.Fatalf("want the job to end successfully at load, got step=%q err=%v", r.failedAt, r.err)
	}
	for _, step := range []string{"pull", "persist", "push", "leaf", "drop_volumes"} {
		if _, ran := r.results[step]; ran {
			t.Errorf("step %s ran for an app already on its tile's compose", step)
		}
	}
	select {
	case cmd := <-checks:
		t.Fatalf("the node was asked to check volumes: %+v", cmd)
	case cmd := <-pulls:
		t.Fatalf("the node was asked to pull: %+v", cmd)
	case cmd := <-got:
		t.Fatalf("the node was sent a deploy: %+v", cmd)
	case <-time.After(100 * time.Millisecond):
	}
	after, _ := store.Get(ctx, testAppID)
	if field := sameRecord(before, after); field != "" || after.LastStatus != before.LastStatus || after.PreviousComposeYAML != composeV1 {
		t.Errorf("the no-op job changed the row (%s): %+v", field, after)
	}
}

// The same, when the other upgrade lands while this one is pulling: persist
// finds the pulled compose already installed, puts the status back, and ends
// successfully without writing or pushing, and without shifting
// previous_compose_yaml again.
func TestUpgradeSaga_AnUpgradeThatLostTheRaceDuringThePullEndsWithoutPushing(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedUpgradeApp(t, testAppID)
	lookup := lookupOf(upgradeTile(composeV2), 2)
	fakePullAgent(t, nc, proto.AppPullAck{OK: true}, func() {
		// The winner's persist, during this job's pull.
		if err := store.UpgradeCompose(ctx, testAppID, ComposeHash(composeV1), UpgradeTarget{Tile: upgradeTile(composeV2), CatalogVersion: 2}.ComposeUpgrade(), time.Now().UTC()); err != nil {
			t.Error(err)
		}
	})
	got := fakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})

	r := runWorkflow(t, UpgradeWorkflow(store, inv, nc, nil, lookup), nc, `{"appId":"`+testAppID+`"}`, "job-loser")
	if !errors.Is(r.err, jobs.ErrStopWorkflow) || r.failedAt != "persist" {
		t.Fatalf("want the job to end successfully at persist, got step=%q err=%v", r.failedAt, r.err)
	}
	select {
	case cmd := <-got:
		t.Fatalf("the losing upgrade pushed: %+v", cmd)
	case <-time.After(100 * time.Millisecond):
	}
	row, _ := store.Get(ctx, testAppID)
	if row.PreviousComposeYAML != composeV1 || row.ComposeYAML != composeV2 {
		t.Errorf("row = compose %q previous %q, want v2 with v1 kept as the previous", row.ComposeYAML, row.PreviousComposeYAML)
	}
	if row.LastStatus != proto.AppStatusRunning {
		t.Errorf("status = %s, want the status the pull marked put back", row.LastStatus)
	}
}

// The saga refuses on its own, not only behind the handler: the catalog can
// change between the request and the job. The refusal comes at the pull, the
// first step that resolves the tile, before the app is marked or the node is
// asked anything.
func TestUpgradeSaga_RefusesBeforeTouchingTheRowOrTheNode(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store, inv := seedUpgradeApp(t, testAppID)
	pulls := fakePullAgent(t, nc, proto.AppPullAck{OK: true}, nil)
	got := fakeDeployAgent(t, nc, proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})

	if _, err := runUpgrade(t, store, inv, nc, lookupOf(upgradeTile(composeV2), 2), testAppID); err != nil {
		t.Fatal(err)
	}
	<-got
	<-pulls

	// Withdraw the tile, then ask again.
	step, err := runUpgrade(t, store, inv, nc, nil, testAppID)
	if !errors.Is(err, ErrUpgradeTileUnavailable) || step != "pull" {
		t.Fatalf("want the pull step to refuse an unavailable tile, got step=%q err=%v", step, err)
	}
	select {
	case cmd := <-got:
		t.Fatalf("a refused upgrade reached the node: %+v", cmd)
	case cmd := <-pulls:
		t.Fatalf("a refused upgrade asked the node to pull: %+v", cmd)
	case <-time.After(100 * time.Millisecond):
	}
	if row, _ := store.Get(ctx, testAppID); row.LastStatus != proto.AppStatusRunning {
		t.Errorf("a refusal marked the app %s", row.LastStatus)
	}
	if row, _ := store.Get(ctx, testAppID); row.ComposeYAML != composeV2 {
		t.Errorf("a refused upgrade wrote the row: %q", row.ComposeYAML)
	}
}
