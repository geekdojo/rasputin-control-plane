package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/catalogsync"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// In-place catalog upgrade through PUT /api/apps/{id}/compose with
// {"source":"catalog"} (geekdojo/geekdojo-brain#409, #410): upgradeAvailable on
// both reads, every refusal, the no-op an already-current app answers, and an
// upgrade that keeps the app's identity while taking its compose from the
// verified store.

// catalogBody is the body that upgrades an app to its tile's compose.
const catalogBody = `{"source":"catalog"}`

// upgradeCatalogVersion is the version of the catalog in effect in these tests.
const upgradeCatalogVersion = 7

// upgradeFixture is gateFixture's live catalog (vaultwarden and jellyfin,
// both available) plus a preview tile, the three compose sagas registered as
// main registers them (app.upgrade against that store; app.edit with the
// server's compose stash), and a fake agent that acks every pull and every
// deploy on n1.
func upgradeFixture(t *testing.T) (*apiFixture, *http.Cookie, *catalogsync.Store, <-chan proto.AppDeployCmd) {
	t.Helper()
	f, cookie, _ := gateFixture(t)
	b := gateTileBundle(upgradeCatalogVersion)
	b.Tiles = append(b.Tiles, oneTileBundle(upgradeCatalogVersion, "preview-app").Tiles[0])
	cat, err := catalogsync.New(t.TempDir(), stubVerifier{}, b)
	if err != nil {
		t.Fatalf("catalog store: %v", err)
	}
	f.srv.SetCatalogSync(cat, nil)
	f.runner.Register(apps.UpgradeWorkflow(f.appsStore, f.inv, f.nc, nil, cat.GetVersioned))
	f.runner.Register(apps.RevertWorkflow(f.appsStore, f.inv, f.nc, nil))
	stash := apps.NewComposeStash()
	f.runner.Register(apps.EditWorkflow(f.appsStore, f.inv, f.nc, nil, stash))
	f.srv.SetComposeStash(stash)

	// The volumes check every compose change's pull step makes first (#412);
	// this node has no volume any compose drops.
	checkSub, err := f.nc.Subscribe(proto.AppVolumesCheckSubject("n1"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.AppVolumesCheckAck{OK: true, Declared: []string{}, Dropped: []proto.AppDroppedVolume{}})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatalf("agent check sub: %v", err)
	}
	t.Cleanup(func() { _ = checkSub.Unsubscribe() })

	// The pull every compose change runs first (#411); this agent's pulls all
	// succeed.
	pullSub, err := f.nc.Subscribe(proto.AppPullSubject("n1"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.AppPullAck{OK: true})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatalf("agent pull sub: %v", err)
	}
	t.Cleanup(func() { _ = pullSub.Unsubscribe() })

	got := make(chan proto.AppDeployCmd, 4)
	sub, err := f.nc.Subscribe(proto.AppDeploySubject("n1"), func(m *nats.Msg) {
		var cmd proto.AppDeployCmd
		_ = json.Unmarshal(m.Data, &cmd)
		got <- cmd
		ack, _ := json.Marshal(proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatalf("agent sub: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	return f, cookie, cat, got
}

// seedUpgradeApp creates an app on n1 installed from tile (or custom, for "")
// with compose, recorded as having come from catalog version.
func seedUpgradeApp(t *testing.T, f *apiFixture, id, name, tile, compose string, version int) *apps.App {
	t.Helper()
	now := time.Now().UTC()
	a := &apps.App{
		ID: id, Name: name, ComposeYAML: compose, TargetNode: "n1", SourceTile: tile,
		PublishedPort: 1234, ExposeLAN: true, ComposeCatalogVersion: version,
		BackupAck:  &apps.BackupAck{At: now.Truncate(time.Millisecond), By: "alice"},
		LastStatus: proto.AppStatusRunning, CreatedAt: now, UpdatedAt: now,
	}
	if err := f.appsStore.Create(f.ctx, a); err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
	return a
}

func tileCompose(t *testing.T, cat *catalogsync.Store, id string) string {
	t.Helper()
	tile, ok := cat.Get(id)
	if !ok {
		t.Fatalf("tile %q not in the test catalog", id)
	}
	return tile.ComposeYAML
}

type upgradeRow struct {
	apps.App
	UpgradeAvailable      bool `json:"upgradeAvailable"`
	UpgradeCatalogVersion int  `json:"upgradeCatalogVersion"`
}

func TestAppsUpgradeAvailable_OnListAndGet(t *testing.T) {
	f, cookie, cat, _ := upgradeFixture(t)
	seedUpgradeApp(t, f, "changed", "vw", "vaultwarden", "services: {old: {}}\n", 3)
	seedUpgradeApp(t, f, "current", "jf", "jellyfin", tileCompose(t, cat, "jellyfin"), upgradeCatalogVersion)
	seedUpgradeApp(t, f, "custom", "mine", "", "services: {old: {}}\n", 0)
	seedUpgradeApp(t, f, "withdrawn", "gone", "no-longer-published", "services: {old: {}}\n", 3)
	seedUpgradeApp(t, f, "preview", "pv", "preview-app", "services: {old: {}}\n", 3)
	seedUpgradeApp(t, f, "backwards", "bw", "vaultwarden", "services: {old: {}}\n", upgradeCatalogVersion+2)

	want := map[string]bool{
		"changed": true, "current": false, "custom": false,
		"withdrawn": false, "preview": false, "backwards": false,
	}

	w := f.do(t, http.MethodGet, "/api/apps", "", cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var rows []upgradeRow
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(want) {
		t.Fatalf("list returned %d rows, want %d", len(rows), len(want))
	}
	for _, r := range rows {
		if r.UpgradeAvailable != want[r.ID] {
			t.Errorf("list %s: upgradeAvailable = %v, want %v", r.ID, r.UpgradeAvailable, want[r.ID])
		}
		if r.UpgradeAvailable && r.UpgradeCatalogVersion != upgradeCatalogVersion {
			t.Errorf("list %s: upgradeCatalogVersion = %d, want %d", r.ID, r.UpgradeCatalogVersion, upgradeCatalogVersion)
		}
		if !r.UpgradeAvailable && r.UpgradeCatalogVersion != 0 {
			t.Errorf("list %s: upgradeCatalogVersion = %d on an app with no upgrade", r.ID, r.UpgradeCatalogVersion)
		}
	}
	// The field is present even when false, so the UI never has to tell
	// "no upgrade" from "an api that predates the field" by absence.
	if !strings.Contains(w.Body.String(), `"upgradeAvailable":false`) {
		t.Errorf("list body never says upgradeAvailable:false: %s", w.Body.String())
	}

	for id, wantAvail := range want {
		w := f.do(t, http.MethodGet, "/api/apps/"+id, "", cookie)
		var r upgradeRow
		if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
			t.Fatalf("get %s: %v (%s)", id, err, w.Body.String())
		}
		if r.UpgradeAvailable != wantAvail {
			t.Errorf("get %s: upgradeAvailable = %v, want %v", id, r.UpgradeAvailable, wantAvail)
		}
	}
}

// With no live catalog wired, nothing is upgradable — the embedded catalog is
// never a source for an upgrade.
func TestAppsUpgradeAvailable_FalseWithoutALiveCatalog(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	seedUpgradeApp(t, f, "a", "jellyfin", "jellyfin", "services: {old: {}}\n", 0)

	w := f.do(t, http.MethodGet, "/api/apps/a", "", cookie)
	var r upgradeRow
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.UpgradeAvailable {
		t.Error("upgradeAvailable must be false when the api has no live catalog")
	}
	if w := f.do(t, http.MethodPut, "/api/apps/a/compose", catalogBody, cookie); w.Code != http.StatusConflict {
		t.Errorf("upgrade without a live catalog: want 409, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestAppsUpgrade_Refusals(t *testing.T) {
	f, cookie, _, got := upgradeFixture(t)
	seedUpgradeApp(t, f, "custom", "mine", "", "services: {old: {}}\n", 0)
	seedUpgradeApp(t, f, "withdrawn", "gone", "no-longer-published", "services: {old: {}}\n", 3)
	seedUpgradeApp(t, f, "preview", "pv", "preview-app", "services: {old: {}}\n", 3)
	seedUpgradeApp(t, f, "backwards", "bw", "vaultwarden", "services: {old: {}}\n", upgradeCatalogVersion+2)

	if w := f.do(t, http.MethodPut, "/api/apps/ghost/compose", catalogBody, cookie); w.Code != http.StatusNotFound {
		t.Errorf("unknown app: want 404, got %d (%s)", w.Code, w.Body.String())
	}
	for _, c := range []struct {
		id   string
		says string
	}{
		{"custom", "composeYaml"},
		{"withdrawn", "not in the catalog in effect"},
		{"preview", "preview"},
		{"backwards", "downgrade"},
	} {
		before, _ := f.appsStore.Get(f.ctx, c.id)
		w := f.do(t, http.MethodPut, "/api/apps/"+c.id+"/compose", catalogBody, cookie)
		if w.Code != http.StatusConflict {
			t.Errorf("%s: want 409, got %d (%s)", c.id, w.Code, w.Body.String())
			continue
		}
		if !strings.Contains(w.Body.String(), c.says) {
			t.Errorf("%s: 409 body %q does not say %q", c.id, w.Body.String(), c.says)
		}
		if after, _ := f.appsStore.Get(f.ctx, c.id); after.ComposeYAML != before.ComposeYAML || after.PreviousComposeYAML != "" {
			t.Errorf("%s: a refused upgrade changed the row", c.id)
		}
	}
	waitForJobs(t, f.runner)
	if js, _ := f.jobsStore.ListJobsByKind(f.ctx, "app.upgrade", 10); len(js) != 0 {
		t.Errorf("a refusal must not create a job; found %d", len(js))
	}
	select {
	case cmd := <-got:
		t.Errorf("a refused upgrade reached the agent: %+v", cmd)
	default:
	}
}

// An app already on its tile's compose is the idempotent case: the PUT changes
// nothing, starts no job and answers 200 with the app as GET shows it. This
// replaced #272's "409 already current".
func TestAppsUpgrade_AlreadyCurrentIsANoOp(t *testing.T) {
	f, cookie, cat, got := upgradeFixture(t)
	seedUpgradeApp(t, f, "current", "jf", "jellyfin", tileCompose(t, cat, "jellyfin"), upgradeCatalogVersion)
	before, _ := f.appsStore.Get(f.ctx, "current")

	w := f.do(t, http.MethodPut, "/api/apps/current/compose", catalogBody, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("already current: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	r := decodeBody[revertRow](t, w.Body.String())
	if r.ID != "current" || r.ComposeSHA256 != before.ComposeSHA256 || r.UpgradeAvailable {
		t.Errorf("200 body = %+v, want the app's current state", r)
	}
	assertNoComposeJob(t, f, got)
	if after, _ := f.appsStore.Get(f.ctx, "current"); after.UpdatedAt != before.UpdatedAt || after.PreviousComposeYAML != "" {
		t.Error("a no-op wrote the row")
	}
}

// The compose an upgrade installs comes from the verified store, and the body
// cannot say otherwise: anything besides the source is a 400, not ignored.
// The app ends up on its tile's compose, with its name, node and exposure
// unchanged.
func TestAppsUpgrade_TakesTheComposeFromTheStoreAndKeepsTheAppsIdentity(t *testing.T) {
	f, cookie, cat, got := upgradeFixture(t)
	const id = "01J9ZK3Q0M8X7Y6W5V4T3S2R1P"
	before := seedUpgradeApp(t, f, id, "vw", "vaultwarden", "services: {old: {}}\n", 3)
	want := tileCompose(t, cat, "vaultwarden")

	for _, body := range []string{
		`{"source":"catalog","composeYaml":"services:\n  evil:\n    image: evil/evil:latest\n"}`,
		`{"source":"catalog","name":"other","targetNode":"elsewhere","exposeLan":false,"sourceTile":"jellyfin"}`,
	} {
		if w := f.do(t, http.MethodPut, "/api/apps/"+id+"/compose", body, cookie); w.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d (%s)", body, w.Code, w.Body.String())
		}
	}
	assertNoComposeJob(t, f, got)

	w := f.do(t, http.MethodPut, "/api/apps/"+id+"/compose", catalogBody, cookie)
	if w.Code != http.StatusAccepted {
		t.Fatalf("upgrade: want 202, got %d (%s)", w.Code, w.Body.String())
	}
	job := decodeBody[jobs.Job](t, w.Body.String())
	if job.Kind != "app.upgrade" || strings.Contains(string(job.Spec), "evil") {
		t.Fatalf("job = %s %s, want app.upgrade keyed only by appId", job.Kind, job.Spec)
	}
	if string(job.Spec) != `{"appId":"`+id+`"}` {
		t.Errorf("spec = %s, want only the app id", job.Spec)
	}
	waitForJobs(t, f.runner)
	if j, _ := f.jobsStore.GetJob(f.ctx, job.ID); j == nil || j.Status != jobs.StatusSucceeded {
		t.Fatalf("job did not succeed: %+v", j)
	}

	select {
	case cmd := <-got:
		if cmd.AppID != id || cmd.ComposeYAML != want {
			t.Errorf("agent was sent app %q compose %q, want %q with the tile's compose", cmd.AppID, cmd.ComposeYAML, id)
		}
		if proto.AppProjectName(cmd.AppID) != proto.AppProjectName(id) {
			t.Errorf("compose project changed: %s", proto.AppProjectName(cmd.AppID))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent never received the upgrade's deploy")
	}

	after, _ := f.appsStore.Get(f.ctx, id)
	if after.ComposeYAML != want || after.PreviousComposeYAML != before.ComposeYAML {
		t.Errorf("row compose = %q previous = %q", after.ComposeYAML, after.PreviousComposeYAML)
	}
	if after.ComposeCatalogVersion != upgradeCatalogVersion {
		t.Errorf("row catalog version = %d, want %d", after.ComposeCatalogVersion, upgradeCatalogVersion)
	}
	if after.ID != id || after.Name != "vw" || after.TargetNode != "n1" || !after.ExposeLAN ||
		after.SourceTile != "vaultwarden" || after.BackupAck == nil || after.BackupAck.By != "alice" {
		t.Errorf("identity or an owner choice changed: %+v", after)
	}
	// Re-copied from the tile exactly as install does: gateTileBundle's tiles
	// declare no web port and no budget, so the seeded 1234 must be gone.
	if after.PublishedPort != 0 || after.WebTLS || after.DeployBudgetSeconds != 0 {
		t.Errorf("tile fields not re-copied: port=%d tls=%v budget=%d", after.PublishedPort, after.WebTLS, after.DeployBudgetSeconds)
	}

	w = f.do(t, http.MethodGet, "/api/apps/"+id, "", cookie)
	var r upgradeRow
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.UpgradeAvailable {
		t.Error("upgradeAvailable must clear once the app is on its tile's compose")
	}
	if w := f.do(t, http.MethodPut, "/api/apps/"+id+"/compose", catalogBody, cookie); w.Code != http.StatusOK {
		t.Errorf("repeated upgrade: want 200 no-op, got %d (%s)", w.Code, w.Body.String())
	}
	waitForJobs(t, f.runner)
	if js, _ := f.jobsStore.ListJobsByKind(f.ctx, "app.upgrade", 10); len(js) != 1 {
		t.Errorf("the repeated PUT started a job: %d app.upgrade jobs", len(js))
	}
}

// Install records which catalog the compose came from, so the first upgrade
// check on a fresh install can tell a newer tile from a catalog that went back.
func TestCatalogInstall_RecordsTheCatalogVersion(t *testing.T) {
	f, cookie, _, _ := upgradeFixture(t)
	w := f.do(t, http.MethodPost, "/api/catalog/jellyfin/install", `{"targetNode":"n1"}`, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("install: %d %s", w.Code, w.Body.String())
	}
	created := decodeBody[apps.App](t, w.Body.String())
	got, _ := f.appsStore.Get(f.ctx, created.ID)
	if got.ComposeCatalogVersion != upgradeCatalogVersion {
		t.Errorf("installed catalog version = %d, want %d", got.ComposeCatalogVersion, upgradeCatalogVersion)
	}
	if got.ComposeSHA256 != apps.ComposeHash(got.ComposeYAML) {
		t.Errorf("installed hash does not match the installed compose")
	}
}
