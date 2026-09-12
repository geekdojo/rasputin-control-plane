package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// PUT /api/apps/{id}/compose and the dropped-volume gate
// (geekdojo/geekdojo-brain#412): the 409 an owner gets at once, its shape,
// deleteVolumes' rules, the no-op that ignores them, and the job's own gate
// standing when the request's check had no answer.

const gateID = "01J9ZK3Q0M8X7Y6W5V4T3S2R1Q"

func gateVolume(key string) string { return proto.AppVolumeName(gateID, key) }

// gateNode is a fake agent on node n3 answering every verb a compose change
// sends it.
type gateNode struct {
	mu sync.Mutex
	// onDisk is what docker.volumes.list reports (the catalog upgrade's
	// advisory check reads it).
	onDisk []proto.AppVolumeInfo
	// dropped is what docker.volumes.check reports.
	dropped []proto.AppDroppedVolume
	// failFirstChecks makes that many checks answer not OK — the request's
	// advisory check getting no answer while the job's does.
	failFirstChecks int
	// listFails makes docker.volumes.list answer not OK.
	listFails bool
	deployOK  bool
	checks    int
	events    []string
	drops     [][]string
}

func (g *gateNode) log() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return strings.Join(g.events, ",")
}

func (g *gateNode) set(fn func()) {
	g.mu.Lock()
	defer g.mu.Unlock()
	fn()
}

func (g *gateNode) dropCalls() [][]string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([][]string(nil), g.drops...)
}

func newGateNode(t *testing.T, f *apiFixture) *gateNode {
	t.Helper()
	now := time.Now().UTC()
	if err := f.inv.Insert(f.ctx, &proto.Node{ID: "n3", Role: proto.RoleCompute, Hostname: "n3.test", FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	g := &gateNode{deployOK: true}
	answer := func(subject string, fn func(m *nats.Msg) any) {
		sub, err := f.nc.Subscribe(subject, func(m *nats.Msg) {
			out := fn(m)
			if out == nil {
				return
			}
			b, _ := json.Marshal(out)
			_ = m.Respond(b)
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sub.Unsubscribe() })
	}
	answer(proto.AppVolumesListSubject("n3"), func(*nats.Msg) any {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.events = append(g.events, "list")
		if g.listFails {
			return proto.AppVolumesListAck{OK: false, Detail: "docker volume ls: exit status 1", Volumes: []proto.AppVolumeInfo{}}
		}
		return proto.AppVolumesListAck{OK: true, Volumes: g.onDisk}
	})
	answer(proto.AppVolumesCheckSubject("n3"), func(*nats.Msg) any {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.checks++
		g.events = append(g.events, "check")
		if g.checks <= g.failFirstChecks {
			return proto.AppVolumesCheckAck{OK: false, Detail: "docker compose config --volumes: exit status 1", Declared: []string{}, Dropped: []proto.AppDroppedVolume{}}
		}
		d := g.dropped
		if d == nil {
			d = []proto.AppDroppedVolume{}
		}
		return proto.AppVolumesCheckAck{OK: true, Declared: []string{}, Dropped: d}
	})
	answer(proto.AppPullSubject("n3"), func(*nats.Msg) any {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.events = append(g.events, "pull")
		return proto.AppPullAck{OK: true}
	})
	answer(proto.AppDeploySubject("n3"), func(*nats.Msg) any {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.events = append(g.events, "deploy")
		if !g.deployOK {
			return proto.AppDeployAck{OK: false, Status: proto.AppStatusFailed, Detail: "port is already allocated"}
		}
		return proto.AppDeployAck{OK: true, Status: proto.AppStatusRunning}
	})
	answer(proto.AppVolumesDropSubject("n3"), func(m *nats.Msg) any {
		var cmd proto.AppVolumesDropCmd
		_ = json.Unmarshal(m.Data, &cmd)
		g.mu.Lock()
		defer g.mu.Unlock()
		g.events = append(g.events, "drop")
		g.drops = append(g.drops, cmd.Names)
		return proto.AppVolumesRemoveAck{OK: true, Removed: cmd.Names, Refused: []proto.AppVolumeRefusal{}}
	})
	return g
}

// seedGateApp puts an app on n3 under gateID: "catalog", a jellyfin catalog
// app on an older compose; "custom", a custom app; "custom-with-previous", a
// custom app edited once, so it has a previous compose to re-apply.
func seedGateApp(t *testing.T, f *apiFixture, kind string) {
	t.Helper()
	now := time.Now().UTC()
	a := &apps.App{ID: gateID, Name: "gated", TargetNode: "n3", LastStatus: proto.AppStatusRunning, CreatedAt: now, UpdatedAt: now}
	switch kind {
	case "catalog":
		a.SourceTile, a.ComposeYAML, a.ComposeCatalogVersion = "jellyfin", "services: {old: {}}\n", 3
	default:
		a.ComposeYAML = customOld
	}
	if err := f.appsStore.Create(f.ctx, a); err != nil {
		t.Fatal(err)
	}
	if kind == "custom-with-previous" {
		if err := f.appsStore.EditCompose(f.ctx, gateID, apps.ComposeHash(customOld), customNew, now); err != nil {
			t.Fatal(err)
		}
	}
}

// gateCase is one variant's PUT, against an app seeded for it.
type gateCase struct {
	name, seed, kind string
	body             func(deleteVolumes []string) string
}

func gateCases(t *testing.T) []gateCase {
	withDelete := func(base map[string]any, dv []string) string {
		if dv != nil {
			base["deleteVolumes"] = dv
		}
		b, err := json.Marshal(base)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	return []gateCase{
		{"upgrade", "catalog", "app.upgrade", func(dv []string) string { return withDelete(map[string]any{"source": "catalog"}, dv) }},
		{"edit", "custom", "app.edit", func(dv []string) string {
			return withDelete(map[string]any{"composeYaml": "services:\n  web:\n    image: me/web:3\n"}, dv)
		}},
		{"revert", "custom-with-previous", "app.revert", func(dv []string) string {
			return withDelete(map[string]any{"sha256": apps.ComposeHash(customOld)}, dv)
		}},
	}
}

// renamed puts the app's renamed-away volume where each variant's advisory
// check finds it: the node's listing (the upgrade compares it with the tile's
// declarations, and jellyfin declares jellyfin-config and jellyfin-cache) and
// the node's compose check (edit and re-apply).
func (g *gateNode) renamed(keys ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.onDisk = []proto.AppVolumeInfo{{Name: gateVolume("jellyfin-config"), AppID: gateID, Volume: "jellyfin-config"}}
	g.dropped = nil
	for _, k := range keys {
		g.onDisk = append(g.onDisk, proto.AppVolumeInfo{Name: gateVolume(k), AppID: gateID, Volume: k})
		g.dropped = append(g.dropped, proto.AppDroppedVolume{Name: gateVolume(k), Volume: k})
	}
}

func assertNoJobOfKind(t *testing.T, f *apiFixture, kind string) {
	t.Helper()
	f.runner.Wait()
	if js, _ := f.jobsStore.ListJobsByKind(f.ctx, kind, 10); len(js) != 0 {
		t.Errorf("expected no %s job, found %d", kind, len(js))
	}
}

// A renamed key, and a dropped service's volume, are a 409 at once, for every
// variant, listing each volume by name and key with no job started and nothing
// asked of the node beyond the check.
func TestAppsComposeVolumeGate_DroppedVolumesAre409WithTheList(t *testing.T) {
	for _, c := range gateCases(t) {
		t.Run(c.name, func(t *testing.T) {
			f, cookie, _, _ := upgradeFixture(t)
			g := newGateNode(t, f)
			seedGateApp(t, f, c.seed)
			g.renamed("jellyfin-data", "worker-cache")

			w := f.do(t, http.MethodPut, "/api/apps/"+gateID+"/compose", c.body(nil), cookie)
			if w.Code != http.StatusConflict {
				t.Fatalf("want 409, got %d (%s)", w.Code, w.Body.String())
			}
			resp := decodeBody[volumeGateResponse](t, w.Body.String())
			if len(resp.DroppedVolumes) != 2 ||
				resp.DroppedVolumes[0].Name != gateVolume("jellyfin-data") || resp.DroppedVolumes[0].Volume != "jellyfin-data" ||
				resp.DroppedVolumes[1].Name != gateVolume("worker-cache") || resp.DroppedVolumes[1].Volume != "worker-cache" {
				t.Errorf("droppedVolumes = %+v", resp.DroppedVolumes)
			}
			if resp.NotDropped == nil || len(resp.NotDropped) != 0 || !strings.Contains(resp.Error, gateVolume("jellyfin-data")) {
				t.Errorf("response = %s", w.Body.String())
			}
			if !strings.Contains(w.Body.String(), `"lastCaptured":null`) {
				t.Errorf("lastCaptured must be present as null for a volume never captured: %s", w.Body.String())
			}
			assertNoJobOfKind(t, f, c.kind)
			if got := g.log(); strings.Contains(got, "pull") || strings.Contains(got, "deploy") || strings.Contains(got, "drop") {
				t.Errorf("node was asked %q", got)
			}
		})
	}
}

// Naming exactly the dropped set proceeds: 202, the job's spec records the
// names, and the node deletes them only after the deploy answered.
func TestAppsComposeVolumeGate_TheExactSetProceedsAndDeletesAfterUp(t *testing.T) {
	for _, c := range gateCases(t) {
		t.Run(c.name, func(t *testing.T) {
			f, cookie, _, _ := upgradeFixture(t)
			g := newGateNode(t, f)
			seedGateApp(t, f, c.seed)
			g.renamed("jellyfin-data", "worker-cache")

			w := f.do(t, http.MethodPut, "/api/apps/"+gateID+"/compose", c.body([]string{gateVolume("worker-cache"), gateVolume("jellyfin-data")}), cookie)
			if w.Code != http.StatusAccepted {
				t.Fatalf("want 202, got %d (%s)", w.Code, w.Body.String())
			}
			job := decodeBody[jobs.Job](t, w.Body.String())
			if job.Kind != c.kind || !strings.Contains(string(job.Spec), `"deleteVolumes":["`+gateVolume("jellyfin-data")+`","`+gateVolume("worker-cache")+`"]`) {
				t.Errorf("job = %s %s", job.Kind, job.Spec)
			}
			f.runner.Wait()
			if j, _ := f.jobsStore.GetJob(f.ctx, job.ID); j == nil || j.Status != jobs.StatusSucceeded {
				t.Fatalf("job did not succeed: %+v", j)
			}
			log := g.log()
			if !strings.HasSuffix(log, "check,pull,deploy,drop") {
				t.Errorf("node was asked %q, want the drop last, after the deploy", log)
			}
			if drops := g.dropCalls(); len(drops) != 1 || strings.Join(drops[0], ",") != gateVolume("jellyfin-data")+","+gateVolume("worker-cache") {
				t.Errorf("drops = %v", drops)
			}
		})
	}
}

// A volume only added drops nothing: 202 and no drop.
func TestAppsComposeVolumeGate_AnAddedVolumeProceeds(t *testing.T) {
	for _, c := range gateCases(t) {
		t.Run(c.name, func(t *testing.T) {
			f, cookie, _, _ := upgradeFixture(t)
			g := newGateNode(t, f)
			seedGateApp(t, f, c.seed)
			g.renamed()

			w := f.do(t, http.MethodPut, "/api/apps/"+gateID+"/compose", c.body(nil), cookie)
			if w.Code != http.StatusAccepted {
				t.Fatalf("want 202, got %d (%s)", w.Code, w.Body.String())
			}
			f.runner.Wait()
			if got := g.log(); strings.Contains(got, "drop") || !strings.Contains(got, "deploy") {
				t.Errorf("node was asked %q", got)
			}
		})
	}
}

// deleteVolumes' rules: another app's volume, an anonymous one, a name that is
// not ours, a duplicate are 400; a partial set and a still-declared volume are
// 409 — the latter listed in notDropped. No job either way.
func TestAppsComposeVolumeGate_DeleteVolumesRefusals(t *testing.T) {
	for _, c := range gateCases(t) {
		t.Run(c.name, func(t *testing.T) {
			f, cookie, _, _ := upgradeFixture(t)
			g := newGateNode(t, f)
			seedGateApp(t, f, c.seed)
			g.renamed("jellyfin-data", "worker-cache")
			put := func(dv []string) *httpResult {
				w := f.do(t, http.MethodPut, "/api/apps/"+gateID+"/compose", c.body(dv), cookie)
				return &httpResult{code: w.Code, body: w.Body.String()}
			}
			for name, dv := range map[string][]string{
				"foreign":   {gateVolume("jellyfin-data"), gateVolume("worker-cache"), proto.AppVolumeName("01J9ZK3Q0M8X7Y6W5V4T3S2R1B", "data")},
				"anonymous": {strings.Repeat("ab", 32)},
				"not ours":  {"myproj_data"},
				"twice":     {gateVolume("jellyfin-data"), gateVolume("jellyfin-data"), gateVolume("worker-cache")},
			} {
				if r := put(dv); r.code != http.StatusBadRequest {
					t.Errorf("%s: want 400, got %d (%s)", name, r.code, r.body)
				}
			}
			r := put([]string{gateVolume("jellyfin-data")})
			if r.code != http.StatusConflict {
				t.Fatalf("partial set: want 409, got %d (%s)", r.code, r.body)
			}
			if resp := decodeBody[volumeGateResponse](t, r.body); len(resp.DroppedVolumes) != 2 || len(resp.NotDropped) != 0 {
				t.Errorf("partial set response = %s", r.body)
			}
			r = put([]string{gateVolume("jellyfin-data"), gateVolume("worker-cache"), gateVolume("jellyfin-config")})
			if r.code != http.StatusConflict {
				t.Fatalf("still declared: want 409, got %d (%s)", r.code, r.body)
			}
			if resp := decodeBody[volumeGateResponse](t, r.body); strings.Join(resp.NotDropped, ",") != gateVolume("jellyfin-config") {
				t.Errorf("still-declared response = %s", r.body)
			}
			assertNoJobOfKind(t, f, c.kind)
			if got := g.log(); strings.Contains(got, "drop") || strings.Contains(got, "pull") {
				t.Errorf("node was asked %q", got)
			}
		})
	}
}

type httpResult struct {
	code int
	body string
}

// A failed `up` deletes nothing.
func TestAppsComposeVolumeGate_AFailedUpDeletesNothing(t *testing.T) {
	for _, c := range gateCases(t) {
		t.Run(c.name, func(t *testing.T) {
			f, cookie, _, _ := upgradeFixture(t)
			g := newGateNode(t, f)
			seedGateApp(t, f, c.seed)
			g.renamed("jellyfin-data")
			g.set(func() { g.deployOK = false })

			w := f.do(t, http.MethodPut, "/api/apps/"+gateID+"/compose", c.body([]string{gateVolume("jellyfin-data")}), cookie)
			if w.Code != http.StatusAccepted {
				t.Fatalf("want 202, got %d (%s)", w.Code, w.Body.String())
			}
			job := decodeBody[jobs.Job](t, w.Body.String())
			f.runner.Wait()
			if j, _ := f.jobsStore.GetJob(f.ctx, job.ID); j == nil || j.Status != jobs.StatusFailed {
				t.Fatalf("job = %+v, want failed at the push", j)
			}
			if got := g.log(); strings.Contains(got, "drop") {
				t.Errorf("node was asked %q: a failed up deleted volumes", got)
			}
		})
	}
}

// The request's check gets no answer — the upgrade's node listing fails, and
// the edit's and re-apply's compose check fails — so the PUT does
// not refuse, and the job's own check does: it fails at the pull naming the
// volume, having pulled, written and deleted nothing.
func TestAppsComposeVolumeGate_TheJobRefusesWhenTheRequestCouldNotCheck(t *testing.T) {
	for _, c := range gateCases(t) {
		t.Run(c.name, func(t *testing.T) {
			f, cookie, _, _ := upgradeFixture(t)
			g := newGateNode(t, f)
			seedGateApp(t, f, c.seed)
			g.renamed("jellyfin-data")
			g.set(func() {
				g.listFails = true
				if c.seed != "catalog" {
					g.failFirstChecks = 1
				}
			})
			before, _ := f.appsStore.Get(f.ctx, gateID)

			w := f.do(t, http.MethodPut, "/api/apps/"+gateID+"/compose", c.body(nil), cookie)
			if w.Code != http.StatusAccepted {
				t.Fatalf("want 202 when the request's check has no answer, got %d (%s)", w.Code, w.Body.String())
			}
			job := decodeBody[jobs.Job](t, w.Body.String())
			f.runner.Wait()
			j, _ := f.jobsStore.GetJob(f.ctx, job.ID)
			if j == nil || j.Status != jobs.StatusFailed || !strings.Contains(j.Error, gateVolume("jellyfin-data")) {
				t.Fatalf("job = %+v, want failed naming the dropped volume", j)
			}
			if got := g.log(); strings.Contains(got, "pull") || strings.Contains(got, "deploy") || strings.Contains(got, "drop") {
				t.Errorf("node was asked %q", got)
			}
			after, _ := f.appsStore.Get(f.ctx, gateID)
			if after.ComposeSHA256 != before.ComposeSHA256 || after.PreviousComposeYAML != before.PreviousComposeYAML {
				t.Error("a refused job wrote the row")
			}
		})
	}
}

// A body naming what is installed is the 200 no-op whatever deleteVolumes
// says — even names that would be a 400 on a real change — and the node is
// not asked anything.
func TestAppsComposeVolumeGate_ANoOpIs200RegardlessOfDeleteVolumes(t *testing.T) {
	f, cookie, cat, _ := upgradeFixture(t)
	g := newGateNode(t, f)
	g.renamed("jellyfin-data")
	now := time.Now().UTC()
	if err := f.appsStore.Create(f.ctx, &apps.App{ID: gateID, Name: "gated", TargetNode: "n3", SourceTile: "jellyfin",
		ComposeYAML: tileCompose(t, cat, "jellyfin"), ComposeCatalogVersion: upgradeCatalogVersion,
		LastStatus: proto.AppStatusRunning, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	const customID = "01J9ZK3Q0M8X7Y6W5V4T3S2R1R"
	if err := f.appsStore.Create(f.ctx, &apps.App{ID: customID, Name: "mine", TargetNode: "n3", ComposeYAML: customOld,
		LastStatus: proto.AppStatusRunning, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	garbage := []string{"myproj_data", strings.Repeat("ab", 32), gateVolume("jellyfin-data")}
	for path, body := range map[string]map[string]any{
		"/api/apps/" + gateID + "/compose":   {"source": "catalog", "deleteVolumes": garbage},
		"/api/apps/" + gateID + "/compose#h": {"sha256": apps.ComposeHash(tileCompose(t, cat, "jellyfin")), "deleteVolumes": garbage},
		"/api/apps/" + customID + "/compose": {"composeYaml": customOld, "deleteVolumes": garbage},
	} {
		b, _ := json.Marshal(body)
		w := f.do(t, http.MethodPut, strings.TrimSuffix(path, "#h"), string(b), cookie)
		if w.Code != http.StatusOK {
			t.Errorf("%s %s: want 200, got %d (%s)", path, b, w.Code, w.Body.String())
		}
	}
	for _, kind := range []string{"app.upgrade", "app.edit", "app.revert"} {
		assertNoJobOfKind(t, f, kind)
	}
	if got := g.log(); got != "" {
		t.Errorf("a no-op asked the node %q", got)
	}
}

// The 409 carries each dropped volume's backup class and last capture when a
// retained backup manifest recorded it — the only record of what a volume the
// new compose no longer declares held — and leaves them absent when none did.
func TestAppsComposeVolumeGate_TheListCarriesBackupClassWhenKnown(t *testing.T) {
	f, cookie, _, _ := upgradeFixture(t)
	g := newGateNode(t, f)
	seedGateApp(t, f, "custom")
	at := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	seedBackupRun(t, f, f.srv.backup, "job-backup-1", "gen-1", gateID, []string{"immich-db"}, []string{"gen-1"}, at)
	g.renamed("immich-db", "never-backed-up")

	w := f.do(t, http.MethodPut, "/api/apps/"+gateID+"/compose", composeYAMLBody(t, "services:\n  web:\n    image: me/web:3\n"), cookie)
	if w.Code != http.StatusConflict {
		t.Fatalf("want 409, got %d (%s)", w.Code, w.Body.String())
	}
	resp := decodeBody[volumeGateResponse](t, w.Body.String())
	if len(resp.DroppedVolumes) != 2 {
		t.Fatalf("droppedVolumes = %+v", resp.DroppedVolumes)
	}
	db, never := resp.DroppedVolumes[0], resp.DroppedVolumes[1]
	if db.Volume != "immich-db" || db.Backup != "critical" || db.LastCaptured == nil || db.LastCaptured.GenerationID != "gen-1" {
		t.Errorf("immich-db = %+v, want critical, captured in gen-1", db)
	}
	if never.Volume != "never-backed-up" || never.Backup != "" || never.LastCaptured != nil {
		t.Errorf("never-backed-up = %+v, want no class and no capture", never)
	}
}
