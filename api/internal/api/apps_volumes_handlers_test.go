package api

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/catalogsync"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
	"github.com/nats-io/nats.go"
)

// geekdojo/geekdojo-brain#399 — the uninstall prompt's facts, and the orphan
// path. What is pinned: the volumes come from the LIVE catalog (the sync
// store) and never from the embedded floor; "last captured" is read from a
// retained generation's manifest and a pruned one does not count; the reclaim
// route refuses an offline node, a live app's volume and a malformed name
// before anything reaches an agent; and the DELETE body's deleteVolumes lands
// in the job spec, default false.

const (
	volULIDLive   = "01J6ZK3Q9V8XKX2M5TQ7R4A9BE"
	volULIDOrphan = "01J6ZK3Q9V8XKX2M5TQ7R4A9BF"
)

// volumesTileBundle is a floor bundle whose one tile classifies three volumes.
func volumesTileBundle(version int, id string) tileschema.Bundle {
	b := oneTileBundle(version, id)
	b.Tiles[0].Tile.Volumes = []tileschema.Volume{
		{Name: "immich-db", Backup: tileschema.BackupCritical, Quiesce: tileschema.QuiesceStop},
		{Name: "immich-upload", Backup: tileschema.BackupState, Quiesce: tileschema.QuiesceStop},
		{Name: "immich-model-cache", Backup: tileschema.BackupCache, Quiesce: tileschema.QuiesceNone},
	}
	return b
}

// volumesFixture wires the catalog store, a backup ledger and an online
// compute node into the api fixture.
func volumesFixture(t *testing.T) (*apiFixture, *http.Cookie, *storage.Store) {
	t.Helper()
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	store, err := catalogsync.New(t.TempDir(), stubVerifier{}, volumesTileBundle(7, "immich"))
	if err != nil {
		t.Fatalf("catalog store: %v", err)
	}
	f.srv.SetCatalogSync(store, nil)
	backup, err := storage.OpenStore(f.ctx, filepath.Join(t.TempDir(), "backup.db"))
	if err != nil {
		t.Fatalf("backup store: %v", err)
	}
	t.Cleanup(func() { _ = backup.Close() })
	f.srv.SetBackupStore(backup)
	now := time.Now().UTC()
	if err := f.inv.Insert(f.ctx, &proto.Node{
		ID: "n1", Role: proto.RoleCompute, Hostname: "n1.test", FirstSeen: now, LastSeen: now,
	}); err != nil {
		t.Fatalf("inv insert: %v", err)
	}
	return f, cookie, backup
}

func seedVolumesApp(t *testing.T, f *apiFixture, id, name string) {
	t.Helper()
	now := time.Now().UTC()
	if err := f.appsStore.Create(f.ctx, &apps.App{
		ID: id, Name: name, ComposeYAML: "services: {}", TargetNode: "n1", SourceTile: "immich",
		LastStatus: proto.AppStatusRunning, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
}

// seedBackupRun writes one backup.run to both ledgers: a backup_runs row that
// landed generation gen, a fan_out step whose manifest records `captured` for
// the named volumes of appID (and not-captured for the rest), and a prune step
// listing kept as the generations still on the target.
func seedBackupRun(t *testing.T, f *apiFixture, backup *storage.Store, jobID, gen, appID string, captured []string, kept []string, at time.Time) {
	t.Helper()
	ctx := f.ctx
	if err := f.jobsStore.CreateJob(ctx, &jobs.Job{
		ID: jobID, Kind: "backup.run", Spec: json.RawMessage(`{}`), Status: jobs.StatusSucceeded,
		CreatedBy: "test", CreatedAt: at,
	}); err != nil {
		t.Fatal(err)
	}
	capSet := map[string]bool{}
	for _, v := range captured {
		capSet[v] = true
	}
	type rec struct {
		App      string `json:"app"`
		AppID    string `json:"appId"`
		Tile     string `json:"tile"`
		Volume   string `json:"volume"`
		Class    string `json:"class"`
		Captured bool   `json:"captured"`
		Reason   string `json:"reason,omitempty"`
	}
	var recs []rec
	for _, v := range []struct{ name, class string }{
		{"immich-db", "critical"}, {"immich-upload", "state"},
	} {
		r := rec{App: "immich", AppID: appID, Tile: "immich", Volume: v.name, Class: v.class, Captured: capSet[v.name]}
		if !r.Captured {
			r.Reason = "test: not captured"
		}
		recs = append(recs, r)
	}
	fan, _ := json.Marshal(map[string]any{"report": map[string]any{"volumes": recs}})
	prune, _ := json.Marshal(map[string]any{"kept": kept})
	for seq, st := range []struct {
		name   string
		result json.RawMessage
	}{{"fan_out", fan}, {"prune", prune}} {
		if err := f.jobsStore.CreateStep(ctx, &jobs.JobStep{JobID: jobID, Seq: seq, Name: st.name, Status: jobs.StepPending, Attempt: 1}); err != nil {
			t.Fatal(err)
		}
		if err := f.jobsStore.MarkStepSucceeded(ctx, jobID, seq, 1, st.result, at); err != nil {
			t.Fatal(err)
		}
	}
	if err := backup.StartRun(ctx, jobID, "manual", proto.BackupScopeControlplaneLocal, at); err != nil {
		t.Fatal(err)
	}
	if err := backup.FinishRun(ctx, jobID, storage.RunResult{GenerationID: gen, AppVolumesCaptured: len(captured), At: at}); err != nil {
		t.Fatal(err)
	}
}

func decodeBody[T any](t *testing.T, body string) T {
	t.Helper()
	var out T
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return out
}

// The prompt's list: the live catalog's classification, each volume with when
// it was last captured — and "never" is a null, not an absent key.
func TestAppVolumes_ListsClassesAndLastCapture(t *testing.T) {
	f, cookie, backup := volumesFixture(t)
	seedVolumesApp(t, f, volULIDLive, "immich")

	base := time.Now().Add(-72 * time.Hour).UTC()
	// gen-1 captured both volumes but retention has since pruned it; gen-2
	// (newer) captured only the db. The upload's only capture is in the
	// pruned generation, so it must read as never.
	seedBackupRun(t, f, backup, "run-1", "gen-1", volULIDLive, []string{"immich-db", "immich-upload"}, nil, base)
	seedBackupRun(t, f, backup, "run-2", "gen-2", volULIDLive, []string{"immich-db"}, []string{"gen-2"}, base.Add(24*time.Hour))

	w := f.do(t, http.MethodGet, "/api/apps/"+volULIDLive+"/volumes", "", cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", w.Code, w.Body.String())
	}
	resp := decodeBody[appVolumesResponse](t, w.Body.String())
	if !resp.Classified || resp.TileID != "immich" || !strings.Contains(resp.Catalog, "v7") {
		t.Fatalf("classification: %+v", resp)
	}
	byName := map[string]appVolumeView{}
	for _, v := range resp.Volumes {
		byName[v.Name] = v
	}
	if len(byName) != 3 {
		t.Fatalf("want 3 volumes, got %+v", resp.Volumes)
	}
	db := byName["immich-db"]
	if db.Backup != "critical" || db.DockerName != proto.AppVolumeName(volULIDLive, "immich-db") {
		t.Errorf("db: %+v", db)
	}
	if db.LastCaptured == nil || db.LastCaptured.GenerationID != "gen-2" {
		t.Errorf("db last capture must be the newest RETAINED generation: %+v", db.LastCaptured)
	}
	if up := byName["immich-upload"]; up.LastCaptured != nil {
		t.Errorf("upload's only capture was pruned; must read never, got %+v", up.LastCaptured)
	}
	if c := byName["immich-model-cache"]; c.Backup != "cache" || c.LastCaptured != nil {
		t.Errorf("cache: %+v", c)
	}
	// "never" is an explicit null on the wire.
	if !strings.Contains(w.Body.String(), `"lastCaptured":null`) {
		t.Errorf("never must be an explicit null: %s", w.Body.String())
	}
}

// No backup ledger at all: every volume is never, and the response says why.
func TestAppVolumes_NoBackupsConfiguredSaysSo(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	store, _ := catalogsync.New(t.TempDir(), stubVerifier{}, volumesTileBundle(7, "immich"))
	f.srv.SetCatalogSync(store, nil)
	now := time.Now().UTC()
	_ = f.inv.Insert(f.ctx, &proto.Node{ID: "n1", Role: proto.RoleCompute, Hostname: "n1", FirstSeen: now, LastSeen: now})
	seedVolumesApp(t, f, volULIDLive, "immich")

	w := f.do(t, http.MethodGet, "/api/apps/"+volULIDLive+"/volumes", "", cookie)
	resp := decodeBody[appVolumesResponse](t, w.Body.String())
	if !strings.Contains(resp.BackupNote, "not configured") {
		t.Errorf("backupNote: %q", resp.BackupNote)
	}
	for _, v := range resp.Volumes {
		if v.LastCaptured != nil {
			t.Errorf("%s: %+v", v.Name, v.LastCaptured)
		}
	}
}

// The classification comes from the sync store — the catalog in effect — and
// NOT from the embedded floor. With no sync store the response says the
// volumes are unclassified rather than falling back to catalog.MustLoad().
func TestAppVolumes_NeverReadsTheEmbeddedFloor(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	now := time.Now().UTC()
	_ = f.inv.Insert(f.ctx, &proto.Node{ID: "n1", Role: proto.RoleCompute, Hostname: "n1", FirstSeen: now, LastSeen: now})
	// An app installed from a tile the EMBEDDED catalog does carry.
	if err := f.appsStore.Create(f.ctx, &apps.App{
		ID: volULIDLive, Name: "jelly", ComposeYAML: "services: {}", TargetNode: "n1", SourceTile: "jellyfin",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	w := f.do(t, http.MethodGet, "/api/apps/"+volULIDLive+"/volumes", "", cookie)
	resp := decodeBody[appVolumesResponse](t, w.Body.String())
	if resp.Classified || len(resp.Volumes) != 0 || !strings.Contains(resp.Note, "no live catalog") {
		t.Fatalf("must not classify from the embedded floor: %+v", resp)
	}

	// A custom app (no tile) is unclassified too, and the note names the
	// volume prefix the operator can look for.
	if err := f.appsStore.Create(f.ctx, &apps.App{
		ID: volULIDOrphan, Name: "custom", ComposeYAML: "services: {}", TargetNode: "n1",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	w = f.do(t, http.MethodGet, "/api/apps/"+volULIDOrphan+"/volumes", "", cookie)
	resp = decodeBody[appVolumesResponse](t, w.Body.String())
	if resp.Classified || !strings.Contains(resp.Note, proto.AppProjectName(volULIDOrphan)) {
		t.Fatalf("custom app: %+v", resp)
	}
	if w := f.do(t, http.MethodGet, "/api/apps/nope/volumes", "", cookie); w.Code != http.StatusNotFound {
		t.Errorf("unknown app: want 404, got %d", w.Code)
	}
}

// fakeVolumeAgent answers docker.volumes.list and docker.volumes.remove on
// nodeID with a fixed inventory, recording what it was asked to remove.
type fakeVolumeAgent struct {
	vols    []proto.AppVolumeInfo
	removed []string
	live    []string
}

func (a *fakeVolumeAgent) serve(t *testing.T, nc *nats.Conn, nodeID string) {
	t.Helper()
	s1, err := nc.Subscribe(proto.AppVolumesListSubject(nodeID), func(m *nats.Msg) {
		b, _ := json.Marshal(proto.AppVolumesListAck{OK: true, Volumes: a.vols})
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatal(err)
	}
	s2, err := nc.Subscribe(proto.AppVolumesRemoveSubject(nodeID), func(m *nats.Msg) {
		var cmd proto.AppVolumesRemoveCmd
		_ = json.Unmarshal(m.Data, &cmd)
		a.removed = append(a.removed, cmd.Names...)
		a.live = cmd.LiveAppIDs
		b, _ := json.Marshal(proto.AppVolumesRemoveAck{OK: true, Removed: cmd.Names, Refused: []proto.AppVolumeRefusal{}})
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s1.Unsubscribe(); _ = s2.Unsubscribe() })
}

// Orphans are the node's rasp_ volumes minus the ledger. A live app's volume
// is not an orphan however it looks on the node; an offline node is reported
// as unreachable, not silently empty; and a manifest that once recorded an
// orphan lends it its app name, class and last capture.
func TestOrphanVolumes_LedgerMinusNode(t *testing.T) {
	f, cookie, backup := volumesFixture(t)
	seedVolumesApp(t, f, volULIDLive, "immich")
	stale := time.Now().Add(-10 * time.Minute).UTC()
	_ = f.inv.Insert(f.ctx, &proto.Node{ID: "n2", Role: proto.RoleCompute, Hostname: "n2", FirstSeen: stale, LastSeen: stale})
	_ = f.inv.Insert(f.ctx, &proto.Node{ID: "fw", Role: proto.RoleFirewall, Hostname: "fw", FirstSeen: stale, LastSeen: stale})

	created := time.Date(2026, 8, 23, 10, 0, 0, 0, time.UTC)
	agent := &fakeVolumeAgent{vols: []proto.AppVolumeInfo{
		{Name: proto.AppVolumeName(volULIDLive, "immich-db"), AppID: volULIDLive, Volume: "immich-db", SizeBytes: 10, CreatedAt: created},
		{Name: proto.AppVolumeName(volULIDOrphan, "immich-db"), AppID: volULIDOrphan, Volume: "immich-db", SizeBytes: 20, CreatedAt: created},
		{Name: proto.AppVolumeName(volULIDOrphan, "immich-upload"), AppID: volULIDOrphan, Volume: "immich-upload", SizeBytes: 7 << 30, CreatedAt: created},
	}}
	agent.serve(t, f.nc, "n1")
	// The orphan's former app was backed up once, and that generation is
	// retained: the manifest is the only place its name and class survive.
	seedBackupRun(t, f, backup, "run-1", "gen-1", volULIDOrphan, []string{"immich-db"}, []string{"gen-1"}, time.Now().Add(-time.Hour).UTC())

	w := f.do(t, http.MethodGet, "/api/volumes/orphans", "", cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", w.Code, w.Body.String())
	}
	resp := decodeBody[orphanVolumesResponse](t, w.Body.String())
	if resp.NodesAsked != 2 {
		t.Errorf("nodesAsked: %d, want 2 (compute nodes only; the firewall hosts no apps)", resp.NodesAsked)
	}
	if len(resp.Unreachable) != 1 || resp.Unreachable[0].NodeID != "n2" {
		t.Errorf("unreachable: %+v", resp.Unreachable)
	}
	if len(resp.Volumes) != 2 {
		t.Fatalf("orphans: %+v", resp.Volumes)
	}
	for _, v := range resp.Volumes {
		if v.AppID != volULIDOrphan {
			t.Errorf("a live app's volume was listed as an orphan: %+v", v)
		}
		if v.NodeID != "n1" || v.AppName != "immich" || v.TileID != "immich" {
			t.Errorf("manifest meta: %+v", v)
		}
		switch v.Volume {
		case "immich-db":
			if v.Backup != "critical" || v.LastCaptured == nil || v.LastCaptured.GenerationID != "gen-1" {
				t.Errorf("db: %+v", v)
			}
		case "immich-upload":
			if v.Backup != "state" || v.LastCaptured != nil || v.SizeBytes != 7<<30 {
				t.Errorf("upload: %+v", v)
			}
		}
	}
}

// Reclaim: refused before anything is sent for an offline node, a live app's
// volume, a malformed name, a name outside the prefix; and on the happy path
// the agent is handed the whole ledger as LiveAppIDs.
func TestReclaimOrphanVolumes_Refusals(t *testing.T) {
	f, cookie, _ := volumesFixture(t)
	seedVolumesApp(t, f, volULIDLive, "immich")
	stale := time.Now().Add(-10 * time.Minute).UTC()
	_ = f.inv.Insert(f.ctx, &proto.Node{ID: "n2", Role: proto.RoleCompute, Hostname: "n2", FirstSeen: stale, LastSeen: stale})
	agent := &fakeVolumeAgent{}
	agent.serve(t, f.nc, "n1")
	orphan := proto.AppVolumeName(volULIDOrphan, "immich-db")

	post := func(body string) (int, string) {
		w := f.do(t, http.MethodPost, "/api/volumes/orphans/reclaim", body, cookie)
		return w.Code, w.Body.String()
	}

	// Offline node: 409 naming it, never queued.
	if code, body := post(`{"nodeId":"n2","names":["` + orphan + `"]}`); code != http.StatusConflict || !strings.Contains(body, "n2") || !strings.Contains(body, "offline") {
		t.Errorf("offline node: %d %s", code, body)
	}
	// Unknown node, wrong role, empty names, unknown field.
	if code, _ := post(`{"nodeId":"ghost","names":["` + orphan + `"]}`); code != http.StatusNotFound {
		t.Errorf("unknown node: %d", code)
	}
	if code, _ := post(`{"nodeId":"n1","names":[]}`); code != http.StatusBadRequest {
		t.Errorf("empty names: %d", code)
	}
	if code, _ := post(`{"nodeId":"n1","names":["` + orphan + `"],"force":true}`); code != http.StatusBadRequest {
		t.Errorf("unknown field: %d", code)
	}
	// A live app's volume, a malformed name and a foreign name each refuse the
	// WHOLE request — even beside a valid orphan — and nothing reaches the agent.
	for _, bad := range []string{proto.AppVolumeName(volULIDLive, "immich-db"), "rasp_abc_data", "myproj_data"} {
		code, body := post(`{"nodeId":"n1","names":["` + orphan + `","` + bad + `"]}`)
		if code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d (%s)", bad, code, body)
		}
		resp := decodeBody[reclaimResponse](t, body)
		if resp.OK || len(resp.Removed) != 0 || len(resp.Refused) != 1 || resp.Refused[0].Name != bad {
			t.Errorf("%s: %+v", bad, resp)
		}
	}
	if len(agent.removed) != 0 {
		t.Fatalf("a refused request reached the agent: %v", agent.removed)
	}

	// Happy path: the orphan goes, and the agent is handed the ledger.
	code, body := post(`{"nodeId":"n1","names":["` + orphan + `"]}`)
	if code != http.StatusOK {
		t.Fatalf("reclaim: %d %s", code, body)
	}
	resp := decodeBody[reclaimResponse](t, body)
	if !resp.OK || len(resp.Removed) != 1 || resp.Removed[0] != orphan {
		t.Errorf("reclaim response: %+v", resp)
	}
	if len(agent.removed) != 1 || agent.removed[0] != orphan {
		t.Errorf("agent asked to remove %v", agent.removed)
	}
	if len(agent.live) != 1 || agent.live[0] != volULIDLive {
		t.Errorf("agent must be handed the ledger as LiveAppIDs, got %v", agent.live)
	}
}

// A node whose agent has no docker verbs (no runtime) is a 409, not a hang.
func TestReclaimOrphanVolumes_NoRuntimeIsARefusal(t *testing.T) {
	f, cookie, _ := volumesFixture(t)
	w := f.do(t, http.MethodPost, "/api/volumes/orphans/reclaim",
		`{"nodeId":"n1","names":["`+proto.AppVolumeName(volULIDOrphan, "x")+`"]}`, cookie)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "no container runtime") {
		t.Fatalf("want 409 no runtime, got %d %s", w.Code, w.Body.String())
	}
}

// DELETE /api/apps/{id}: the body's deleteVolumes lands in the job spec; no
// body means false; an unknown field is refused.
func TestDeleteApp_BodyCarriesDeleteVolumes(t *testing.T) {
	f, cookie, _ := volumesFixture(t)
	seedVolumesApp(t, f, volULIDLive, "immich")
	// The fixture's runner knows no workflows; Submit refuses an unknown kind.
	f.runner.Register(apps.DeleteWorkflow(f.appsStore, f.inv, f.nc, nil))

	w := f.do(t, http.MethodDelete, "/api/apps/"+volULIDLive, "", cookie)
	if w.Code != http.StatusAccepted {
		t.Fatalf("no body: want 202, got %d (%s)", w.Code, w.Body.String())
	}
	job := decodeBody[jobs.Job](t, w.Body.String())
	var spec apps.DeleteSpec
	if err := json.Unmarshal(job.Spec, &spec); err != nil || spec.AppID != volULIDLive || spec.DeleteVolumes {
		t.Fatalf("spec: %s (%v) — deleteVolumes must default to false", job.Spec, err)
	}

	w = f.do(t, http.MethodDelete, "/api/apps/"+volULIDLive, `{"deleteVolumes":true}`, cookie)
	if w.Code != http.StatusAccepted {
		t.Fatalf("with body: want 202, got %d (%s)", w.Code, w.Body.String())
	}
	job = decodeBody[jobs.Job](t, w.Body.String())
	if err := json.Unmarshal(job.Spec, &spec); err != nil || !spec.DeleteVolumes {
		t.Fatalf("spec: %s (%v) — deleteVolumes:true did not land", job.Spec, err)
	}

	if w := f.do(t, http.MethodDelete, "/api/apps/"+volULIDLive, `{"deleteVolume":true}`, cookie); w.Code != http.StatusBadRequest {
		t.Errorf("misspelled field: want 400, got %d (%s)", w.Code, w.Body.String())
	}
	if w := f.do(t, http.MethodDelete, "/api/apps/"+volULIDLive, `{"deleteVolumes":`, cookie); w.Code != http.StatusBadRequest {
		t.Errorf("bad json: want 400, got %d", w.Code)
	}
}
