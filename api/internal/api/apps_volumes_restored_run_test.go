package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-903-14 (geekdojo/geekdojo-brain#903): once the restore boot has settled
// the run that wrote the restored generation, the uninstall prompt's
// lastCaptured names that generation for every volume its manifest records as
// captured, and an older retained generation still answers for the rest.
func TestAppVolumes_LastCapturedNamesTheReconciledGeneration(t *testing.T) {
	f, cookie, backup := volumesFixture(t)
	seedVolumesApp(t, f, volULIDLive, "immich")
	ctx := f.ctx

	// R0: an earlier succeeded run of G0 that captured both volumes, with a
	// prune result.
	r0At := time.Now().Add(-48 * time.Hour).UTC().Truncate(time.Millisecond)
	seedBackupRun(t, f, backup, "run-0", "gen-0", volULIDLive, []string{"immich-db", "immich-upload"}, []string{"gen-0"}, r0At)

	// J as the restored database holds it: the job and its run row running,
	// snapshot_db running, no generation.
	const jobID, genID = "job-restored", "gen-restored"
	at := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	started := at.Add(-5 * time.Minute)
	if err := f.jobsStore.CreateJob(ctx, &jobs.Job{ID: jobID, Kind: storage.RunJobKind, Spec: json.RawMessage(`{}`),
		Status: jobs.StatusRunning, CreatedBy: "scheduler", CreatedAt: started, StartedAt: &started}); err != nil {
		t.Fatal(err)
	}
	if err := f.jobsStore.CreateStep(ctx, &jobs.JobStep{JobID: jobID, Seq: 0, Name: "snapshot_db", Status: jobs.StepRunning, StartedAt: &started}); err != nil {
		t.Fatal(err)
	}
	if err := backup.StartRun(ctx, jobID, storage.ReasonScheduled, proto.BackupScopeFull, started); err != nil {
		t.Fatal(err)
	}

	// The generation's manifest: immich-db captured, immich-upload not.
	report := storage.NewAppVolumeReport(storage.AppEnumeration{AppsInstalled: 1, AppsResolved: 1}, []storage.VolumeRecord{
		{App: "immich", AppID: volULIDLive, TileID: "immich", Node: "n1", Volume: "immich-db", Class: "critical", Captured: true, AppRestored: true},
		{App: "immich", AppID: volULIDLive, TileID: "immich", Node: "n1", Volume: "immich-upload", Class: "state", Reason: "test: not captured", AppRestored: true},
	}, 1)
	rep := &storage.RestoreReport{
		ID: "rs-0011223344556677", Phase: storage.RestorePhase, GenerationID: genID, GenerationCreatedAt: at,
		Scope: proto.BackupScopeFull, Complete: report.Complete(), SealedDigest: "d", SealedBytes: 1,
		GenerationJobID: jobID, GenerationAppVolumes: &report,
	}
	rc := storage.NewRestoredRunReconciler(backup, f.jobsStore, slog.New(slog.DiscardHandler), time.Now)
	if err := rc.Reconcile(ctx, rep); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	w := f.do(t, http.MethodGet, "/api/apps/"+volULIDLive+"/volumes", "", cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", w.Code, w.Body.String())
	}
	resp := decodeBody[appVolumesResponse](t, w.Body.String())
	byName := map[string]appVolumeView{}
	for _, v := range resp.Volumes {
		byName[v.Name] = v
	}
	if db := byName["immich-db"].LastCaptured; db == nil || db.GenerationID != genID || !db.At.Equal(at) || db.RunJobID != jobID {
		t.Errorf("immich-db lastCaptured = %+v, want generation %s at %v by run %s", db, genID, at, jobID)
	}
	if up := byName["immich-upload"].LastCaptured; up == nil || up.GenerationID != "gen-0" {
		t.Errorf("immich-upload lastCaptured = %+v, want gen-0, the retained generation that holds it", up)
	}
	if want := fmt.Sprintf("retention state unknown: treating the newest %d generation(s) as retained", proto.BackupRetainGenerations); resp.BackupNote != want {
		t.Errorf("backupNote = %q, want %q", resp.BackupNote, want)
	}
}
