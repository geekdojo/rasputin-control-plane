package storage

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// geekdojo/geekdojo-brain#903: the restore boot settles the backup run that
// wrote the restored generation from that generation's manifest, before the
// jobs runner's Recover can fail it as "restarted mid-job".

const (
	recJobID  = "job-gen-1"
	recGenID  = "gen-20261031-full-jobgen1"
	recRSID   = "rs-0123456789abcdef"
	recDigest = "sha256:feedface"
	recBytes  = uint64(40960)
)

// reconcileFixture is the restored database as the snapshot caught it: real
// SQLite storage and jobs stores on one file, and a captured logger.
type reconcileFixture struct {
	st   *Store
	js   *jobs.Store
	logs *bytes.Buffer
	rc   *RestoredRunReconciler
	at   time.Time // the manifest's createdAt
}

func newReconcileFixture(t *testing.T, at time.Time) *reconcileFixture {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "rasputin.db")
	st, err := OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	js, err := jobs.OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.Close() })
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	clock := func() time.Time { return at.Add(2 * time.Hour) }
	return &reconcileFixture{st: st, js: js, logs: &logs, rc: NewRestoredRunReconciler(st, js, logger, clock), at: at}
}

// seedJob writes a job row of kind with its steps; the last step is running.
func (f *reconcileFixture) seedJob(t *testing.T, id, kind string, steps ...string) {
	t.Helper()
	ctx := context.Background()
	started := f.at.Add(-5 * time.Minute)
	if err := f.js.CreateJob(ctx, &jobs.Job{ID: id, Kind: kind, Spec: json.RawMessage(`{}`), Status: jobs.StatusRunning,
		CreatedBy: "scheduler", CreatedAt: started, StartedAt: &started}); err != nil {
		t.Fatal(err)
	}
	for seq, name := range steps {
		if err := f.js.CreateStep(ctx, &jobs.JobStep{JobID: id, Seq: seq, Name: name, Status: jobs.StepRunning, StartedAt: &started}); err != nil {
			t.Fatal(err)
		}
		if seq < len(steps)-1 {
			if err := f.js.MarkStepSucceeded(ctx, id, seq, 1, json.RawMessage(`{"ok":true}`), started); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func (f *reconcileFixture) seedRunRow(t *testing.T, id string) {
	t.Helper()
	if err := f.st.StartRun(context.Background(), id, ReasonScheduled, proto.BackupScopeFull, f.at.Add(-5*time.Minute)); err != nil {
		t.Fatal(err)
	}
}

// seedCaptured is the restored-DB shape at capture time: the backup.run job
// running with validate and preflight done and snapshot_db running, and its
// backup_runs row running with no generation.
func (f *reconcileFixture) seedCaptured(t *testing.T) {
	t.Helper()
	f.seedJob(t, recJobID, RunJobKind, "validate", "preflight", "snapshot_db")
	f.seedRunRow(t, recJobID)
}

func (f *reconcileFixture) report(vols AppVolumeReport) *RestoreReport {
	return &RestoreReport{
		ID: recRSID, Phase: RestorePhase, GenerationID: recGenID, GenerationCreatedAt: f.at,
		Scope: proto.BackupScopeFull, Complete: vols.Complete(), SealedDigest: recDigest, SealedBytes: recBytes,
		GenerationJobID: recJobID, GenerationAppVolumes: &vols,
	}
}

// ledgerSnapshot is everything Reconcile could write for one job id.
type ledgerSnapshot struct {
	Run    *BackupRun
	Job    *jobs.Job
	Steps  []*jobs.JobStep
	Events []*jobs.JobEvent
}

func (f *reconcileFixture) snapshot(t *testing.T, id string) ledgerSnapshot {
	t.Helper()
	ctx := context.Background()
	run, err := f.st.GetRun(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	snap := f.jobsSnapshot(t, id)
	snap.Run = run
	return snap
}

func (f *reconcileFixture) jobsSnapshot(t *testing.T, id string) ledgerSnapshot {
	t.Helper()
	ctx := context.Background()
	j, err := f.js.GetJob(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	steps, err := f.js.ListSteps(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	evs, err := f.js.ListEvents(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return ledgerSnapshot{Job: j, Steps: steps, Events: evs}
}

// records parses the captured JSON log lines.
func (f *reconcileFixture) records(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(f.logs.Bytes()))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("log line %q: %v", sc.Text(), err)
		}
		out = append(out, m)
	}
	return out
}

// record returns the one record at level whose message contains msg.
func (f *reconcileFixture) record(t *testing.T, level, msg string) map[string]any {
	t.Helper()
	var found []map[string]any
	for _, r := range f.records(t) {
		if r["level"] == level && strings.Contains(r["msg"].(string), msg) {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want one %s record containing %q, got %d in:\n%s", level, msg, len(found), f.logs.String())
	}
	return found[0]
}

func wantFields(t *testing.T, rec map[string]any, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got, _ := rec[k].(string); got != v {
			t.Errorf("log field %s = %q, want %q (record %v)", k, got, v, rec)
		}
	}
}

// appVol is one fan-out record for an app; captured, failed with a reason,
// or neither (skipped with a reason).
func appVol(appID, app, volume, class string, captured, failed bool, reason string) VolumeRecord {
	return VolumeRecord{App: app, AppID: appID, TileID: app, Node: "n-1", Volume: volume, Class: class,
		Captured: captured, Failed: failed, Reason: reason, AppRestored: true}
}

func volReport(apps int, recs ...VolumeRecord) AppVolumeReport {
	return NewAppVolumeReport(AppEnumeration{AppsInstalled: apps, AppsResolved: apps, Catalog: "test"}, recs, 1)
}

// The two installed apps the derivation cases read, and their tiles.
func reconcileApps() ([]*apps.App, fakeTiles) {
	installed := []*apps.App{
		testApp("app-vw", "vaultwarden", "n-1", "vaultwarden"),
		testApp("app-im", "immich", "n-1", "immich"),
	}
	tiles := fakeTiles{
		"vaultwarden": testTile("vaultwarden", vol("vaultwarden-data", tileschema.BackupCritical, tileschema.QuiesceStop)),
		"immich": testTile("immich",
			vol("immich-upload", tileschema.BackupState, tileschema.QuiesceStop),
			vol("immich-library", tileschema.BackupBulk, tileschema.QuiesceNone)),
	}
	return installed, tiles
}

// statesAt derives every app's state over the fixture's ledger with the clock
// at now, through the real reader.
func (f *reconcileFixture) statesAt(t *testing.T, installed []*apps.App, tiles TileVolumes, now time.Time) map[string]proto.AppBackupStatus {
	t.Helper()
	src := NewBackupStates(f.st, f.js, &fakeApps{list: installed}, tiles, newMemorySettings(), true)
	src.now = func() time.Time { return now }
	all, err := src.AppBackupStates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]proto.AppBackupStatus{}
	for _, s := range all {
		out[s.AppName] = s
	}
	return out
}

// claimTarget gives the fixture a claimed backup target, so a backup is due.
func (f *reconcileFixture) claimTarget(t *testing.T) {
	t.Helper()
	seedRunTarget(t, f.st, newTestKeypair(t), runHarnessOpts{})
}

func fanOutStep(t *testing.T, steps []*jobs.JobStep) *jobs.JobStep {
	t.Helper()
	var found *jobs.JobStep
	for _, st := range steps {
		if st.Name == "fan_out" {
			if found != nil {
				t.Fatalf("two fan_out steps: %+v", steps)
			}
			found = st
		}
	}
	if found == nil {
		t.Fatalf("no fan_out step in %+v", steps)
	}
	return found
}

// recNow is a manifest createdAt an hour before the real clock, at the
// ledger's millisecond precision.
func recNow() time.Time { return time.Now().UTC().Truncate(time.Millisecond).Add(-time.Hour) }

// TC-903-02: a complete generation's run is settled succeeded from its
// manifest, with the manifest's createdAt as its finish time, the snapshot
// step closed and the fan-out step recorded from the manifest.
func TestReconcileSettlesTheGeneratingRunSucceeded(t *testing.T) {
	f := newReconcileFixture(t, recNow())
	f.seedCaptured(t)
	vols := volReport(2,
		appVol("app-vw", "vaultwarden", "vaultwarden-data", "critical", true, false, ""),
		appVol("app-pl", "paperless", "paperless-data", "state", true, false, ""))
	if err := f.rc.Reconcile(context.Background(), f.report(vols)); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	snap := f.snapshot(t, recJobID)

	run := snap.Run
	if run.Status != RunSucceeded || run.GenerationID != recGenID || run.Digest != recDigest || run.SizeBytes != recBytes ||
		run.AppVolumesCaptured != 2 || run.AppVolumesSkipped != 0 || run.AppVolumesFailed != 0 || !run.Complete || run.Error != "" {
		t.Fatalf("run = %+v", run)
	}
	if run.FinishedAt == nil || !run.FinishedAt.Equal(f.at) {
		t.Errorf("run finished_at = %v, want the manifest's createdAt %v", run.FinishedAt, f.at)
	}
	for _, want := range []string{recRSID, recGenID, "retention prune", "not recorded"} {
		if !strings.Contains(run.Warning, want) {
			t.Errorf("run warning %q lacks %q", run.Warning, want)
		}
	}

	if snap.Job.Status != jobs.StatusSucceeded || snap.Job.Error != "" || snap.Job.FinishedAt == nil || !snap.Job.FinishedAt.Equal(f.at) {
		t.Errorf("job = %+v, want succeeded at %v with no error", snap.Job, f.at)
	}
	for _, st := range snap.Steps {
		if st.Name == "snapshot_db" && st.Status != jobs.StepSucceeded {
			t.Errorf("snapshot_db = %s, want succeeded", st.Status)
		}
	}
	fan := fanOutStep(t, snap.Steps)
	if fan.Status != jobs.StepSucceeded || fan.Seq != 3 {
		t.Errorf("fan_out = %+v, want succeeded at seq 3", fan)
	}
	var res runFanOutResult
	if err := json.Unmarshal(fan.Result, &res); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Report, jsonRoundTrip(t, vols)) {
		t.Errorf("fan_out report = %+v\nwant %+v", res.Report, vols)
	}

	if len(snap.Events) != 1 || snap.Events[0].Type != string(proto.JobLog) {
		t.Fatalf("events = %+v, want one log event", snap.Events)
	}
	var ev proto.LogEventData
	if err := json.Unmarshal(snap.Events[0].Data, &ev); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ev.Message, recRSID) || !strings.Contains(run.Warning, ev.Message) {
		t.Errorf("log event %q is not the run's note", ev.Message)
	}

	rec := f.record(t, "INFO", "reconciled the backup run that wrote the restored generation")
	wantFields(t, rec, map[string]string{"restore_id": recRSID, "job_id": recJobID, "generation_id": recGenID, "verdict": "succeeded"})
}

func jsonRoundTrip(t *testing.T, r AppVolumeReport) AppVolumeReport {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var out AppVolumeReport
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TC-903-03: after the reconcile the real readers see the captured apps as
// backed up at the manifest's time, with no failed-job or overdue alert; past
// cadence plus grace they read OVERDUE by age, never failed or never.
func TestReconciledRunReadsOKThroughTheRealReaders(t *testing.T) {
	f := newReconcileFixture(t, recNow())
	f.claimTarget(t)
	f.seedCaptured(t)
	installed := []*apps.App{
		testApp("app-vw", "vaultwarden", "n-1", "vaultwarden"),
		testApp("app-pl", "paperless", "n-1", "paperless"),
	}
	tiles := clusterTiles()
	vols := volReport(2,
		appVol("app-vw", "vaultwarden", "vaultwarden-data", "critical", true, false, ""),
		appVol("app-pl", "paperless", "paperless-data", "state", true, false, ""))
	if err := f.rc.Reconcile(context.Background(), f.report(vols)); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	for name, st := range f.statesAt(t, installed, tiles, f.at.Add(time.Hour)) {
		if st.State != proto.AppBackupOK || st.LastSuccessAt == nil || !st.LastSuccessAt.Equal(f.at) || !strings.Contains(st.Reason, "backed up 1h ago") {
			t.Errorf("%s = %s (%s), last success %v; want OK, backed up 1h ago at %v", name, st.State, st.Reason, st.LastSuccessAt, f.at)
		}
	}
	all := alertsOver(t, &runHarness{store: f.st, jobStore: f.js, settings: newMemorySettings()}, installed, tiles)
	for _, a := range all {
		if a.ID == "job-failed:"+recJobID || strings.HasPrefix(a.ID, "backup-overdue:") {
			t.Errorf("unexpected alert %s: %s", a.ID, a.Detail)
		}
	}

	cadence := DefaultBackupCadence
	late := f.at.Add(cadence + BackupGrace(cadence) + time.Minute)
	for name, st := range f.statesAt(t, installed, tiles, late) {
		if st.State != proto.AppBackupOverdue || !strings.Contains(st.Reason, "the last successful backup was") ||
			strings.Contains(st.Reason, "never backed up") || strings.Contains(st.Reason, "FAILED") {
			t.Errorf("%s past cadence+grace = %s (%s); want OVERDUE by age", name, st.State, st.Reason)
		}
	}
}

// TC-903-04: a volume the run skipped (not failed) leaves the run succeeded
// with the skip warning, the record keeps the manifest's reason, and the app
// still reads OK because a bulk volume is not owed.
func TestReconcileSkippedVolumeKeepsTheRunSucceeded(t *testing.T) {
	f := newReconcileFixture(t, recNow())
	f.claimTarget(t)
	f.seedCaptured(t)
	installed, tiles := reconcileApps()
	const bulkReason = "bulk volumes stream direct; that lane is not built"
	vols := volReport(1,
		appVol("app-im", "immich", "immich-upload", "state", true, false, ""),
		appVol("app-im", "immich", "immich-library", "bulk", false, false, bulkReason))
	if vols.Complete() || vols.SkippedCount != 1 {
		t.Fatalf("test setup: complete=%v skipped=%d", vols.Complete(), vols.SkippedCount)
	}
	if err := f.rc.Reconcile(context.Background(), f.report(vols)); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	snap := f.snapshot(t, recJobID)
	if snap.Run.Status != RunSucceeded || snap.Run.AppVolumesSkipped != 1 || snap.Run.Complete {
		t.Fatalf("run = %+v", snap.Run)
	}
	if !strings.HasPrefix(snap.Run.Warning, "1 app volume(s) were not captured") || !strings.Contains(snap.Run.Warning, recRSID) {
		t.Errorf("run warning = %q", snap.Run.Warning)
	}
	var res runFanOutResult
	if err := json.Unmarshal(fanOutStep(t, snap.Steps).Result, &res); err != nil {
		t.Fatal(err)
	}
	bulkFound := false
	for _, v := range res.Report.Volumes {
		if v.Volume == "immich-library" {
			bulkFound = !v.Captured && v.Reason == bulkReason
		}
	}
	if !bulkFound {
		t.Errorf("fan_out lacks the bulk record with its reason: %+v", res.Report.Volumes)
	}
	if st := f.statesAt(t, installed, tiles, f.at.Add(time.Hour))["immich"]; st.State != proto.AppBackupOK {
		t.Errorf("immich = %s (%s), want OK", st.State, st.Reason)
	}
}

// TC-903-05: a volume the run tried and could not take settles the run and
// the job failed with the run's own message, never "restarted mid-job"; the
// captured app reads OK, the failed one OVERDUE with the manifest's reason,
// and the job-failed alert carries the message.
func TestReconcileFailedVolumeSettlesTheRunFailed(t *testing.T) {
	f := newReconcileFixture(t, recNow())
	f.claimTarget(t)
	f.seedCaptured(t)
	installed, tiles := reconcileApps()
	vols := volReport(2,
		appVol("app-vw", "vaultwarden", "vaultwarden-data", "critical", true, false, ""),
		appVol("app-im", "immich", "immich-upload", "state", false, true, "node n-x is OFFLINE"))
	if vols.FailedCount != 1 {
		t.Fatalf("test setup: failed=%d", vols.FailedCount)
	}
	if err := f.rc.Reconcile(context.Background(), f.report(vols)); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	want := failedVolumesMessage(vols.FailedApps(), vols.Failed)
	snap := f.snapshot(t, recJobID)
	run := snap.Run
	if run.Status != RunFailed || run.Error != want || run.GenerationID != recGenID || run.Digest != recDigest ||
		run.SizeBytes != recBytes || run.AppVolumesCaptured != 1 || run.AppVolumesFailed != 1 {
		t.Fatalf("run = %+v\nwant error %q", run, want)
	}
	if !strings.HasPrefix(run.Warning, want) || !strings.Contains(run.Warning, recRSID) {
		t.Errorf("run warning = %q, want the message plus the note", run.Warning)
	}
	if run.FinishedAt == nil || !run.FinishedAt.Equal(f.at) {
		t.Errorf("run finished_at = %v, want %v", run.FinishedAt, f.at)
	}
	if snap.Job.Status != jobs.StatusFailed || snap.Job.Error != want {
		t.Errorf("job = %s %q", snap.Job.Status, snap.Job.Error)
	}
	for _, s := range []string{run.Error, run.Warning, snap.Job.Error} {
		if strings.Contains(s, "restarted mid-job") {
			t.Errorf("%q says restarted mid-job", s)
		}
	}
	states := f.statesAt(t, installed, tiles, f.at.Add(time.Hour))
	if st := states["vaultwarden"]; st.State != proto.AppBackupOK {
		t.Errorf("vaultwarden = %s (%s), want OK", st.State, st.Reason)
	}
	if st := states["immich"]; st.State != proto.AppBackupOverdue || !strings.Contains(st.Reason, "node n-x is OFFLINE") {
		t.Errorf("immich = %s (%s), want OVERDUE with the manifest's reason", st.State, st.Reason)
	}
	found := false
	for _, a := range alertsOver(t, &runHarness{store: f.st, jobStore: f.js, settings: newMemorySettings()}, installed, tiles) {
		if a.ID == "job-failed:"+recJobID {
			found = a.Detail == want
		}
	}
	if !found {
		t.Errorf("no job-failed:%s alert carrying the run's message", recJobID)
	}
}

// TC-903-06: an app the run left down settles the run and the job failed with
// appsLeftDownMessage, and the run still names its generation and counts.
func TestReconcileAppLeftDownSettlesTheRunFailed(t *testing.T) {
	f := newReconcileFixture(t, recNow())
	f.seedCaptured(t)
	down := appVol("app-im", "immich", "immich-upload", "state", true, false, "")
	down.AppRestored = false
	vols := volReport(1, down)
	if err := f.rc.Reconcile(context.Background(), f.report(vols)); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	want := appsLeftDownMessage([]string{"immich"})
	snap := f.snapshot(t, recJobID)
	if snap.Run.Status != RunFailed || snap.Run.Error != want || snap.Run.GenerationID != recGenID || snap.Run.AppVolumesCaptured != 1 {
		t.Fatalf("run = %+v\nwant error %q", snap.Run, want)
	}
	if snap.Job.Status != jobs.StatusFailed || snap.Job.Error != want {
		t.Errorf("job = %s %q", snap.Job.Status, snap.Job.Error)
	}
}

// TC-903-07: a backup.run job with no backup_runs row records nothing.
func TestReconcileWithNoRunRowWritesNothing(t *testing.T) {
	f := newReconcileFixture(t, recNow())
	f.seedJob(t, recJobID, RunJobKind, "validate", "preflight", "snapshot_db")
	before := f.snapshot(t, recJobID)
	if err := f.rc.Reconcile(context.Background(), f.report(volReport(0))); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if after := f.snapshot(t, recJobID); !reflect.DeepEqual(before, after) {
		t.Errorf("ledger changed:\nbefore %+v\nafter  %+v", before, after)
	}
	rec := f.record(t, "WARN", "holds no backup run")
	wantFields(t, rec, map[string]string{"restore_id": recRSID, "job_id": recJobID, "generation_id": recGenID})
	if r, _ := rec["reason"].(string); r == "" {
		t.Errorf("WARN has no reason: %v", rec)
	}
}

// TC-903-08: a run row with no job row, or a job that is not a backup.run,
// records nothing.
func TestReconcileWithNoMatchingJobWritesNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed func(t *testing.T, f *reconcileFixture)
	}{
		{"no job row", func(t *testing.T, f *reconcileFixture) { f.seedRunRow(t, recJobID) }},
		{"job of another kind", func(t *testing.T, f *reconcileFixture) {
			f.seedJob(t, recJobID, "ping", "ping")
			f.seedRunRow(t, recJobID)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newReconcileFixture(t, recNow())
			tc.seed(t, f)
			before := f.snapshot(t, recJobID)
			if err := f.rc.Reconcile(context.Background(), f.report(volReport(0))); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			if after := f.snapshot(t, recJobID); !reflect.DeepEqual(before, after) {
				t.Errorf("ledger changed:\nbefore %+v\nafter  %+v", before, after)
			}
			if r, _ := f.record(t, "WARN", "holds no backup run")["reason"].(string); r == "" {
				t.Error("WARN has no reason")
			}
		})
	}
}

// TC-903-09: a report that names no run — none at all, no job id, no
// per-volume record, or a restore.json from the previous release — records
// nothing, and the previous release's report is still recorded.
func TestReconcileWithoutTheGenerationsIdentityWritesNothing(t *testing.T) {
	ctx := context.Background()
	noJob := func(f *reconcileFixture) *RestoreReport {
		r := f.report(volReport(0))
		r.GenerationJobID = ""
		return r
	}
	noVols := func(f *reconcileFixture) *RestoreReport {
		r := f.report(volReport(0))
		r.GenerationAppVolumes = nil
		return r
	}
	previous := func(f *reconcileFixture) *RestoreReport {
		// The previous release's restore.json: neither new key.
		dataDir := t.TempDir()
		applied := filepath.Join(dataDir, restoreAppliedDirName)
		if err := os.MkdirAll(applied, 0o700); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(applied, restoreReportFile), `{"id":"`+recRSID+`","phase":"identity","generationId":"`+recGenID+
			`","generationCreatedAt":"2026-10-30T12:00:00Z","complete":true,"manifestVersion":3,"partUuid":"p","nodeId":"n",`+
			`"sealedDigest":"d","sealedBytes":1,"restored":[],"notRestored":[],"appVolumesPresent":[],"appVolumesAbsent":[],"warning":"w","preparedAt":"2026-10-30T12:00:00Z"}`)
		rep, err := RecordAppliedRestore(ctx, f.st, dataDir)
		if err != nil || rep == nil {
			t.Fatalf("RecordAppliedRestore: %v %v", rep, err)
		}
		all, err := f.st.ListRestores(ctx)
		if err != nil || len(all) != 1 || all[0].ID != recRSID {
			t.Fatalf("previous release's report not recorded: %+v %v", all, err)
		}
		return rep
	}
	for _, tc := range []struct {
		name string
		rep  func(f *reconcileFixture) *RestoreReport
		warn bool
	}{
		{"nil report", func(*reconcileFixture) *RestoreReport { return nil }, false},
		{"no job id", noJob, true},
		{"no per-volume record", noVols, true},
		{"previous release's restore.json", previous, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newReconcileFixture(t, recNow())
			f.seedCaptured(t)
			rep := tc.rep(f)
			before := f.snapshot(t, recJobID)
			if err := f.rc.Reconcile(ctx, rep); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			if after := f.snapshot(t, recJobID); !reflect.DeepEqual(before, after) {
				t.Errorf("ledger changed:\nbefore %+v\nafter  %+v", before, after)
			}
			if tc.warn {
				f.record(t, "WARN", "names no backup job; no run reconciled")
			}
		})
	}
}

// TC-903-10: a second reconcile with the same report changes nothing.
func TestReconcileTwiceChangesNothing(t *testing.T) {
	f := newReconcileFixture(t, recNow())
	f.seedCaptured(t)
	rep := f.report(volReport(1, appVol("app-vw", "vaultwarden", "vaultwarden-data", "critical", true, false, "")))
	if err := f.rc.Reconcile(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	first := f.snapshot(t, recJobID)
	if err := f.rc.Reconcile(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	if second := f.snapshot(t, recJobID); !reflect.DeepEqual(first, second) {
		t.Errorf("second reconcile changed the ledger:\nfirst  %+v\nsecond %+v", first, second)
	}
	f.record(t, "INFO", "already settled")
}

// TC-903-11: another job in flight is left for Recover.
func TestReconcileLeavesOtherInflightJobsAlone(t *testing.T) {
	f := newReconcileFixture(t, recNow())
	f.seedCaptured(t)
	f.seedJob(t, "job-k", "storage.reconcile", "reconcile")
	before := f.jobsSnapshot(t, "job-k")
	if err := f.rc.Reconcile(context.Background(), f.report(volReport(0))); err != nil {
		t.Fatal(err)
	}
	after := f.jobsSnapshot(t, "job-k")
	if !reflect.DeepEqual(before, after) || after.Job.Status != jobs.StatusRunning || after.Steps[0].Status != jobs.StepRunning {
		t.Errorf("job K changed or is not running:\nbefore %+v\nafter  %+v", before, after)
	}
}

// TC-903-12: a store error is returned wrapped, and nothing is written.
func TestReconcileReturnsAStoreErrorWrapped(t *testing.T) {
	f := newReconcileFixture(t, recNow())
	f.seedCaptured(t)
	before := f.jobsSnapshot(t, recJobID)
	if err := f.st.Close(); err != nil {
		t.Fatal(err)
	}
	err := f.rc.Reconcile(context.Background(), f.report(volReport(0)))
	if err == nil || !strings.HasPrefix(err.Error(), "reconcile restored run "+recJobID) || errors.Unwrap(err) == nil {
		t.Fatalf("err = %v, want a wrapped store error naming the job", err)
	}
	if after := f.jobsSnapshot(t, recJobID); !reflect.DeepEqual(before, after) {
		t.Errorf("job ledger changed:\nbefore %+v\nafter  %+v", before, after)
	}
}

// TC-903-13: the verdict rule, over inputs derived from a report the same way
// runAssemble derives them.
func TestRunVerdictOverTheManifestDerivation(t *testing.T) {
	captured := appVol("app-vw", "vaultwarden", "vaultwarden-data", "critical", true, false, "")
	failed := appVol("app-im", "immich", "immich-upload", "state", false, true, "node n-x is OFFLINE")
	skipped := appVol("app-im", "immich", "immich-library", "bulk", false, false, "bulk lane not built")
	down := captured
	down.AppRestored = false

	leftAndFailed := volReport(2, down, failed)
	failedOnly := volReport(2, captured, failed)
	skippedOnly := volReport(2, captured, skipped)
	complete := volReport(1, captured)
	for _, tc := range []struct {
		name              string
		r                 AppVolumeReport
		wantErr, wantWarn string
	}{
		{"apps left down and failed volumes", leftAndFailed, appsLeftDownMessage([]string{"vaultwarden"}), ""},
		{"failed volumes only", failedOnly, failedVolumesMessage(failedOnly.FailedApps(), failedOnly.Failed), ""},
		{"skipped volumes only", skippedOnly, "", "1 app volume(s) were not captured; the manifest names each one and its reason"},
		{"complete", complete, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			errMsg, warn := runVerdict(volumeOutcome(tc.r, tc.r.Complete()))
			if errMsg != tc.wantErr || warn != tc.wantWarn {
				t.Errorf("runVerdict = (%q, %q), want (%q, %q)", errMsg, warn, tc.wantErr, tc.wantWarn)
			}
		})
	}
}

// TC-903-01: the prepared report, and the one RecordAppliedRestore returns,
// carry the manifest's job id and per-volume record; restore.json holds them.
func TestRestoreReportCarriesTheGeneratingRun(t *testing.T) {
	h := newRestoreHarness(t, generationOpts{
		complete: false,
		volumes: []VolumeRecord{
			capturedVolume("vaultwarden", "data", "critical"),
			skippedVolume("jellyfin", "library", "bulk", "bulk volumes stream direct; that lane is not built"),
		},
	})
	seedFreshInstall(t, h.dataDir)
	want := jsonRoundTrip(t, h.manifest.AppVolumes)
	check := func(stage string, rep *RestoreReport) {
		t.Helper()
		if rep.GenerationJobID != h.manifest.JobID || rep.GenerationJobID == "" || rep.JobID != "" {
			t.Errorf("%s: generationJobId %q jobId %q, want %q and empty", stage, rep.GenerationJobID, rep.JobID, h.manifest.JobID)
		}
		if rep.GenerationAppVolumes == nil || !reflect.DeepEqual(*rep.GenerationAppVolumes, want) {
			t.Errorf("%s: generationAppVolumes = %+v\nwant %+v", stage, rep.GenerationAppVolumes, want)
		}
	}
	ctx := context.Background()
	prepared, err := PrepareRestore(ctx, h.cfg, h.request(h.key.priv.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	check("prepared", prepared)
	raw, err := os.ReadFile(filepath.Join(h.dataDir, restorePendingDirName, restoreReportFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"generationJobId"`, `"generationAppVolumes"`} {
		if !bytes.Contains(raw, []byte(key)) {
			t.Errorf("restore.json lacks %s", key)
		}
	}
	layout := RestoreLayout{DataDir: h.dataDir, TrustDir: filepath.Join(h.dataDir, "trust"), MeshStateDir: filepath.Join(h.dataDir, "mesh")}
	if _, applied, err := ApplyPendingRestore(layout); err != nil || !applied {
		t.Fatalf("apply: %v applied=%v", err, applied)
	}
	st, err := OpenStore(ctx, filepath.Join(t.TempDir(), "restored.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	recorded, err := RecordAppliedRestore(ctx, st, h.dataDir)
	if err != nil || recorded == nil {
		t.Fatalf("RecordAppliedRestore: %v %v", recorded, err)
	}
	check("recorded", recorded)
}
