package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The /api/backup/runs and /api/backup/schedule surface.
//
// The assertions that matter are not about status codes. They are about what a
// client CANNOT render without: an archive from this build contains no app
// data, and no response here may leave that out.

// runsTestServer extends the §4.8 storage test server with the backup.run
// workflow and a real settings store, so the schedule routes have somewhere to
// persist.
func runsTestServer(t *testing.T) (*Server, *storage.Store) {
	t.Helper()
	s, store, _ := storageTestServer(t)
	setupStore, err := setup.OpenStore(context.Background(), t.TempDir()+"/settings.db")
	if err != nil {
		t.Fatalf("setup OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = setupStore.Close() })
	s.setup = setup.NewService(setupStore, setup.Probes{}, "cp-1", "test1.local", "test1")
	return s, store
}

func getJSON(t *testing.T, s *Server, h http.HandlerFunc, path string, into any) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if into != nil && rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), into); err != nil {
			t.Fatalf("decode %s: %v (body %s)", path, err, rec.Body.String())
		}
	}
	return rec
}

// TestListBackupRunsAlwaysCarriesTheScopeCaveat is the assertion this endpoint
// exists to satisfy. A client that renders runs without the caveat tells an
// operator their apps are backed up when they are not.
func TestListBackupRunsAlwaysCarriesTheScopeCaveat(t *testing.T) {
	s, _ := runsTestServer(t)

	var body backupRunsResponse
	rec := getJSON(t, s, s.handleListBackupRuns, "/api/backup/runs", &body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	if body.Scope != proto.BackupScopeControlplaneLocal {
		t.Errorf("scope = %q, want %q", body.Scope, proto.BackupScopeControlplaneLocal)
	}
	if body.ScopeWarning == "" {
		t.Error("no scope warning: a client would have nothing to show but a green success line")
	}
	if !strings.Contains(strings.ToLower(body.ScopeWarning), "not a complete backup") {
		t.Errorf("the warning does not say, in words, that this is not a complete backup: %q", body.ScopeWarning)
	}
	if body.Retain != proto.BackupRetainGenerations {
		t.Errorf("retain = %d, want §4.4's %d", body.Retain, proto.BackupRetainGenerations)
	}
	// An empty ledger returns [] rather than null: a client mapping over the
	// list should not have to special-case a first boot.
	if body.Runs == nil {
		t.Error("runs is null on an empty ledger")
	}
	// And "never" is served as an explicit null rather than omitted, because a
	// client has to be able to tell it from "the field was not sent".
	if !strings.Contains(rec.Body.String(), `"lastSuccess":null`) {
		t.Errorf("lastSuccess is not an explicit null on a fresh installation: %s", rec.Body)
	}
}

// TestListBackupRunsReportsTheLastSuccessSeparately: the last success may be
// older than the page of recent runs, so it cannot be derived from the list.
func TestListBackupRunsReportsTheLastSuccessSeparately(t *testing.T) {
	s, store := runsTestServer(t)
	ctx := context.Background()

	// One success, then a failure on top of it. A client reading only the most
	// recent row would report the failure as the state of the backups; the
	// question an operator asks is when one last WORKED.
	if err := store.StartRun(ctx, "job-ok", storage.ReasonScheduled, proto.BackupScopeIdentityOnly, time.Now().Add(-2*time.Hour).UTC()); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishRun(ctx, "job-ok", storage.RunResult{
		GenerationID: "20260901T030000Z-aaaa-identity-only", Digest: "d", SizeBytes: 4096,
		GenerationsKept: 4, GenerationsPruned: 1, At: time.Now().Add(-2 * time.Hour).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.StartRun(ctx, "job-bad", storage.ReasonManual, proto.BackupScopeIdentityOnly, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := store.FailRun(ctx, "job-bad", "the target is full", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	var body backupRunsResponse
	getJSON(t, s, s.handleListBackupRuns, "/api/backup/runs", &body)
	if len(body.Runs) != 2 {
		t.Fatalf("got %d runs, want 2", len(body.Runs))
	}
	if body.Runs[0].JobID != "job-bad" {
		t.Errorf("runs are not newest-first: %s", body.Runs[0].JobID)
	}
	if body.LastSuccess == nil || body.LastSuccess.JobID != "job-ok" {
		t.Fatalf("lastSuccess = %+v, want job-ok", body.LastSuccess)
	}
	// §4.4: a failed run is loud, with a real reason, in the feed.
	if body.Runs[0].Error != "the target is full" {
		t.Errorf("the failed run carries error %q", body.Runs[0].Error)
	}
	// And every row says what it captured.
	for _, r := range body.Runs {
		if r.Scope != proto.BackupScopeIdentityOnly {
			t.Errorf("run %s has scope %q", r.JobID, r.Scope)
		}
		if r.AppVolumesCaptured != 0 {
			t.Errorf("run %s claims %d app volumes", r.JobID, r.AppVolumesCaptured)
		}
	}
}

// TestStartBackupRunRefusesAConcurrentRun: two archives staged at once is how a
// backup fills the disk it is protecting. The saga refuses it too; this refusal
// exists so the button gives a reason rather than a job that only fails.
func TestStartBackupRunRefusesAConcurrentRun(t *testing.T) {
	s, store := runsTestServer(t)
	if err := store.StartRun(context.Background(), "job-inflight",
		storage.ReasonScheduled, proto.BackupScopeIdentityOnly, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.handleStartBackupRun(rec, httptest.NewRequest(http.MethodPost, "/api/backup/runs", strings.NewReader("{}")))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "already running") {
		t.Errorf("the refusal does not say why: %s", rec.Body)
	}
}

// TestStartBackupRunRefusesAnInventedField: the body becomes the job spec, and
// the job spec is persisted and rendered. A field a caller invented must not
// ride along into either.
func TestStartBackupRunRefusesAnInventedField(t *testing.T) {
	s, _ := runsTestServer(t)
	for _, body := range []string{
		`{"partUuid":"somewhere-else"}`,
		`{"retain":0}`,
		`{"privateKey":"AAAA"}`,
	} {
		rec := httptest.NewRecorder()
		s.handleStartBackupRun(rec, httptest.NewRequest(http.MethodPost, "/api/backup/runs", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400 (%s)", body, rec.Code, rec.Body)
		}
	}
}

// TestBackupScheduleRoundTrips covers §4.1's "weekly by default, overridable
// per installation".
func TestBackupScheduleRoundTrips(t *testing.T) {
	s, _ := runsTestServer(t)

	var got backupScheduleResponse
	rec := getJSON(t, s, s.handleGetBackupSchedule, "/api/backup/schedule", &got)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	if !got.Enabled {
		t.Error("scheduled backups default to off; §4.1 makes the weekly run the product's behaviour")
	}
	if got.EverySeconds != int64(storage.DefaultBackupCadence/time.Second) {
		t.Errorf("everySeconds = %d, want a week", got.EverySeconds)
	}
	// The bounds are served so a form can validate without hard-coding them.
	if got.MinEvery == "" || got.MaxEvery == "" || got.DefaultEvery == "" {
		t.Errorf("the schedule response does not carry its own bounds: %+v", got)
	}

	put := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.handleSetBackupSchedule(rec, httptest.NewRequest(http.MethodPut, "/api/backup/schedule", strings.NewReader(body)))
		return rec
	}
	if rec := put(`{"enabled":true,"every":"24h"}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d: %s", rec.Code, rec.Body)
	}
	getJSON(t, s, s.handleGetBackupSchedule, "/api/backup/schedule", &got)
	if got.EverySeconds != 86400 {
		t.Errorf("the cadence did not persist: everySeconds = %d", got.EverySeconds)
	}

	// Out-of-bounds cadences are refused with a reason, not clamped: a silent
	// clamp would leave the operator believing a cadence they did not get.
	for _, body := range []string{`{"enabled":true,"every":"1m"}`, `{"enabled":true,"every":"10000h"}`, `{"enabled":true,"every":"nonsense"}`} {
		if rec := put(body); rec.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400 (%s)", body, rec.Code, rec.Body)
		}
	}
	// An unknown field is a 400 rather than a silently ignored setting.
	if rec := put(`{"enabled":true,"every":"24h","cron":"0 3 * * 0"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown field was accepted: %d %s", rec.Code, rec.Body)
	}

	// Turning the schedule off is a supported state and must persist as one.
	if rec := put(`{"enabled":false}`); rec.Code != http.StatusOK {
		t.Fatalf("disabling failed: %d %s", rec.Code, rec.Body)
	}
	getJSON(t, s, s.handleGetBackupSchedule, "/api/backup/schedule", &got)
	if got.Enabled {
		t.Error("the schedule did not stay off")
	}
	if got.NextDue != nil {
		t.Error("a disabled schedule reports a next-due time")
	}
}

// TestBackupRunRoutesAnswer503WithoutAStore: an api built without the ledger
// says so rather than pretending there are no backups.
func TestBackupRunRoutesAnswer503WithoutAStore(t *testing.T) {
	s := &Server{}
	for name, h := range map[string]http.HandlerFunc{
		"list":  s.handleListBackupRuns,
		"start": s.handleStartBackupRun,
	} {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, "/api/backup/runs", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: status = %d, want 503", name, rec.Code)
		}
	}
}
