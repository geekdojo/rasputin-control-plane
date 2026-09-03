package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Backup RUN endpoints — the api surface of design/storage.md §4.1's producer.
//
//	GET  /api/backup/runs      the ledger, failures included
//	POST /api/backup/runs      "Back up now": submits the backup.run saga
//	GET  /api/backup/schedule  the cadence
//	PUT  /api/backup/schedule  set the cadence, per installation
//
// The split from the §4.8 target routes next door is the split §4.1 draws:
// those choose and format a disk, these write to the one already chosen.
//
// # The scope field, and why it is on every response here
//
// Every generation this build writes is `identity-only`
// (proto.BackupScopeIdentityOnly): the controlplane's database, the mesh CA and
// Headscale state, and NO app data — the volumes are classified (#293) and the
// agent can stage one (#294), but the path that carries a staged copy into
// this archive (#295, #296) is unbuilt. An archive that omits app data is not
// the backup a user assumes they have, so no response below can be rendered
// without the fact being in it: the run rows carry `scope` and
// `appVolumesCaptured`, and the two summary endpoints carry the prose as well.

// backupRunsResponse is GET /api/backup/runs.
//
// A wrapper rather than a bare array, because the array alone cannot carry the
// two things a Backups view needs beside it: the honest scope caveat, and when
// a backup last actually SUCCEEDED. The second is deliberately not derivable
// from a page of recent runs — the last success may be older than the page.
type backupRunsResponse struct {
	Runs []*storage.BackupRun `json:"runs"`
	// LastSuccess is the most recent successful run, or null when there has
	// never been one. Null is a real answer and the UI must render it as one:
	// "no backup has ever succeeded" is not "the last one was a while ago".
	LastSuccess *storage.BackupRun `json:"lastSuccess"`
	// Scope and ScopeWarning describe what an archive from this build contains.
	// Served on the list so a client cannot render a run without them.
	Scope        string `json:"scope"`
	ScopeWarning string `json:"scopeWarning"`
	// Retain is §4.4's generation count, so the view can say "4 kept" without
	// hard-coding it.
	Retain int `json:"retain"`
}

// GET /api/backup/runs?limit=N
func (s *Server) handleListBackupRuns(w http.ResponseWriter, r *http.Request) {
	if s.backup == nil {
		writeError(w, http.StatusServiceUnavailable, "backups are not configured on this api")
		return
	}
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	runs, err := s.backup.ListRuns(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if runs == nil {
		runs = []*storage.BackupRun{}
	}
	last, err := s.backup.LastSuccess(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, backupRunsResponse{
		Runs:         runs,
		LastSuccess:  last,
		Scope:        proto.BackupScopeControlplaneLocal,
		ScopeWarning: storage.AppVolumeFanOutReason(),
		Retain:       proto.BackupRetainGenerations,
	})
}

// startBackupRequest is the body of POST /api/backup/runs.
//
// Empty is the normal case — "Back up now" takes no parameters, because every
// decision a run makes is POLICY and §4.1 puts policy on the control plane.
// Decoded with DisallowUnknownFields all the same: the body becomes the job
// spec, the job spec is persisted and rendered, and a field a caller invented
// must not ride along into either.
type startBackupRequest struct{}

// POST /api/backup/runs
//
// §4.1's on-demand "Back up now". Submits the same saga the schedule submits,
// with the same refusals in the same order — there is deliberately no express
// path for a manual run, because the checks it would skip are the ones that
// stop a backup filling the disk it protects.
func (s *Server) handleStartBackupRun(w http.ResponseWriter, r *http.Request) {
	if s.backup == nil {
		writeError(w, http.StatusServiceUnavailable, "backups are not configured on this api")
		return
	}
	if r.Body != nil {
		dec := json.NewDecoder(io.LimitReader(r.Body, 4<<10))
		dec.DisallowUnknownFields()
		var req startBackupRequest
		if err := dec.Decode(&req); err != nil && err != io.EOF {
			writeError(w, http.StatusBadRequest, "invalid json body: "+err.Error())
			return
		}
	}
	// Refused HERE as well as in step 1, so an operator hammering the button
	// gets a 409 with the reason rather than a job that exists only to fail.
	// Step 1 keeps its own copy of the check because this one is advisory: two
	// requests can pass it concurrently, and the saga is where that is settled.
	running, err := s.backup.ListRunning(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(running) > 0 {
		writeError(w, http.StatusConflict,
			"a backup is already running (job "+running[0].JobID+"). Only one runs at a time — two archives staged at once is how a backup fills the disk it is protecting")
		return
	}
	body, err := json.Marshal(storage.RunSpec{Reason: storage.ReasonManual})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	j, err := s.runner.Submit(r.Context(), storage.RunJobKind, body, creator(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, j)
}

// backupScheduleResponse is GET/PUT /api/backup/schedule.
type backupScheduleResponse struct {
	storage.BackupSchedule
	// EverySeconds is the resolved cadence in seconds — what Interval() would
	// return, including the fallback for an empty or unusable value. Served
	// beside the raw string so a client renders what the scheduler will
	// actually do rather than what the setting says.
	EverySeconds int64 `json:"everySeconds"`
	// NextDue is when the next scheduled run becomes due, or null when the
	// schedule is off or nothing has ever succeeded (in which case it is due
	// now). Derived from the last SUCCESS, which is what DueFunc measures.
	NextDue *time.Time `json:"nextDue"`
	// DefaultEvery and bounds, so a form can validate without hard-coding them.
	DefaultEvery string `json:"defaultEvery"`
	MinEvery     string `json:"minEvery"`
	MaxEvery     string `json:"maxEvery"`
}

func (s *Server) backupScheduleView(r *http.Request, sched storage.BackupSchedule) backupScheduleResponse {
	out := backupScheduleResponse{
		BackupSchedule: sched,
		EverySeconds:   int64(sched.Interval() / time.Second),
		DefaultEvery:   storage.DefaultBackupCadence.String(),
		MinEvery:       storage.MinBackupCadence.String(),
		MaxEvery:       storage.MaxBackupCadence.String(),
	}
	if !sched.Enabled || s.backup == nil {
		return out
	}
	if last, err := s.backup.LastSuccess(r.Context()); err == nil && last != nil && last.FinishedAt != nil {
		due := last.FinishedAt.Add(sched.Interval())
		out.NextDue = &due
	}
	return out
}

// GET /api/backup/schedule
func (s *Server) handleGetBackupSchedule(w http.ResponseWriter, r *http.Request) {
	if s.setup == nil {
		writeError(w, http.StatusServiceUnavailable, "settings are not configured on this api")
		return
	}
	sched, err := storage.GetBackupSchedule(r.Context(), s.setup.Store(), true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.backupScheduleView(r, sched))
}

// PUT /api/backup/schedule
//
// §4.1's "overridable per installation". Takes effect on the scheduler's next
// check rather than on the next api restart — see storage.DueFunc, which reads
// this setting on every tick.
func (s *Server) handleSetBackupSchedule(w http.ResponseWriter, r *http.Request) {
	if s.setup == nil {
		writeError(w, http.StatusServiceUnavailable, "settings are not configured on this api")
		return
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<10))
	dec.DisallowUnknownFields()
	var req storage.BackupSchedule
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body: "+err.Error())
		return
	}
	saved, err := storage.SetBackupSchedule(r.Context(), s.setup.Store(), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.backupScheduleView(r, saved))
}
