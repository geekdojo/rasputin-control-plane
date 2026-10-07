package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/nodetrust"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// After an identity restore: get the restored controlplane CA back out to the
// nodes now, not on the next scheduled tick.
//
// The restore swapped trust/mesh-ca.pem under every node that enrolled since
// the box was re-flashed; each of those still trusts the CA the restore
// replaced, and every node→api TLS client on it fails until the restored CA
// is delivered again (e3bench 2026-09-04 — the backup run after a restore
// finalised FAILED for the app volume because compute1 could not verify the
// api's leaf). trust.converge does the delivery from data (each node's
// reported fingerprint against the api's); this only brings the first pass
// forward from the scheduler's initial delay to "as soon as the agents have
// re-registered", and records what that pass found on the restore report so
// the storage page can say which nodes the restored CA reached and which have
// not said what they trust.
//
// Nodes whose agent predates trust.install are left by trust.converge to the
// mesh bridge (converge_trust inside mesh.reconcile). When the pass counts any,
// this also kicks mesh.reconcile once the mesh can take one, so they get the
// restored CA as promptly as before (#516 "B1").
//
// Every wait here has a deadline. Nothing depends on this goroutine: the
// scheduled trust.converge and mesh.reconcile converge the same nodes on their
// own ticks.

const (
	// restoreTrustMeshDeadline bounds the wait for the mesh to come up after
	// the restart, before the legacy bridge's reconcile. Self-hosted Headscale
	// pulls nothing on a warm box and is up in seconds; a cold pull can take a
	// minute or two.
	restoreTrustMeshDeadline = 5 * time.Minute
	// restoreTrustSettle is how long, after the restart, to let agents
	// re-register (they reconnect within seconds of the api restart, and the
	// registration is what carries the fingerprint) before comparing.
	restoreTrustSettle = 10 * time.Second
	// restoreTrustReconcileDeadline bounds the wait for each kicked job to
	// reach a terminal state.
	restoreTrustReconcileDeadline = 3 * time.Minute
)

// restoreTrustDeps is what the restore kick needs, passed in by main.
type restoreTrustDeps struct {
	Log *slog.Logger
	// Now stamps the record's CheckedAt.
	Now func() time.Time
	// Submit submits a job (jobs.Runner.Submit).
	Submit func(ctx context.Context, kind string, spec any, createdBy string) (*jobs.Job, error)
	// Jobs reads a job and its steps back (*jobs.Store).
	Jobs interface {
		GetJob(ctx context.Context, id string) (*jobs.Job, error)
		ListSteps(ctx context.Context, jobID string) ([]*jobs.JobStep, error)
	}
	// Record writes the report's trust record (storage.Store
	// .RecordRestoreTrustRedelivery).
	Record func(ctx context.Context, reportID string, rec *storage.TrustRedeliveryRecord) error
	// MeshReady reports whether mesh.reconcile can run now.
	MeshReady func() bool
	// Fingerprint is the api's node trust bundle fingerprint.
	Fingerprint func() string
	// The bounds on each wait; main passes the consts above.
	Settle, JobDeadline, MeshDeadline time.Duration
}

// kickTrustConvergenceAfterRestore runs in the background on the start that
// applied an identity restore.
func kickTrustConvergenceAfterRestore(ctx context.Context, d restoreTrustDeps, reportID string) {
	log := d.Log.With("restore_id", reportID)
	record := func(rec *storage.TrustRedeliveryRecord) {
		rec.CheckedAt = d.Now().UTC()
		if err := d.Record(ctx, reportID, rec); err != nil {
			log.ErrorContext(ctx, "restore: trust re-delivery record not written", "err", err.Error())
		}
	}
	fail := func(detail string) {
		log.WarnContext(ctx, "restore: trust re-delivery did not run", "detail", detail)
		res := nodetrust.NewConvergeResult(d.Fingerprint())
		record(recordOf(res, detail))
	}

	select {
	case <-ctx.Done():
		return
	case <-time.After(d.Settle):
	}

	res, detail, ok := runAndRead(ctx, d, nodetrust.ConvergeKind, "converge")
	if !ok {
		if ctx.Err() != nil {
			return
		}
		fail(detail + "; the scheduled trust.converge will deliver the restored controlplane CA")
		return
	}
	var conv nodetrust.ConvergeResult
	if err := json.Unmarshal(res, &conv); err != nil {
		fail(fmt.Sprintf("the post-restore %s result could not be read: %v", nodetrust.ConvergeKind, err))
		return
	}
	rec := recordOf(conv, detail)
	record(rec)
	log.InfoContext(ctx, "restore: restored controlplane CA delivered",
		"fingerprint", proto.ShortFingerprint(conv.CAFingerprint), "installed", strings.Join(conv.Redelivered, ","),
		"current", len(conv.Current), "unreported", strings.Join(conv.Unreported, ","), "skipped", fmt.Sprint(conv.Skipped))

	legacy := conv.Skipped["legacy_agent"]
	if legacy == 0 {
		return
	}
	// Agents too old for trust.install take the CA only from mesh.enroll,
	// which mesh.reconcile's converge_trust re-runs for them.
	if !waitUntil(ctx, d.MeshDeadline, d.MeshReady) {
		if ctx.Err() != nil {
			return
		}
		bridgeFailed(ctx, log, record, rec, fmt.Sprintf("%d node(s) run an agent that predates %s, and the mesh was not ready within %s to re-deliver to them; the scheduled mesh.reconcile will",
			legacy, proto.TrustInstallVerb, d.MeshDeadline))
		return
	}
	if _, detail, ok := runAndRead(ctx, d, "mesh.reconcile", "converge_trust"); !ok {
		if ctx.Err() != nil {
			return
		}
		bridgeFailed(ctx, log, record, rec, fmt.Sprintf("%d node(s) run an agent that predates %s, and the mesh.reconcile kicked for them did not complete: %s",
			legacy, proto.TrustInstallVerb, detail))
		return
	}
	log.InfoContext(ctx, "restore: mesh.reconcile re-delivered to legacy agents", "legacy_agents", legacy)
}

// bridgeFailed appends why the legacy bridge did not run to the record and
// writes it again.
func bridgeFailed(ctx context.Context, log *slog.Logger, record func(*storage.TrustRedeliveryRecord), rec *storage.TrustRedeliveryRecord, why string) {
	log.WarnContext(ctx, "restore: legacy trust bridge did not run", "detail", why)
	if rec.Detail != "" {
		rec.Detail += "; "
	}
	rec.Detail += why
	record(rec)
}

// runAndRead submits kind, waits for it to finish, and returns step's result.
// ok is false with detail saying why when the job could not be submitted, did
// not finish in time, or finished without step's result; detail is set
// alongside ok when the job finished unsucceeded after step ran.
func runAndRead(ctx context.Context, d restoreTrustDeps, kind, step string) (result json.RawMessage, detail string, ok bool) {
	j, err := d.Submit(ctx, kind, nil, "restore-trust")
	if err != nil {
		return nil, fmt.Sprintf("could not submit the post-restore %s: %v", kind, err), false
	}
	var final *jobs.Job
	done := waitUntil(ctx, d.JobDeadline, func() bool {
		got, err := d.Jobs.GetJob(ctx, j.ID)
		if err != nil || got == nil {
			return false
		}
		switch got.Status {
		case jobs.StatusSucceeded, jobs.StatusFailed, jobs.StatusCancelled:
			final = got
			return true
		}
		return false
	})
	if !done {
		return nil, fmt.Sprintf("the post-restore %s %s did not finish within %s", kind, j.ID, d.JobDeadline), false
	}
	steps, err := d.Jobs.ListSteps(ctx, j.ID)
	if err != nil {
		return nil, fmt.Sprintf("the post-restore %s %s finished %s but its steps could not be read: %v", kind, j.ID, final.Status, err), false
	}
	for _, s := range steps {
		if s.Name == step && len(s.Result) > 0 {
			result = s.Result
		}
	}
	if result == nil {
		detail = fmt.Sprintf("the post-restore %s %s finished %s before its %s step ran", kind, j.ID, final.Status, step)
		if final.Error != "" {
			detail += ": " + final.Error
		}
		return nil, detail, false
	}
	if final.Status != jobs.StatusSucceeded && final.Error != "" {
		detail = fmt.Sprintf("the post-restore %s %s finished %s after %s: %s", kind, j.ID, final.Status, step, final.Error)
	}
	return result, detail, true
}

// recordOf is the restore report's record of a convergence pass.
func recordOf(res nodetrust.ConvergeResult, detail string) *storage.TrustRedeliveryRecord {
	return &storage.TrustRedeliveryRecord{
		CAFingerprint: res.CAFingerprint,
		Redelivered:   orEmpty(res.Redelivered),
		Stale:         orEmpty(res.Stale),
		Current:       orEmpty(res.Current),
		Unreported:    orEmpty(res.Unreported),
		Skipped:       res.Skipped,
		Detail:        detail,
	}
}

// waitUntil polls cond every second until it is true (returns true), the
// deadline passes or ctx ends (returns false). A wait with no deadline is a
// bug; this one names its deadline in the caller.
func waitUntil(ctx context.Context, deadline time.Duration, cond func() bool) bool {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	end := time.Now().Add(deadline)
	for {
		if cond() {
			return true
		}
		if time.Now().After(end) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
		}
	}
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
