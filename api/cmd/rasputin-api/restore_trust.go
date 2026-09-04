package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// After an identity restore: get the restored mesh CA back out to the nodes
// now, not on the next scheduled tick.
//
// The restore swapped trust/mesh-ca.pem under every node that enrolled since
// the box was re-flashed; each of those still trusts the CA the restore
// replaced, and every node→api TLS client on it fails until the restored CA
// is delivered again (e3bench 2026-09-04 — the backup run after a restore
// finalised FAILED for the app volume because compute1 could not verify the
// api's leaf). mesh.reconcile's converge_trust step does the delivery from
// data (each node's reported fingerprint against the api's); this only
// brings the first pass forward from the scheduler's 90s initial delay plus
// the mesh bring-up to "as soon as the mesh can take a reconcile", and
// records what that pass found on the restore report so the storage page
// can say which nodes the restored CA reached and which have not said what
// they trust.
//
// Every wait here has a deadline. Nothing depends on this goroutine: the
// scheduled reconcile converges the same nodes on its own tick.

const (
	// restoreTrustMeshDeadline bounds the wait for the mesh to come up after
	// the restart. Self-hosted Headscale pulls nothing on a warm box and is
	// up in seconds; a cold pull can take a minute or two.
	restoreTrustMeshDeadline = 5 * time.Minute
	// restoreTrustSettle is how long, after the mesh is ready, to let agents
	// re-register (they reconnect within seconds of the api restart, and the
	// registration is what carries the fingerprint) before comparing.
	restoreTrustSettle = 10 * time.Second
	// restoreTrustReconcileDeadline bounds the wait for the kicked reconcile
	// to reach a terminal state.
	restoreTrustReconcileDeadline = 3 * time.Minute
)

// kickTrustConvergenceAfterRestore runs in the background on the start that
// applied an identity restore.
func kickTrustConvergenceAfterRestore(ctx context.Context, meshSvc *mesh.Service, runner *jobs.Runner, jstore *jobs.Store, st *storage.Store, reportID string) {
	record := func(rec *storage.TrustRedeliveryRecord) {
		rec.CheckedAt = time.Now().UTC()
		if err := st.RecordRestoreTrustRedelivery(ctx, reportID, rec); err != nil {
			log.Printf("rasputin-api: restore %s: record trust re-delivery: %v", reportID, err)
		}
	}
	fail := func(detail string) {
		log.Printf("rasputin-api: restore %s: %s", reportID, detail)
		record(&storage.TrustRedeliveryRecord{
			CAFingerprint: meshSvc.MeshCAFingerprint(),
			Redelivered:   []string{}, Stale: []string{}, Current: []string{}, Unreported: []string{},
			Detail: detail,
		})
	}

	if !waitUntil(ctx, restoreTrustMeshDeadline, meshSvc.Ready) {
		if ctx.Err() != nil {
			return
		}
		fail(fmt.Sprintf("the mesh was not ready within %s of the restore; the scheduled mesh.reconcile will re-deliver the restored mesh CA to any node still trusting the replaced one once it is", restoreTrustMeshDeadline))
		return
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(restoreTrustSettle):
	}

	j, err := runner.Submit(ctx, "mesh.reconcile", json.RawMessage("{}"), "restore-trust")
	if err != nil {
		fail(fmt.Sprintf("could not submit the post-restore mesh.reconcile: %v; the scheduled one will re-deliver the restored mesh CA", err))
		return
	}
	log.Printf("rasputin-api: restore %s: kicked mesh.reconcile %s to re-deliver the restored mesh CA (%s) to any node still trusting the replaced one",
		reportID, j.ID, proto.ShortFingerprint(meshSvc.MeshCAFingerprint()))

	var final *jobs.Job
	done := waitUntil(ctx, restoreTrustReconcileDeadline, func() bool {
		got, err := jstore.GetJob(ctx, j.ID)
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
		if ctx.Err() != nil {
			return
		}
		fail(fmt.Sprintf("the post-restore mesh.reconcile %s did not finish within %s; the scheduled one will re-deliver the restored mesh CA", j.ID, restoreTrustReconcileDeadline))
		return
	}

	// The converge_trust step's result is the record, whether or not a later
	// step of the reconcile failed.
	steps, err := jstore.ListSteps(ctx, j.ID)
	if err != nil {
		fail(fmt.Sprintf("the post-restore mesh.reconcile %s finished %s but its steps could not be read: %v", j.ID, final.Status, err))
		return
	}
	var res *mesh.TrustConvergeResult
	for _, s := range steps {
		if s.Name != "converge_trust" || len(s.Result) == 0 {
			continue
		}
		var r mesh.TrustConvergeResult
		if json.Unmarshal(s.Result, &r) == nil {
			res = &r
		}
	}
	if res == nil {
		detail := fmt.Sprintf("the post-restore mesh.reconcile %s finished %s before its converge_trust step ran", j.ID, final.Status)
		if final.Error != "" {
			detail += ": " + final.Error
		}
		fail(detail + "; the scheduled reconcile will re-deliver the restored mesh CA")
		return
	}
	rec := &storage.TrustRedeliveryRecord{
		CAFingerprint: res.CAFingerprint,
		Redelivered:   orEmpty(res.Redelivered),
		Stale:         orEmpty(res.Stale),
		Current:       orEmpty(res.Current),
		Unreported:    orEmpty(res.Unreported),
		Skipped:       res.Skipped,
	}
	if final.Status != jobs.StatusSucceeded && final.Error != "" {
		rec.Detail = fmt.Sprintf("the post-restore mesh.reconcile %s finished %s after converge_trust: %s", j.ID, final.Status, final.Error)
	}
	record(rec)
	log.Printf("rasputin-api: restore %s: mesh CA %s re-delivered to %d node(s) [%s]; %d current; %d not yet reported [%s]; %d stale held back %v",
		reportID, proto.ShortFingerprint(rec.CAFingerprint), len(rec.Redelivered), strings.Join(rec.Redelivered, ", "),
		len(rec.Current), len(rec.Unreported), strings.Join(rec.Unreported, ", "), len(rec.Stale)-len(rec.Redelivered), rec.Skipped)
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
