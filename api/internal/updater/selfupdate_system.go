package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Self-update, one level up: how a FLEET update survives the api rebooting
// itself (#56, ADR-0005 Decision 9).
//
// selfupdate.go solves the single-node case — a node.update targeting the
// controlplane defers at Recover and finishes on the new slot. That leaves the
// parent. Before #56 the cascade excluded self entirely, so the question never
// arose; now self is an ordinary target and the `system.update` job dies with
// its own orchestrator, mid-`cascade`, exactly like the child.
//
// What makes this tractable rather than "resume a distributed cascade" is
// ORDER. Self is planned strictly last (planTargets), the tier sort puts the
// controlplane after compute and storage, and the component filter means no
// firewall target ever shares a run with it. So when the api goes down there
// is nothing left to orchestrate — every other target has already reached a
// terminal state — and resuming degenerates into: wait for the self child to
// finish on its own resume path, rebuild the report, close the parent.
//
// The rebuild is the part worth stating plainly. The normal summarize step
// reads the cascade's in-memory grid out of sc.PriorResults; that map died
// with the old api, AND the cascade step never completed, so it recorded no
// durable result either. The grid is therefore RECONSTRUCTED from the two
// things that did survive: the plan step's persisted result (which targets,
// which tier, which arch, which canary) and the child jobs' terminal statuses
// (what happened to each). Those are the same two sources summarize falls back
// to, so a resumed run reports in the same shape as a normal one.

// resumeChildWait bounds how long the parent waits for the self child to reach
// a terminal state after the api comes back.
//
// It is a deadline, not a hope: the child has its own 5-minute bounded wait for
// the agent plus a health battery, so anything past this means the child's
// resume path itself is not going to finish, and a parent that waits forever is
// a job that reads `running` in the UI until someone restarts the api.
const resumeChildWait = 15 * time.Minute

// resumeChildPoll is how often the parent checks the child's status. The child
// is one job and the wait is minutes, so a slow poll costs nothing.
const resumeChildPoll = 5 * time.Second

// SystemUpdateDeferred reports whether an in-flight `system.update` should be
// DEFERRED at Recover rather than failed — i.e. whether this api restart is the
// one its own cascade caused.
//
// The distinguishing evidence is the self child being past its reboot step. An
// api that crashed for any other reason — a panic mid-compute-tier, an operator
// restart, a power cut — has no such child and must fail normally, because
// deferring it would leave a zombie `running` job that nothing will ever
// finish. "The plan contains self" is deliberately NOT sufficient: it is true
// from the moment the run starts, including for the crash cases.
func SystemUpdateDeferred(ctx context.Context, jobStore *jobs.Store, j *jobs.Job, selfNodeID string) bool {
	if selfNodeID == "" || j.Kind != "system.update" {
		return false
	}
	child := selfChildOf(ctx, jobStore, j.ID, selfNodeID)
	if child == nil {
		return false
	}
	childSteps, err := jobStore.ListSteps(ctx, child.ID)
	if err != nil {
		return false
	}
	return rebootDone(childSteps)
}

// selfChildOf returns the node.update child of parentID that targets
// selfNodeID, or nil.
func selfChildOf(ctx context.Context, jobStore *jobs.Store, parentID, selfNodeID string) *jobs.Job {
	children, err := jobStore.ListChildJobs(ctx, parentID)
	if err != nil {
		return nil
	}
	for _, c := range children {
		if c.Kind != "node.update" {
			continue
		}
		var spec UpdateSpec
		if json.Unmarshal(c.Spec, &spec) != nil || spec.NodeID != selfNodeID {
			continue
		}
		return c
	}
	return nil
}

// ResumeSystemUpdates finishes any fleet update left in flight when the api
// rebooted itself as the last target of its own cascade. Call once at startup,
// AFTER Recover (which deferred these) and alongside ResumeSelfUpdates, which
// drives the child this waits on. Non-blocking: each candidate runs in its own
// goroutine.
func ResumeSystemUpdates(
	ctx context.Context,
	jobStore *jobs.Store,
	runner *jobs.Runner,
	nc *nats.Conn,
	selfNodeID string,
) {
	if selfNodeID == "" {
		return
	}
	running, err := jobStore.ListJobsByStatus(ctx, []jobs.Status{jobs.StatusRunning})
	if err != nil {
		log.Printf("updater: resume system-update: list jobs: %v", err)
		return
	}
	for _, j := range running {
		if j.Kind != "system.update" {
			continue
		}
		child := selfChildOf(ctx, jobStore, j.ID, selfNodeID)
		if child == nil {
			// Recover deferred this, so a child was there a moment ago.
			// Failing it is the honest move: nothing will finish it otherwise.
			runner.FinishDeferred(ctx, j.ID, false,
				"resumed after the controlplane's own reboot, but its update child is gone — the run cannot be reported")
			continue
		}
		go resumeSystemUpdate(ctx, jobStore, runner, nc, j.ID, child.ID, selfNodeID)
	}
}

func resumeSystemUpdate(
	ctx context.Context,
	jobStore *jobs.Store,
	runner *jobs.Runner,
	nc *nats.Conn,
	parentID, childID, selfNodeID string,
) {
	log.Printf("updater: resuming fleet update %s after the controlplane's own reboot (self child %s)", parentID, childID)

	status, err := awaitChildTerminal(ctx, jobStore, childID)
	if err != nil {
		// The child never settled. Report what IS known rather than nothing —
		// every other target already finished before the api went down, and
		// that report is the operator's whole picture of the run.
		log.Printf("updater: fleet update %s: self child %s never settled: %v", parentID, childID, err)
		finishResumed(ctx, jobStore, runner, nc, parentID, selfNodeID, jobs.StatusFailed,
			fmt.Sprintf("the controlplane's own update never reported an outcome after the reboot: %v", err))
		return
	}
	finishResumed(ctx, jobStore, runner, nc, parentID, selfNodeID, status, "")
}

// awaitChildTerminal polls the self child until it reaches a terminal status or
// the deadline passes. The child is driven independently by ResumeSelfUpdates;
// this only observes it, which is the same relationship the live cascade has
// with its children.
func awaitChildTerminal(ctx context.Context, jobStore *jobs.Store, childID string) (jobs.Status, error) {
	deadline := time.Now().Add(resumeChildWait)
	for {
		j, err := jobStore.GetJob(ctx, childID)
		if err != nil {
			return "", fmt.Errorf("read child %s: %w", childID, err)
		}
		if j == nil {
			return "", fmt.Errorf("child %s no longer exists", childID)
		}
		switch j.Status {
		case jobs.StatusSucceeded, jobs.StatusFailed, jobs.StatusCancelled:
			return j.Status, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("still %s after %s", j.Status, resumeChildWait)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(resumeChildPoll):
		}
	}
}

// finishResumed rebuilds the report from durable state, publishes it, and
// closes the parent — the resumed equivalent of the summarize step.
//
// Publishing BEFORE deciding the parent's colour mirrors systemSummarize
// deliberately: the operator needs the report in order to act on it, and a
// path that errors before publishing takes the report down with it.
func finishResumed(
	ctx context.Context,
	jobStore *jobs.Store,
	runner *jobs.Runner,
	nc *nats.Conn,
	parentID, selfNodeID string,
	selfStatus jobs.Status,
	selfDetail string,
) {
	plan, grid, err := rebuildReport(ctx, jobStore, parentID, selfNodeID, selfStatus, selfDetail)
	if err != nil {
		log.Printf("updater: fleet update %s: rebuild report: %v", parentID, err)
		runner.FinishDeferred(ctx, parentID, false,
			"resumed after the controlplane's own reboot but could not rebuild the run's report: "+err.Error())
		return
	}

	var succeeded, failed, notAttempted int
	for _, r := range grid {
		switch r.Outcome {
		case proto.NodeOutcomeSucceeded:
			succeeded++
		case proto.NodeOutcomeFailed:
			failed++
		case proto.NodeOutcomeNotAttempted:
			notAttempted++
		}
	}
	stranded := plan.stranded()
	counts := &proto.SystemUpdateCounts{
		Total:        len(grid),
		Succeeded:    succeeded,
		Failed:       failed,
		Skipped:      len(plan.Skipped),
		Stranded:     len(stranded),
		NotAttempted: notAttempted,
	}
	publishSystemChange(nc, proto.SystemUpdateChangeEvt{
		ParentJobID: parentID,
		Change:      proto.SystemUpdateCompleted,
		Counts:      counts,
		Skipped:     plan.Skipped,
		Results:     grid,
		Ts:          time.Now().UTC(),
	})
	log.Printf("updater: fleet update %s complete across the controlplane's reboot: %d succeeded, %d failed, %d never started",
		parentID, succeeded, failed, notAttempted)

	// The parent's colour, on the same rules systemSummarize applies: any
	// failed node fails the run, and a stranded node fails it even when every
	// child committed — the run still did not do what UPDATE ALL says.
	switch {
	case failed > 0:
		runner.FinishDeferred(ctx, parentID, false,
			fmt.Sprintf("%d of %d node(s) failed", failed, len(grid)))
	case len(stranded) > 0:
		ids := make([]string, len(stranded))
		for i, sk := range stranded {
			ids[i] = sk.NodeID
		}
		runner.FinishDeferred(ctx, parentID, false,
			fmt.Sprintf("%d node(s) had no artifact for their architecture and were never updated (%v)",
				len(stranded), ids))
	default:
		runner.FinishDeferred(ctx, parentID, true, "")
	}
}

// rebuildReport reconstructs the per-node grid from the plan step's persisted
// result plus the child jobs' terminal statuses.
//
// Rows keep planned order, which is what makes two runs of the same update
// diffable — the same property the live cascade goes out of its way to hold.
func rebuildReport(
	ctx context.Context,
	jobStore *jobs.Store,
	parentID, selfNodeID string,
	selfStatus jobs.Status,
	selfDetail string,
) (systemPlanState, []proto.NodeResult, error) {
	var plan systemPlanState
	steps, err := jobStore.ListSteps(ctx, parentID)
	if err != nil {
		return plan, nil, fmt.Errorf("list steps: %w", err)
	}
	raw := stepResult(steps, "plan")
	if len(raw) == 0 {
		return plan, nil, fmt.Errorf("the plan step recorded no result, so the run's targets are unknown")
	}
	if err := json.Unmarshal(raw, &plan); err != nil {
		return plan, nil, fmt.Errorf("read plan result: %w", err)
	}

	children, err := jobStore.ListChildJobs(ctx, parentID)
	if err != nil {
		return plan, nil, fmt.Errorf("list children: %w", err)
	}
	byNode := map[string]*jobs.Job{}
	for _, c := range children {
		if c.Kind != "node.update" {
			continue
		}
		var spec UpdateSpec
		if json.Unmarshal(c.Spec, &spec) != nil {
			continue
		}
		byNode[spec.NodeID] = c
	}

	grid := make([]proto.NodeResult, 0, len(plan.Targets))
	for _, t := range plan.Targets {
		row := proto.NodeResult{
			NodeID: t.NodeID, Tier: t.Tier, Compatible: t.Compatible, Canary: t.Canary,
		}
		child, ok := byNode[t.NodeID]
		if !ok {
			// No child was ever submitted for this target. Under best-effort
			// that means the run stopped before reaching it — and since self
			// is planned last, a run that got as far as rebooting the api
			// should not have any. Recorded rather than dropped: a target
			// missing from the grid is the exact failure the grid exists to
			// prevent.
			row.Outcome = proto.NodeOutcomeNotAttempted
			row.Detail = "no update was started for this node before the controlplane rebooted"
			grid = append(grid, row)
			continue
		}
		row.ChildJobID = child.ID
		status := child.Status
		detail := child.Error
		if t.NodeID == selfNodeID {
			// The self row comes from the resume path, not the job record:
			// FinishDeferred may not have landed yet when this reads.
			status = selfStatus
			if selfDetail != "" {
				detail = selfDetail
			}
		}
		switch status {
		case jobs.StatusSucceeded:
			row.Outcome = proto.NodeOutcomeSucceeded
		case jobs.StatusFailed, jobs.StatusCancelled:
			row.Outcome = proto.NodeOutcomeFailed
			row.Detail = detail
		default:
			// Non-terminal at read time. Only reachable for a non-self target,
			// which ordering says should not happen — say so rather than
			// silently colouring it.
			row.Outcome = proto.NodeOutcomeNotAttempted
			row.Detail = fmt.Sprintf("still %s when the run was reported", status)
		}
		grid = append(grid, row)
	}
	return plan, grid, nil
}
