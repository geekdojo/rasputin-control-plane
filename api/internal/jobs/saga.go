package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
	"github.com/oklog/ulid/v2"
)

// StepCtx is the per-step context handed to a WorkflowStep's Do function.
type StepCtx struct {
	Ctx   context.Context
	JobID string
	Spec  json.RawMessage
	NATS  *nats.Conn
	// PriorResults holds the json.RawMessage each previously-completed
	// step in this workflow returned, keyed by step name. Steps that
	// returned nil are absent. Lets a later step reuse an earlier
	// step's output (e.g. install reading precheck's ack) without
	// re-issuing the RPC. nil-safe — a freshly-constructed StepCtx may
	// have a nil map.
	PriorResults map[string]json.RawMessage
	// Log appends a log line both to the persistent job_events table and to
	// the live NATS event stream so the UI sees it in real time.
	Log func(level, message string)
}

// DoFn executes one step. It may return a JSON-encodable result that will be
// recorded against the step. A non-nil error triggers the step's retry
// policy and, on exhaustion, fails the job.
type DoFn func(sc *StepCtx) (json.RawMessage, error)

// WorkflowStep declares one step of a Workflow.
type WorkflowStep struct {
	Name    string
	Do      DoFn
	Timeout time.Duration
	Retries int // additional attempts beyond the first

	// Irreversible declares that this step's side effect cannot be undone by
	// the saga: there is no compensation in this runner, so once the step has
	// run, running it again does the thing a second time. A `dd` into a slot,
	// a mkfs, a mint-and-hand-out of a credential.
	//
	// Declaring it changes two things in the runner:
	//
	//  1. The step is never auto-retried, whatever Retries says. Register
	//     REJECTS a workflow that declares both (see ValidateWorkflow); the
	//     runner also clamps maxAttempts to 1 so a Workflow assembled without
	//     going through Register cannot slip past.
	//  2. The step refuses to run at all when the ledger already holds a
	//     record of it for this job — see assertNoPriorAttempt. It fails the
	//     job with ErrIrreversibleReplay rather than repeating the effect.
	//
	// Declarative rather than by convention, deliberately. A step that depends
	// on its author remembering `Retries: 0` reads as correct in review and is
	// wrong the first time someone copies an existing workflow as a starting
	// point.
	//
	// This is the DECLARATION, not the mechanism that makes a re-run safe. The
	// agent-side operation ledger is what would make such a step idempotent;
	// until that exists the runner's answer to "did this already happen?" is to
	// refuse, not to reconcile.
	Irreversible bool
}

// Workflow is a registered, named sequence of WorkflowSteps. Workflows are
// linear sagas: steps run in order; a step's failure terminates the job.
type Workflow struct {
	Kind  string
	Steps []WorkflowStep

	// OnTerminal, when set, fires exactly once when a job of this Kind reaches
	// a terminal state — from run() on both success and failure, from Recover()
	// for jobs orphaned by an api restart, and from FinishDeferred() for jobs a
	// resume handler drove to an outcome. ADR-0005 Decision 5.
	//
	// It exists because a workflow can own state the runner knows nothing
	// about. node.update writes a per-node row that only ever reached a
	// terminal status on the verify/commit path, so a saga that failed at
	// download, install, or verify left the row reading `in_progress` forever
	// while the job itself was correctly `failed` — the Updates page then
	// rendered a failed run as one still in progress (#53, and reproduced on
	// e3bench 2026-08-12 by a firewall update that failed at step 5).
	//
	// A workflow hook rather than a JobFailed bus subscriber, deliberately: it
	// keeps the runner generic — the runner still knows nothing about
	// node_updates, the knowledge lives in the workflow that owns the table —
	// while being in-process, synchronous, and unit-testable with no bus
	// round-trip or delivery-ordering risk.
	//
	// The hook must be idempotent. It is called once per terminal transition,
	// but a job that Recover() defers and a resume handler later finishes will
	// see one call from the path that actually terminated it, and a workflow
	// that also finalizes its own row on the happy path will see a call for a
	// row already in a terminal state.
	OnTerminal func(ctx context.Context, jobID string, success bool, errMsg string)
}

// ErrStopWorkflow, returned by a step's Do, ends the saga *successfully*
// without running the remaining steps. Use it for guard steps that decide the
// rest of the workflow is a no-op (e.g. firewall apply/reconcile in LAN-peer
// mode, where the box is idle). Distinct from any other error, which fails the
// job. Not retried — the step is marked succeeded and the job completes.
var ErrStopWorkflow = errors.New("jobs: stop workflow early")

// ErrIrreversibleReplay is the error a job fails with when the runner declines
// to run an Irreversible step because the ledger already holds a record of that
// step for this job — or because it could not read the ledger to find out.
//
// The message is deliberately fixed and greppable: it is the string an operator
// sees on the failed job, and the string a log sweep looks for. It is a refusal,
// not a crash: the effect did NOT happen a second time, and the job was failed
// so a human decides what to do next.
var ErrIrreversibleReplay = errors.New("jobs: irreversible step refused")

// ValidateWorkflow reports programming errors in a Workflow that the runner
// must not paper over at runtime. Register calls it and panics on a non-nil
// result; call it directly to check a Workflow without that.
func ValidateWorkflow(w Workflow) error {
	for i, s := range w.Steps {
		if s.Irreversible && s.Retries > 0 {
			return fmt.Errorf("jobs: workflow %q step %d (%q): an Irreversible step cannot declare Retries (got %d) — a retry would repeat the side effect the declaration exists to protect",
				w.Kind, i, s.Name, s.Retries)
		}
	}
	return nil
}

// Runner is the saga executor. One Runner per api process; workflows are
// registered at startup and looked up at Submit time.
type Runner struct {
	store     *Store
	nc        *nats.Conn
	mu        sync.RWMutex
	workflows map[string]Workflow
	wg        sync.WaitGroup
	// backoff returns the delay to wait before retry N (1-indexed).
	// Defaults to N seconds — preserves the previous hard-coded behavior
	// in production while letting tests inject a near-zero delay so
	// "step succeeds on retry" cases don't pay a real second per attempt.
	backoff func(attempt int) time.Duration
	// recoverDecider, when set, is consulted per in-flight job during Recover.
	// Returning RecoverDefer leaves the job *running* instead of failing it —
	// for workflows whose completion intentionally spans the api's own restart
	// (the control-plane self-update reboots the api mid-saga; a separate
	// resume handler finishes the job). Default (nil) = fail everything, the
	// v0 "abort, not resume" policy. See architecture O-8.
	recoverDecider func(j *Job, steps []*JobStep) RecoverDecision
}

// RecoverDecision is what to do with an in-flight job found at startup.
type RecoverDecision int

const (
	// RecoverFail marks the job failed ("control plane restarted mid-job") —
	// the default, v0 abort-not-resume behavior.
	RecoverFail RecoverDecision = iota
	// RecoverDefer leaves the job running for a separate resume handler that
	// owns its completion (e.g. the self-update reconciler).
	RecoverDefer
)

// DefaultBackoff is the production retry-delay schedule: N seconds before
// retry N. Exported so callers / tests can wrap it.
func DefaultBackoff(attempt int) time.Duration { return time.Duration(attempt) * time.Second }

// NewRunner constructs a Runner bound to a Store and NATS connection.
func NewRunner(store *Store, nc *nats.Conn) *Runner {
	return &Runner{
		store:     store,
		nc:        nc,
		workflows: make(map[string]Workflow),
		backoff:   DefaultBackoff,
	}
}

// SetBackoff overrides the retry-delay function. Intended for tests that
// want runStep to retry without waiting; production callers should leave
// the default in place. Safe to call before or after Start; a nil hook
// resets to DefaultBackoff so the runner never ends up with a nil
// callback at the time-sensitive moment.
func (r *Runner) SetBackoff(fn func(attempt int) time.Duration) {
	if fn == nil {
		fn = DefaultBackoff
	}
	r.backoff = fn
}

// SetRecoverDecider installs a policy consulted for each in-flight job during
// Recover (see RecoverDecision). nil restores the default fail-everything
// behavior. Set before Recover runs.
func (r *Runner) SetRecoverDecider(fn func(j *Job, steps []*JobStep) RecoverDecision) {
	r.recoverDecider = fn
}

// Register adds a Workflow to the runner's registry. Calling Register after
// the runner is in use is safe.
//
// It PANICS on a workflow that fails ValidateWorkflow. Registration happens
// once, at api startup, from a call site with no error path (main.go registers
// two dozen workflows as bare statements), so the only fail-closed option is to
// refuse to come up. The alternative — accept the workflow and quietly ignore
// its Retries — leaves the author's stated intent and the runner's behaviour
// permanently disagreeing, in the one place where that disagreement is
// unrecoverable. A boot that stops with the offending workflow and step named
// is a five-minute fix; a saga that silently means something other than what it
// says is the failure mode this field exists to remove.
func (r *Runner) Register(w Workflow) {
	if err := ValidateWorkflow(w); err != nil {
		panic(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.workflows[w.Kind] = w
}

// Submit creates a new Job and kicks it off in a background goroutine. The
// returned Job is the initial persisted state; callers should not assume it
// reflects later step progress (use GetJob for that).
func (r *Runner) Submit(ctx context.Context, kind string, spec json.RawMessage, createdBy string) (*Job, error) {
	return r.submit(ctx, kind, spec, createdBy, "")
}

// SubmitChild creates a new Job whose parent_id is set to parentID. The
// child runs in its own goroutine independently of the parent; the parent
// saga is expected to await terminal status via NATS or by polling the
// store. Used by orchestrating sagas like system.update.
func (r *Runner) SubmitChild(ctx context.Context, kind string, spec json.RawMessage, createdBy, parentID string) (*Job, error) {
	if parentID == "" {
		return nil, errors.New("SubmitChild requires a parentID; call Submit for a root job")
	}
	return r.submit(ctx, kind, spec, createdBy, parentID)
}

func (r *Runner) submit(ctx context.Context, kind string, spec json.RawMessage, createdBy, parentID string) (*Job, error) {
	// Normalize an absent spec to an empty object.
	//
	// spec is persisted verbatim into a TEXT column and scanned straight back
	// into a json.RawMessage (store.go). A nil/empty spec therefore round-trips
	// as RawMessage(""), which FAILS to marshal — "unexpected end of JSON
	// input" — and takes the entire /api/jobs response down with it, not just
	// the offending row. One specless job blanks the whole Tasks page.
	//
	// Every workflow that marshals a spec struct already yields "{}" at
	// minimum, so this just makes the genuinely specless kinds (obs.enable /
	// obs.disable) match rather than poison the list.
	if len(spec) == 0 {
		spec = json.RawMessage("{}")
	}
	r.mu.RLock()
	wf, ok := r.workflows[kind]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown job kind %q", kind)
	}

	j := &Job{
		ID:        ulid.Make().String(),
		Kind:      kind,
		Spec:      spec,
		Status:    StatusQueued,
		CreatedBy: createdBy,
		CreatedAt: time.Now().UTC(),
	}
	if parentID != "" {
		j.ParentID = &parentID
	}
	if err := r.store.CreateJob(ctx, j); err != nil {
		return nil, fmt.Errorf("create job: %w", err)
	}
	r.emit(ctx, j.ID, proto.JobCreated, j)

	r.wg.Add(1)
	go r.run(j, wf)
	return j, nil
}

// Wait blocks until all running jobs finish. Used by main during shutdown.
func (r *Runner) Wait() { r.wg.Wait() }

// Recover marks any in-flight (queued or running) jobs as failed. Called at
// api startup to keep the ledger honest after a crash or restart. v0 policy
// is conservative: we abort, we don't resume. Resume would require knowing
// whether each step's side effects had been applied, which we don't track
// yet (it's a v1 problem; see architecture doc §6.4).
func (r *Runner) Recover(ctx context.Context) error {
	inFlight, err := r.store.ListJobsByStatus(ctx, []Status{StatusQueued, StatusRunning})
	if err != nil {
		return err
	}
	const msg = "control plane restarted mid-job"
	for _, j := range inFlight {
		if r.recoverDecider != nil {
			steps, _ := r.store.ListSteps(ctx, j.ID)
			if r.recoverDecider(j, steps) == RecoverDefer {
				log.Printf("jobs: recover %s [%s]: deferred to a resume handler (left running)", j.ID, j.Kind)
				continue
			}
		}
		now := time.Now().UTC()
		if err := r.store.MarkJobFailed(ctx, j.ID, msg, now); err != nil {
			log.Printf("jobs: recover %s: %v", j.ID, err)
			continue
		}
		steps, _ := r.store.ListSteps(ctx, j.ID)
		for _, st := range steps {
			if st.Status == StepRunning {
				_ = r.store.MarkStepFailed(ctx, j.ID, st.Seq, msg, now)
			}
		}
		r.emit(ctx, j.ID, proto.JobFailed, map[string]any{
			"error":     msg,
			"recovered": true,
		})
		// An orphan is exactly the case the hook exists for: nothing else will
		// ever run for this job, so whatever state the workflow owns is stranded
		// unless it is finalized here.
		if wf, ok := r.workflowFor(j.Kind); ok {
			r.fireTerminal(ctx, wf, j.ID, false, msg)
		}
		log.Printf("jobs: recovered (failed) %s [%s]", j.ID, j.Kind)
	}
	return nil
}

// FinishDeferred terminally completes a job that Recover left running
// (RecoverDefer) once a resume handler has driven it to an outcome. Marks the
// job succeeded/failed and emits the matching job event so the UI updates live,
// exactly as a normally-run job would. errMsg is ignored on success.
func (r *Runner) FinishDeferred(ctx context.Context, jobID string, success bool, errMsg string) {
	now := time.Now().UTC()
	// This is a terminal transition like any other, and the ADR's list of hook
	// sites predates it. A deferred job that a resume handler fails — a
	// self-update whose post-reboot verify did not pass — strands its workflow
	// state exactly as a step failure would, so it fires the hook too.
	var wf Workflow
	haveWF := false
	if j, err := r.store.GetJob(ctx, jobID); err == nil && j != nil {
		wf, haveWF = r.workflowFor(j.Kind)
	}
	if success {
		_ = r.store.MarkJobSucceeded(ctx, jobID, now)
		r.emit(ctx, jobID, proto.JobSucceeded, nil)
		if haveWF {
			r.fireTerminal(ctx, wf, jobID, true, "")
		}
		return
	}
	_ = r.store.MarkJobFailed(ctx, jobID, errMsg, now)
	r.emit(ctx, jobID, proto.JobFailed, map[string]string{"error": errMsg})
	if haveWF {
		r.fireTerminal(ctx, wf, jobID, false, errMsg)
	}
}

func (r *Runner) run(j *Job, wf Workflow) {
	defer r.wg.Done()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := r.store.MarkJobStarted(ctx, j.ID, now); err != nil {
		log.Printf("jobs: mark started %s: %v", j.ID, err)
	}
	r.emit(ctx, j.ID, proto.JobStarted, nil)

	prior := make(map[string]json.RawMessage, len(wf.Steps))
	for seq, step := range wf.Steps {
		if err := r.runStep(ctx, j, seq, step, prior); err != nil {
			if errors.Is(err, ErrStopWorkflow) {
				// Guard step decided the rest is a no-op — succeed early.
				break
			}
			now := time.Now().UTC()
			_ = r.store.MarkJobFailed(ctx, j.ID, err.Error(), now)
			r.emit(ctx, j.ID, proto.JobFailed, map[string]string{"error": err.Error()})
			r.fireTerminal(ctx, wf, j.ID, false, err.Error())
			return
		}
	}
	now = time.Now().UTC()
	_ = r.store.MarkJobSucceeded(ctx, j.ID, now)
	r.emit(ctx, j.ID, proto.JobSucceeded, nil)
	r.fireTerminal(ctx, wf, j.ID, true, "")
}

// fireTerminal invokes a workflow's OnTerminal hook, if it has one.
//
// The panic guard is load-bearing rather than defensive habit: the hook is
// workflow-owned code touching a store the runner does not know about, and it
// runs on the runner's goroutine AFTER the job ledger has already been made
// consistent. A panic there must not unwind past this point and take the runner
// down or, worse, make a correctly-recorded job look like a crash.
func (r *Runner) fireTerminal(ctx context.Context, wf Workflow, jobID string, success bool, errMsg string) {
	if wf.OnTerminal == nil {
		return
	}
	defer func() {
		if p := recover(); p != nil {
			log.Printf("jobs: OnTerminal %s [%s] panicked: %v", jobID, wf.Kind, p)
		}
	}()
	wf.OnTerminal(ctx, jobID, success, errMsg)
}

// workflowFor looks up a registered workflow by kind. Returns false for a kind
// this process has no workflow for, which is normal after a downgrade: the
// ledger can hold jobs whose workflow no longer exists.
func (r *Runner) workflowFor(kind string) (Workflow, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	wf, ok := r.workflows[kind]
	return wf, ok
}

// assertNoPriorAttempt refuses an Irreversible step whose execution this job's
// ledger already records.
//
// The check reads the ledger rather than trusting the in-memory loop, because
// the loop is not the only thing that can reach a step: a job can be resumed
// after a Recover left it running (RecoverDefer), and a workflow's step list
// can differ between the process that started the job and the process that
// picks it up. Both are ways for run() to arrive at a step that already
// happened while believing it is running it for the first time.
//
// Matching is on seq OR name, not seq alone, and that asymmetry is on purpose:
// if a workflow's step list changed between the two processes, seq no longer
// identifies the same step, and the only safe reading of "there is a record
// named install" is that install ran. Over-refusing costs a failed job an
// operator can inspect; under-refusing costs a second `dd`.
//
// It does NOT touch the existing step row. That row is the record of what
// actually happened — succeeded, failed, or running when the process died — and
// overwriting it with this refusal would destroy the only evidence of the very
// thing being refused.
func (r *Runner) assertNoPriorAttempt(ctx context.Context, jobID string, seq int, step WorkflowStep) error {
	steps, err := r.store.ListSteps(ctx, jobID)
	if err != nil {
		// Fail closed. Not knowing whether the side effect already happened is
		// the same as knowing that it might have.
		return fmt.Errorf("%w: job %s step %d (%q): cannot read the step ledger: %v",
			ErrIrreversibleReplay, jobID, seq, step.Name, err)
	}
	for _, st := range steps {
		if st.Seq != seq && st.Name != step.Name {
			continue
		}
		return fmt.Errorf("%w: job %s step %d (%q) already has a recorded attempt (ledger seq %d %q, status %s, attempt %d); an irreversible step is never re-run",
			ErrIrreversibleReplay, jobID, seq, step.Name, st.Seq, st.Name, st.Status, st.Attempt)
	}
	return nil
}

func (r *Runner) runStep(ctx context.Context, j *Job, seq int, step WorkflowStep, prior map[string]json.RawMessage) error {
	if step.Irreversible {
		// Before CreateStep, deliberately: creating the row is itself the
		// record of an attempt, and on a replay the row is already there.
		if err := r.assertNoPriorAttempt(ctx, j.ID, seq, step); err != nil {
			log.Printf("jobs: %v", err)
			// Event only — no store write. The refusal is why the JOB fails
			// (run() records that); the step row keeps the prior attempt's
			// verdict.
			r.emit(ctx, j.ID, proto.JobStepFailed, proto.StepEventData{
				Seq: seq, Name: step.Name, Error: err.Error(),
			})
			return err
		}
	}
	startedAt := time.Now().UTC()
	stepRow := &JobStep{
		JobID:     j.ID,
		Seq:       seq,
		Name:      step.Name,
		Status:    StepRunning,
		StartedAt: &startedAt,
	}
	if err := r.store.CreateStep(ctx, stepRow); err != nil {
		log.Printf("jobs: create step %s/%d: %v", j.ID, seq, err)
	}
	r.emit(ctx, j.ID, proto.JobStepStarted, proto.StepEventData{Seq: seq, Name: step.Name})

	var lastErr error
	maxAttempts := step.Retries + 1
	if step.Irreversible {
		// Never auto-retry, whatever Retries says. Register rejects the
		// combination outright, so in practice this only fires for a Workflow
		// that never went through Register (a hand-built one in a test, or a
		// future caller that bypasses the registry) — which is exactly the case
		// a validation-only guard would miss.
		maxAttempts = 1
	}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			r.emit(ctx, j.ID, proto.JobStepRetrying, proto.StepEventData{
				Seq: seq, Name: step.Name, Attempt: attempt, Error: lastErr.Error(),
			})
			delay := r.backoff(attempt)
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
		stepCtx, cancel := context.WithTimeout(ctx, step.Timeout)
		sc := &StepCtx{
			Ctx:          stepCtx,
			JobID:        j.ID,
			Spec:         j.Spec,
			NATS:         r.nc,
			PriorResults: prior,
			Log: func(level, message string) {
				r.emit(ctx, j.ID, proto.JobLog, proto.LogEventData{
					Level: level, Message: message,
				})
			},
		}
		result, err := step.Do(sc)
		cancel()
		if err == nil {
			_ = r.store.MarkStepSucceeded(ctx, j.ID, seq, attempt, result, time.Now().UTC())
			r.emit(ctx, j.ID, proto.JobStepSucceeded, proto.StepEventData{
				Seq: seq, Name: step.Name, Attempt: attempt, Result: result,
			})
			if prior != nil && result != nil {
				prior[step.Name] = result
			}
			return nil
		}
		// A stop-early signal marks the step succeeded (not failed) and
		// propagates up so run() can end the saga successfully. Never retried.
		if errors.Is(err, ErrStopWorkflow) {
			_ = r.store.MarkStepSucceeded(ctx, j.ID, seq, attempt, result, time.Now().UTC())
			r.emit(ctx, j.ID, proto.JobStepSucceeded, proto.StepEventData{
				Seq: seq, Name: step.Name, Attempt: attempt, Result: result,
			})
			return ErrStopWorkflow
		}
		lastErr = err
	}
	_ = r.store.MarkStepFailed(ctx, j.ID, seq, lastErr.Error(), time.Now().UTC())
	r.emit(ctx, j.ID, proto.JobStepFailed, proto.StepEventData{
		Seq: seq, Name: step.Name, Error: lastErr.Error(),
	})
	return lastErr
}

// emit persists a job event and publishes it on the live NATS subject.
// Best-effort: failures are logged but do not fail the saga.
func (r *Runner) emit(ctx context.Context, jobID string, t proto.JobEventType, data any) {
	var raw json.RawMessage
	if data != nil {
		b, err := json.Marshal(data)
		if err == nil {
			raw = b
		}
	}
	now := time.Now().UTC()
	if err := r.store.AppendEvent(ctx, jobID, string(t), raw, now); err != nil {
		log.Printf("jobs: append event %s/%s: %v", jobID, t, err)
	}
	ev := proto.JobEvent{Type: t, JobID: jobID, Ts: now, Data: raw}
	payload, err := json.Marshal(ev)
	if err != nil {
		return
	}
	if err := r.nc.Publish(proto.JobEventsSubject(jobID), payload); err != nil {
		log.Printf("jobs: publish event %s/%s: %v", jobID, t, err)
	}
}
