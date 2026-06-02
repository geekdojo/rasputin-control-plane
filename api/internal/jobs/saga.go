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
}

// Workflow is a registered, named sequence of WorkflowSteps. Workflows are
// linear sagas: steps run in order; a step's failure terminates the job.
type Workflow struct {
	Kind  string
	Steps []WorkflowStep
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
}

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

// Register adds a Workflow to the runner's registry. Calling Register after
// the runner is in use is safe.
func (r *Runner) Register(w Workflow) {
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
		log.Printf("jobs: recovered (failed) %s [%s]", j.ID, j.Kind)
	}
	return nil
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
			now := time.Now().UTC()
			_ = r.store.MarkJobFailed(ctx, j.ID, err.Error(), now)
			r.emit(ctx, j.ID, proto.JobFailed, map[string]string{"error": err.Error()})
			return
		}
	}
	now = time.Now().UTC()
	_ = r.store.MarkJobSucceeded(ctx, j.ID, now)
	r.emit(ctx, j.ID, proto.JobSucceeded, nil)
}

func (r *Runner) runStep(ctx context.Context, j *Job, seq int, step WorkflowStep, prior map[string]json.RawMessage) error {
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
