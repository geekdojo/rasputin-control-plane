package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
)

// startNATS spins up an in-process NATS server on a random port and returns a
// connected client. Server shuts down on test cleanup.
func startNATS(t *testing.T) *nats.Conn {
	t.Helper()
	srv := natsserver.RunRandClientPortServer()
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// waitForStatus polls the store for a job's terminal status. The runner runs
// jobs in a goroutine; we don't want deterministic-test-killing sleeps, so we
// just spin on the store with 10ms ticks and a 2s ceiling.
func waitForStatus(t *testing.T, store *Store, id string, target Status, timeout time.Duration) *Job {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		j, err := store.GetJob(context.Background(), id)
		if err != nil {
			t.Fatalf("GetJob: %v", err)
		}
		if j != nil && j.Status == target {
			return j
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job %s did not reach %s within %s", id, target, timeout)
	return nil
}

// ============================================================================
// Submit a synchronous, all-Go workflow and watch it run to success — exercises
// run, runStep (single-attempt), and emit.
// ============================================================================

func TestRunner_Submit_RunsWorkflowToSuccess(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	r := NewRunner(store, nc)

	var ran int32
	r.Register(Workflow{
		Kind: "test.sync.ok",
		Steps: []WorkflowStep{
			{Name: "a", Timeout: time.Second, Do: func(sc *StepCtx) (json.RawMessage, error) {
				atomic.AddInt32(&ran, 1)
				sc.Log("info", "step a")
				return json.RawMessage(`{"ok":true}`), nil
			}},
			{Name: "b", Timeout: time.Second, Do: func(sc *StepCtx) (json.RawMessage, error) {
				atomic.AddInt32(&ran, 1)
				return json.RawMessage(`{"b":1}`), nil
			}},
		},
	})

	// Subscribe to all rasputin.job.* events so we can confirm emit() runs.
	wildcardSub, err := nc.SubscribeSync("rasputin.job.>")
	if err != nil {
		t.Fatalf("wildcard sub: %v", err)
	}
	defer func() { _ = wildcardSub.Unsubscribe() }()

	j, err := r.Submit(context.Background(), "test.sync.ok", json.RawMessage(`{}`), "test")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if j.Status != StatusQueued {
		t.Errorf("initial Status: want queued, got %q", j.Status)
	}

	done := waitForStatus(t, store, j.ID, StatusSucceeded, 2*time.Second)
	if done.FinishedAt == nil {
		t.Errorf("FinishedAt should be set")
	}
	if atomic.LoadInt32(&ran) != 2 {
		t.Errorf("both steps should have run, got %d", atomic.LoadInt32(&ran))
	}

	// Confirm at least one job event was published.
	if _, err := wildcardSub.NextMsg(time.Second); err != nil {
		t.Errorf("expected job events on bus: %v", err)
	}

	// Ensure the Runner's wg unwinds.
	r.Wait()
}

// TestRunner_Submit_StepFailureMarksJobFailed exercises runStep's retry +
// failure path. Step returns an error on every attempt; with retries=1 we get
// two attempts, then the step is failed, then the job is failed.
func TestRunner_Submit_StepFailureMarksJobFailed(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	r := NewRunner(store, nc)

	var attempts int32
	r.Register(Workflow{
		Kind: "test.fail",
		Steps: []WorkflowStep{
			{
				Name:    "bad",
				Timeout: time.Second,
				Retries: 1,
				Do: func(sc *StepCtx) (json.RawMessage, error) {
					atomic.AddInt32(&attempts, 1)
					return nil, errors.New("nope")
				},
			},
		},
	})

	j, err := r.Submit(context.Background(), "test.fail", json.RawMessage(`{}`), "test")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	done := waitForStatus(t, store, j.ID, StatusFailed, 5*time.Second)
	if done.Error != "nope" {
		t.Errorf("error: %q", done.Error)
	}
	// 1 initial + 1 retry = 2 attempts.
	if atomic.LoadInt32(&attempts) != 2 {
		t.Errorf("attempts: want 2, got %d", atomic.LoadInt32(&attempts))
	}

	r.Wait()
}

// TestRunner_Submit_StepSucceedsOnRetry covers runStep's retry-then-succeed
// branch — the JobStepRetrying emit path. Uses SetBackoff(zero) so the
// test doesn't burn a real second per retry; production callers still get
// the DefaultBackoff (N seconds before retry N).
func TestRunner_Submit_StepSucceedsOnRetry(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	r := NewRunner(store, nc)
	r.SetBackoff(func(int) time.Duration { return 0 })

	var attempts int32
	r.Register(Workflow{
		Kind: "test.flaky",
		Steps: []WorkflowStep{
			{
				Name:    "flaky",
				Timeout: time.Second,
				Retries: 2,
				Do: func(sc *StepCtx) (json.RawMessage, error) {
					n := atomic.AddInt32(&attempts, 1)
					if n == 1 {
						return nil, errors.New("first try")
					}
					return json.RawMessage(`"ok"`), nil
				},
			},
		},
	})

	start := time.Now()
	j, err := r.Submit(context.Background(), "test.flaky", json.RawMessage(`{}`), "test")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	waitForStatus(t, store, j.ID, StatusSucceeded, 5*time.Second)
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("test took %v — backoff override not applied", elapsed)
	}
	if atomic.LoadInt32(&attempts) != 2 {
		t.Errorf("attempts: want 2, got %d", atomic.LoadInt32(&attempts))
	}
	r.Wait()
}

// TestRunner_SubmitChild_RunsWithParent exercises the SubmitChild non-empty
// parent path (ParentID set on the inserted row).
func TestRunner_SubmitChild_RunsWithParent(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	r := NewRunner(store, nc)

	r.Register(Workflow{
		Kind:  "test.child",
		Steps: []WorkflowStep{{Name: "noop", Timeout: time.Second, Do: func(sc *StepCtx) (json.RawMessage, error) { return nil, nil }}},
	})

	child, err := r.SubmitChild(context.Background(), "test.child", json.RawMessage(`{}`), "test", "parent-xyz")
	if err != nil {
		t.Fatalf("SubmitChild: %v", err)
	}
	if child.ParentID == nil || *child.ParentID != "parent-xyz" {
		t.Errorf("ParentID not set: %+v", child.ParentID)
	}
	waitForStatus(t, store, child.ID, StatusSucceeded, 2*time.Second)
	r.Wait()
}

// TestRunner_Recover_FailsInflightJobs covers Recover's non-empty path: a row
// in StatusRunning gets flipped to StatusFailed, and any running step too.
func TestRunner_Recover_FailsInflightJobs(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)
	r := NewRunner(store, nc)

	// Insert a job in Queued and another in Running with a running step.
	j1 := makeJob("j-q", "k")
	j1.Status = StatusQueued
	if err := store.CreateJob(ctx, j1); err != nil {
		t.Fatalf("CreateJob j-q: %v", err)
	}
	j2 := makeJob("j-r", "k")
	if err := store.CreateJob(ctx, j2); err != nil {
		t.Fatalf("CreateJob j-r: %v", err)
	}
	if err := store.MarkJobStarted(ctx, "j-r", time.Now().UTC()); err != nil {
		t.Fatalf("mark started: %v", err)
	}
	started := time.Now().UTC()
	if err := store.CreateStep(ctx, &JobStep{
		JobID:     "j-r",
		Seq:       0,
		Name:      "inflight",
		Status:    StepRunning,
		StartedAt: &started,
	}); err != nil {
		t.Fatalf("CreateStep: %v", err)
	}

	if err := r.Recover(ctx); err != nil {
		t.Fatalf("Recover: %v", err)
	}

	g1, _ := store.GetJob(ctx, "j-q")
	g2, _ := store.GetJob(ctx, "j-r")
	if g1.Status != StatusFailed {
		t.Errorf("j-q: want failed, got %q", g1.Status)
	}
	if g2.Status != StatusFailed {
		t.Errorf("j-r: want failed, got %q", g2.Status)
	}
	steps, _ := store.ListSteps(ctx, "j-r")
	if len(steps) != 1 || steps[0].Status != StepFailed {
		t.Errorf("step: want failed, got %+v", steps)
	}
}

// ============================================================================
// pingStep happy path: build a fake agent on the diag.ping subject that replies
// with a canned ack. Confirms the NATS request/response branch of pingStep
// (the only branch that isn't already covered by the spec-validation tests).
// ============================================================================

func TestPingStep_HappyPath_WithFakeAgent(t *testing.T) {
	nc := startNATS(t)

	const nodeID = "n-ping"
	sub, err := nc.Subscribe(proto.NodeCmdSubject(nodeID, "diag.ping"), func(m *nats.Msg) {
		_ = m.Respond([]byte(`{"ok":true}`))
	})
	if err != nil {
		t.Fatalf("agent subscribe: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	sc := &StepCtx{
		Ctx:   context.Background(),
		JobID: "j",
		NATS:  nc,
		Spec:  json.RawMessage(`{"nodeId":"` + nodeID + `"}`),
		Log:   func(string, string) {},
	}
	out, err := pingStep(sc)
	if err != nil {
		t.Fatalf("pingStep: %v", err)
	}
	if string(out) != `{"ok":true}` {
		t.Errorf("out: %s", out)
	}
}

// ============================================================================
// rebootRequestAndObserve happy path: fake agent acks the RPC and publishes a
// "rebooting" event. Exercises both the RPC + the side-channel subscribe.
// ============================================================================

func TestRebootRequestAndObserve_HappyPath(t *testing.T) {
	nc := startNATS(t)
	const nodeID = "n-reb"

	// Agent: respond to system.reboot RPC, then publish "rebooting".
	sub, err := nc.Subscribe(proto.NodeCmdSubject(nodeID, "system.reboot"), func(m *nats.Msg) {
		_ = m.Respond([]byte(`{}`))
		// Publish rebooting event synchronously so the saga's select
		// catches it before timing out.
		_ = nc.Publish(proto.NodeEvtSubject(nodeID, "rebooting"), []byte(`{"ts":"now"}`))
	})
	if err != nil {
		t.Fatalf("agent sub: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	sc := &StepCtx{
		Ctx:   context.Background(),
		JobID: "j",
		NATS:  nc,
		Spec:  json.RawMessage(`{"nodeId":"` + nodeID + `","delaySeconds":1}`),
		Log:   func(string, string) {},
	}
	out, err := rebootRequestAndObserve(sc)
	if err != nil {
		t.Fatalf("rebootRequestAndObserve: %v", err)
	}
	if len(out) == 0 {
		t.Error("expected rebooting event payload, got empty")
	}
}

// TestRebootRequestAndObserve_BadSpec exercises the early validation branch
// (no NATS used).
func TestRebootRequestAndObserve_BadSpec(t *testing.T) {
	sc := &StepCtx{
		Ctx:  context.Background(),
		Spec: json.RawMessage(`{}`),
		Log:  func(string, string) {},
	}
	if _, err := rebootRequestAndObserve(sc); err == nil {
		t.Error("missing nodeId: want error")
	}
}

// TestRebootRequestAndObserve_RPCFails: no agent listens, so the RPC times out
// within the saga's own context. Covers the "reboot rpc" error branch.
func TestRebootRequestAndObserve_RPCFails(t *testing.T) {
	nc := startNATS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	sc := &StepCtx{
		Ctx:  ctx,
		NATS: nc,
		Spec: json.RawMessage(`{"nodeId":"missing","delaySeconds":1}`),
		Log:  func(string, string) {},
	}
	if _, err := rebootRequestAndObserve(sc); err == nil {
		t.Error("RPC with no responder should error")
	}
}

// ============================================================================
// rebootWaitOnline: a fake agent emits an evt.registered after a brief delay;
// the step picks it up via the subscription.
// ============================================================================

func TestRebootWaitOnline_HappyPath(t *testing.T) {
	nc := startNATS(t)
	const nodeID = "n-up"

	// Publish the registered event from a goroutine so the test stays
	// deterministic — the subscriber is already up before publish thanks
	// to nc.Flush() inside Subscribe.
	go func() {
		// Tiny stagger to let the saga's subscribe land before we publish.
		// Using nats.Flush + Subscribe ordering is sufficient: the saga
		// subscribes inside rebootWaitOnline before reading from ch.
		// But this goroutine needs to run *after* that subscribe; the
		// simplest deterministic option is to wait until the saga's
		// subscription is visible by retrying.
		for i := 0; i < 50; i++ {
			if _, err := nc.Request("nonexistent-sentinel-"+nodeID, nil, 5*time.Millisecond); err != nil {
				_ = err
			}
			_ = nc.Publish(proto.NodeRegisteredSubject(nodeID), []byte(`{"nodeId":"`+nodeID+`"}`))
			time.Sleep(10 * time.Millisecond)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sc := &StepCtx{
		Ctx:  ctx,
		NATS: nc,
		Spec: json.RawMessage(`{"nodeId":"` + nodeID + `"}`),
		Log:  func(string, string) {},
	}
	out, err := rebootWaitOnline(sc)
	if err != nil {
		t.Fatalf("rebootWaitOnline: %v", err)
	}
	if len(out) == 0 {
		t.Error("expected reg event payload")
	}
}

func TestRebootWaitOnline_BadSpec(t *testing.T) {
	sc := &StepCtx{
		Ctx:  context.Background(),
		Spec: json.RawMessage(`{}`),
		Log:  func(string, string) {},
	}
	if _, err := rebootWaitOnline(sc); err == nil {
		t.Error("missing nodeId: want error")
	}
}

func TestRebootWaitOnline_ContextCancelled(t *testing.T) {
	nc := startNATS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	sc := &StepCtx{
		Ctx:  ctx,
		NATS: nc,
		Spec: json.RawMessage(`{"nodeId":"never"}`),
		Log:  func(string, string) {},
	}
	if _, err := rebootWaitOnline(sc); err == nil {
		t.Error("waiting without anyone publishing should error after ctx deadline")
	}
}

// ============================================================================
// rebootHealthCheck happy + sad paths.
// ============================================================================

func TestRebootHealthCheck_HappyPath(t *testing.T) {
	nc := startNATS(t)
	const nodeID = "n-hc"

	sub, err := nc.Subscribe(proto.NodeCmdSubject(nodeID, "diag.ping"), func(m *nats.Msg) {
		_ = m.Respond([]byte(`{"pong":true}`))
	})
	if err != nil {
		t.Fatalf("sub: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	sc := &StepCtx{
		Ctx:   context.Background(),
		JobID: "j",
		NATS:  nc,
		Spec:  json.RawMessage(`{"nodeId":"` + nodeID + `"}`),
		Log:   func(string, string) {},
	}
	out, err := rebootHealthCheck(sc)
	if err != nil {
		t.Fatalf("rebootHealthCheck: %v", err)
	}
	if string(out) != `{"pong":true}` {
		t.Errorf("out: %s", out)
	}
}

func TestRebootHealthCheck_BadSpec(t *testing.T) {
	sc := &StepCtx{
		Ctx:  context.Background(),
		Spec: json.RawMessage(`{}`),
		Log:  func(string, string) {},
	}
	if _, err := rebootHealthCheck(sc); err == nil {
		t.Error("missing nodeId: want error")
	}
}

func TestDefaultBackoff(t *testing.T) {
	if got := DefaultBackoff(0); got != 0 {
		t.Errorf("DefaultBackoff(0) = %v, want 0", got)
	}
	if got := DefaultBackoff(1); got != time.Second {
		t.Errorf("DefaultBackoff(1) = %v, want 1s", got)
	}
	if got := DefaultBackoff(3); got != 3*time.Second {
		t.Errorf("DefaultBackoff(3) = %v, want 3s", got)
	}
}

func TestRunner_SetBackoff_NilResets(t *testing.T) {
	r := NewRunner(nil, nil)
	r.SetBackoff(func(int) time.Duration { return time.Hour })
	r.SetBackoff(nil)
	// After reset to nil, the runner falls back to DefaultBackoff.
	if got := r.backoff(2); got != 2*time.Second {
		t.Errorf("after SetBackoff(nil): got %v, want %v (DefaultBackoff(2))", got, 2*time.Second)
	}
}

func TestRebootHealthCheck_RPCFails(t *testing.T) {
	nc := startNATS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	sc := &StepCtx{
		Ctx:  ctx,
		NATS: nc,
		Spec: json.RawMessage(`{"nodeId":"never"}`),
		Log:  func(string, string) {},
	}
	if _, err := rebootHealthCheck(sc); err == nil {
		t.Error("RPC with no responder should error")
	}
}
