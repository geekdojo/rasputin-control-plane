package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenStore(context.Background(), filepath.Join(dir, "jobs.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func makeJob(id, kind string) *Job {
	return &Job{
		ID:        id,
		Kind:      kind,
		Spec:      json.RawMessage(`{"hello":"world"}`),
		Status:    StatusQueued,
		CreatedBy: "test",
		CreatedAt: time.Now().Add(-1 * time.Minute).UTC(),
	}
}

// ============================================================================
// Jobs CRUD + lifecycle transitions
// ============================================================================

func TestStore_CreateAndGetJob(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	want := makeJob("j-1", "node.update")

	if err := s.CreateJob(ctx, want); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	got, err := s.GetJob(ctx, "j-1")
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if got == nil {
		t.Fatal("GetJob returned nil for known id")
	}
	if got.ID != "j-1" || got.Kind != "node.update" || got.Status != StatusQueued {
		t.Errorf("scalar mismatch: %+v", got)
	}
	if string(got.Spec) != string(want.Spec) {
		t.Errorf("Spec: got %s, want %s", got.Spec, want.Spec)
	}
	if got.StartedAt != nil || got.FinishedAt != nil {
		t.Errorf("unfinished job should have nil timestamps, got started=%v finished=%v", got.StartedAt, got.FinishedAt)
	}
	if got.ParentID != nil {
		t.Errorf("root job should have nil parent, got %v", *got.ParentID)
	}
}

func TestStore_GetUnknownReturnsNilNil(t *testing.T) {
	s := newStore(t)
	got, err := s.GetJob(context.Background(), "ghost")
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestStore_JobLifecycleTransitions(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	if err := s.CreateJob(ctx, makeJob("j-ok", "diag.ping")); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	started := time.Now().Add(-2 * time.Second).UTC()
	if err := s.MarkJobStarted(ctx, "j-ok", started); err != nil {
		t.Fatalf("MarkJobStarted: %v", err)
	}
	mid, _ := s.GetJob(ctx, "j-ok")
	if mid.Status != StatusRunning {
		t.Errorf("after start: status %q", mid.Status)
	}
	if mid.StartedAt == nil || mid.StartedAt.UnixMilli() != started.UnixMilli() {
		t.Errorf("StartedAt mismatch: %v", mid.StartedAt)
	}

	finished := time.Now().UTC()
	if err := s.MarkJobSucceeded(ctx, "j-ok", finished); err != nil {
		t.Fatalf("MarkJobSucceeded: %v", err)
	}
	end, _ := s.GetJob(ctx, "j-ok")
	if end.Status != StatusSucceeded {
		t.Errorf("after succeed: status %q", end.Status)
	}
	if end.FinishedAt == nil || end.FinishedAt.UnixMilli() != finished.UnixMilli() {
		t.Errorf("FinishedAt mismatch: %v", end.FinishedAt)
	}
}

func TestStore_MarkJobFailedRecordsError(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.CreateJob(ctx, makeJob("j-fail", "system.reboot")); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	ts := time.Now().UTC()
	if err := s.MarkJobFailed(ctx, "j-fail", "verify exit 1", ts); err != nil {
		t.Fatalf("MarkJobFailed: %v", err)
	}
	got, _ := s.GetJob(ctx, "j-fail")
	if got.Status != StatusFailed || got.Error != "verify exit 1" {
		t.Errorf("failed: %+v", got)
	}
	if got.FinishedAt == nil {
		t.Error("FinishedAt should be set on failure")
	}
}

// ============================================================================
// ListJobs / ListJobsByStatus / ListChildJobs
// ============================================================================

func TestStore_ListJobs_OrderDescAndLimit(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	base := time.Now().UTC()

	for i, id := range []string{"a", "b", "c"} {
		j := makeJob(id, "k")
		// stagger CreatedAt by i seconds so order is well-defined.
		j.CreatedAt = base.Add(time.Duration(i) * time.Second)
		if err := s.CreateJob(ctx, j); err != nil {
			t.Fatalf("CreateJob %s: %v", id, err)
		}
	}

	got, err := s.ListJobs(ctx, 0) // 0 → default
	if err != nil {
		t.Fatalf("ListJobs: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3, got %d", len(got))
	}
	// DESC by created_at → newest first → c, b, a
	if got[0].ID != "c" || got[1].ID != "b" || got[2].ID != "a" {
		t.Errorf("order: %s %s %s", got[0].ID, got[1].ID, got[2].ID)
	}

	limited, err := s.ListJobs(ctx, 2)
	if err != nil {
		t.Fatalf("ListJobs(2): %v", err)
	}
	if len(limited) != 2 {
		t.Errorf("limit 2: got %d", len(limited))
	}

	// Over-limit clamps to default; smoke test that it doesn't panic / error.
	bigLimit, err := s.ListJobs(ctx, 99999)
	if err != nil {
		t.Fatalf("ListJobs(99999): %v", err)
	}
	if len(bigLimit) != 3 {
		t.Errorf("oversized limit: want 3 (all), got %d", len(bigLimit))
	}
}

func TestStore_ListJobsByStatus(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	jobs := []struct {
		id     string
		status Status
	}{
		{"q1", StatusQueued},
		{"r1", StatusRunning},
		{"r2", StatusRunning},
		{"s1", StatusSucceeded},
		{"f1", StatusFailed},
	}
	for _, j := range jobs {
		row := makeJob(j.id, "k")
		if err := s.CreateJob(ctx, row); err != nil {
			t.Fatalf("CreateJob %s: %v", j.id, err)
		}
		// Patch status to the desired terminal value where needed.
		switch j.status {
		case StatusRunning:
			if err := s.MarkJobStarted(ctx, j.id, time.Now().UTC()); err != nil {
				t.Fatalf("MarkJobStarted: %v", err)
			}
		case StatusSucceeded:
			if err := s.MarkJobSucceeded(ctx, j.id, time.Now().UTC()); err != nil {
				t.Fatalf("MarkJobSucceeded: %v", err)
			}
		case StatusFailed:
			if err := s.MarkJobFailed(ctx, j.id, "boom", time.Now().UTC()); err != nil {
				t.Fatalf("MarkJobFailed: %v", err)
			}
		}
	}

	inFlight, err := s.ListJobsByStatus(ctx, []Status{StatusQueued, StatusRunning})
	if err != nil {
		t.Fatalf("ListJobsByStatus: %v", err)
	}
	if len(inFlight) != 3 {
		t.Fatalf("want 3 in-flight, got %d", len(inFlight))
	}
	gotIDs := make([]string, 0, len(inFlight))
	for _, j := range inFlight {
		gotIDs = append(gotIDs, j.ID)
	}
	sort.Strings(gotIDs)
	wantIDs := []string{"q1", "r1", "r2"}
	for i, id := range wantIDs {
		if gotIDs[i] != id {
			t.Errorf("inFlight[%d]: got %q, want %q", i, gotIDs[i], id)
		}
	}

	// Empty input → empty output, no error.
	none, err := s.ListJobsByStatus(ctx, nil)
	if err != nil {
		t.Fatalf("ListJobsByStatus(nil): %v", err)
	}
	if len(none) != 0 {
		t.Errorf("nil status list should return empty, got %d", len(none))
	}
}

func TestStore_ListChildJobs(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	// Parent + two children + one unrelated root.
	if err := s.CreateJob(ctx, makeJob("parent", "system.update")); err != nil {
		t.Fatalf("create parent: %v", err)
	}
	for i, id := range []string{"child-a", "child-b"} {
		c := makeJob(id, "node.update")
		c.CreatedAt = time.Now().Add(time.Duration(i) * time.Second).UTC()
		pid := "parent"
		c.ParentID = &pid
		if err := s.CreateJob(ctx, c); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	if err := s.CreateJob(ctx, makeJob("stranger", "diag.ping")); err != nil {
		t.Fatalf("create stranger: %v", err)
	}

	kids, err := s.ListChildJobs(ctx, "parent")
	if err != nil {
		t.Fatalf("ListChildJobs: %v", err)
	}
	if len(kids) != 2 {
		t.Fatalf("want 2 children, got %d", len(kids))
	}
	// ORDER BY created_at ASC → child-a before child-b.
	if kids[0].ID != "child-a" || kids[1].ID != "child-b" {
		t.Errorf("children order: %s, %s", kids[0].ID, kids[1].ID)
	}
	for _, k := range kids {
		if k.ParentID == nil || *k.ParentID != "parent" {
			t.Errorf("child %s parent not roundtripped: %v", k.ID, k.ParentID)
		}
	}

	// Unknown parent → empty.
	orphans, err := s.ListChildJobs(ctx, "no-such")
	if err != nil {
		t.Fatalf("ListChildJobs unknown: %v", err)
	}
	if len(orphans) != 0 {
		t.Errorf("unknown parent: got %d kids", len(orphans))
	}
}

// ============================================================================
// Steps
// ============================================================================

func TestStore_StepsLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.CreateJob(ctx, makeJob("j", "k")); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	started := time.Now().UTC()
	step0 := &JobStep{
		JobID:     "j",
		Seq:       0,
		Name:      "prep",
		Status:    StepRunning,
		StartedAt: &started,
	}
	if err := s.CreateStep(ctx, step0); err != nil {
		t.Fatalf("CreateStep 0: %v", err)
	}
	step1 := &JobStep{
		JobID:  "j",
		Seq:    1,
		Name:   "apply",
		Status: StepPending,
	}
	if err := s.CreateStep(ctx, step1); err != nil {
		t.Fatalf("CreateStep 1: %v", err)
	}

	// Succeed step 0 with a JSON result, fail step 1.
	if err := s.MarkStepSucceeded(ctx, "j", 0, 1,
		json.RawMessage(`{"ok":true}`), time.Now().UTC()); err != nil {
		t.Fatalf("MarkStepSucceeded: %v", err)
	}
	if err := s.MarkStepFailed(ctx, "j", 1, "exit 1", time.Now().UTC()); err != nil {
		t.Fatalf("MarkStepFailed: %v", err)
	}

	steps, err := s.ListSteps(ctx, "j")
	if err != nil {
		t.Fatalf("ListSteps: %v", err)
	}
	if len(steps) != 2 {
		t.Fatalf("want 2 steps, got %d", len(steps))
	}
	// ListSteps ORDER BY seq ASC.
	if steps[0].Seq != 0 || steps[1].Seq != 1 {
		t.Errorf("seq order broken: %d, %d", steps[0].Seq, steps[1].Seq)
	}
	if steps[0].Status != StepSucceeded || string(steps[0].Result) != `{"ok":true}` {
		t.Errorf("step 0 result: %+v", steps[0])
	}
	if steps[0].Attempt != 1 {
		t.Errorf("step 0 attempt: want 1, got %d", steps[0].Attempt)
	}
	if steps[0].FinishedAt == nil {
		t.Error("step 0 should have FinishedAt set")
	}
	if steps[0].StartedAt == nil || steps[0].StartedAt.UnixMilli() != started.UnixMilli() {
		t.Errorf("step 0 StartedAt not round-tripped: %v", steps[0].StartedAt)
	}
	if steps[1].Status != StepFailed || steps[1].Error != "exit 1" {
		t.Errorf("step 1: %+v", steps[1])
	}
}

func TestStore_ListSteps_EmptyForUnknownJob(t *testing.T) {
	s := newStore(t)
	got, err := s.ListSteps(context.Background(), "missing")
	if err != nil {
		t.Fatalf("ListSteps: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want 0 steps for unknown job, got %d", len(got))
	}
}

// ============================================================================
// Events
// ============================================================================

func TestStore_AppendAndListEvents(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.CreateJob(ctx, makeJob("j", "k")); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	// Two events with a few ms between them so ts ordering is sensible.
	t0 := time.Now().UTC()
	if err := s.AppendEvent(ctx, "j", "started", json.RawMessage(`{"by":"test"}`), t0); err != nil {
		t.Fatalf("AppendEvent 1: %v", err)
	}
	t1 := t0.Add(5 * time.Millisecond)
	// nil data is allowed; the column is nullable.
	if err := s.AppendEvent(ctx, "j", "succeeded", nil, t1); err != nil {
		t.Fatalf("AppendEvent 2: %v", err)
	}

	events, err := s.ListEvents(ctx, "j")
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 events, got %d", len(events))
	}
	// ListEvents ORDER BY id ASC == insertion order.
	if events[0].Type != "started" || events[1].Type != "succeeded" {
		t.Errorf("event order/types: %+v %+v", events[0], events[1])
	}
	if string(events[0].Data) != `{"by":"test"}` {
		t.Errorf("event[0].Data: %s", events[0].Data)
	}
	if len(events[1].Data) != 0 {
		t.Errorf("event[1].Data: want empty, got %s", events[1].Data)
	}
	if events[0].ID == 0 || events[1].ID <= events[0].ID {
		t.Errorf("auto-id should be monotonic: %d %d", events[0].ID, events[1].ID)
	}

	// Unknown job: empty list, not error.
	none, err := s.ListEvents(ctx, "ghost")
	if err != nil {
		t.Fatalf("ListEvents ghost: %v", err)
	}
	if len(none) != 0 {
		t.Errorf("unknown job: got %d events", len(none))
	}
}

// ============================================================================
// Parent_id with empty pointer is treated as NULL — round-trip check.
// ============================================================================

func TestStore_CreateJob_EmptyParentPointerIsNull(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	j := makeJob("j", "k")
	empty := ""
	j.ParentID = &empty // pointer set but to empty string → store should NULL it out.
	if err := s.CreateJob(ctx, j); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	got, _ := s.GetJob(ctx, "j")
	if got.ParentID != nil {
		t.Errorf("empty pointer should round-trip to nil, got %v", *got.ParentID)
	}
}

// ============================================================================
// Sanity: sql.ErrNoRows is what scan helpers return on the no-rows path,
// confirming the wrapping pattern future callers rely on.
// ============================================================================

func TestStore_GetJob_ErrNoRowsWrappedAsNil(t *testing.T) {
	s := newStore(t)
	got, err := s.GetJob(context.Background(), "x")
	if err != nil {
		// scanJob converts sql.ErrNoRows into (nil, nil); anything else is a regression.
		if errors.Is(err, errors.New("any")) {
		}
		t.Fatalf("GetJob unknown returned error: %v", err)
	}
	if got != nil {
		t.Errorf("unknown job should be nil, got %+v", got)
	}
}

// ============================================================================
// Runner — bits that don't touch NATS.
//
// Submit / SubmitChild / run / runStep / emit all dereference r.nc, so
// running a real workflow needs a bus. What we can do without one:
//   - NewRunner / Register / Wait (no side effects)
//   - Recover on an empty store (no in-flight jobs → no emit calls)
//   - SubmitChild's pre-flight validation that rejects an empty parentID
// ============================================================================

func TestRunner_NewAndRegister(t *testing.T) {
	store := newStore(t)
	r := NewRunner(store, nil)
	if r == nil {
		t.Fatal("NewRunner returned nil")
	}
	r.Register(Workflow{Kind: "diag.ping"})
	r.Register(Workflow{Kind: "node.reboot"})
	if _, ok := r.workflows["diag.ping"]; !ok {
		t.Error("Register did not store diag.ping")
	}
	if _, ok := r.workflows["node.reboot"]; !ok {
		t.Error("Register did not store node.reboot")
	}
	// Wait with no running jobs returns immediately.
	r.Wait()
}

func TestRunner_Recover_EmptyStore(t *testing.T) {
	store := newStore(t)
	r := NewRunner(store, nil)
	// No in-flight jobs → Recover finds nothing → never reaches emit.
	if err := r.Recover(context.Background()); err != nil {
		t.Errorf("Recover empty: %v", err)
	}
}

func TestRunner_SubmitChild_RejectsEmptyParent(t *testing.T) {
	store := newStore(t)
	r := NewRunner(store, nil)
	_, err := r.SubmitChild(context.Background(), "diag.ping", nil, "test", "")
	if err == nil {
		t.Error("SubmitChild with empty parentID should error")
	}
}

func TestRunner_Submit_UnknownKindError(t *testing.T) {
	store := newStore(t)
	r := NewRunner(store, nil)
	// Unknown kind is rejected before any NATS work happens.
	_, err := r.Submit(context.Background(), "no.such.kind", nil, "test")
	if err == nil {
		t.Error("Submit unknown kind should error")
	}
}

// ============================================================================
// Pure workflow helpers — no NATS required.
// ============================================================================

func TestPingWorkflowShape(t *testing.T) {
	w := PingWorkflow()
	if w.Kind != "diag.ping" {
		t.Errorf("Kind: %q", w.Kind)
	}
	if len(w.Steps) != 1 || w.Steps[0].Name != "ping" {
		t.Errorf("steps: %+v", w.Steps)
	}
	if w.Steps[0].Retries < 1 {
		t.Errorf("ping step should retry at least once, got %d", w.Steps[0].Retries)
	}
}

func TestRebootWorkflowShape(t *testing.T) {
	w := RebootWorkflow()
	if w.Kind != "node.reboot" {
		t.Errorf("Kind: %q", w.Kind)
	}
	wantSteps := []string{"prepare", "request_and_observe", "wait_online", "health_check"}
	if len(w.Steps) != len(wantSteps) {
		t.Fatalf("step count: got %d want %d", len(w.Steps), len(wantSteps))
	}
	for i, name := range wantSteps {
		if w.Steps[i].Name != name {
			t.Errorf("step %d: got %q, want %q", i, w.Steps[i].Name, name)
		}
	}
}

// ============================================================================
// Step DoFns that don't actually need NATS to fail.
// ============================================================================

func TestRebootPrepare_HappyPath(t *testing.T) {
	// rebootPrepare only does validation + sc.Log + marshals the spec back.
	// No NATS calls — sc.NATS may safely be nil.
	sc := &StepCtx{
		Ctx:   context.Background(),
		JobID: "j",
		Spec:  json.RawMessage(`{"nodeId":"n","delaySeconds":5}`),
		Log:   func(level, message string) {},
	}
	raw, err := rebootPrepare(sc)
	if err != nil {
		t.Fatalf("rebootPrepare: %v", err)
	}
	var got RebootSpec
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if got.NodeID != "n" || got.DelaySeconds != 5 {
		t.Errorf("rebootPrepare result: %+v", got)
	}
}

func TestRebootPrepare_BadSpecError(t *testing.T) {
	sc := &StepCtx{
		Ctx:  context.Background(),
		Spec: json.RawMessage(`{}`), // missing nodeId
		Log:  func(level, message string) {},
	}
	if _, err := rebootPrepare(sc); err == nil {
		t.Error("rebootPrepare should reject missing nodeId")
	}
}

func TestPingStep_RejectsInvalidSpec(t *testing.T) {
	// pingStep errors before touching NATS for missing nodeId or bad JSON.
	cases := []json.RawMessage{
		json.RawMessage(`{}`),
		json.RawMessage(`not-json`),
	}
	for _, spec := range cases {
		sc := &StepCtx{Ctx: context.Background(), Spec: spec, Log: func(string, string) {}}
		if _, err := pingStep(sc); err == nil {
			t.Errorf("pingStep(%s) should error", spec)
		}
	}
}

func TestParseRebootSpec(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantErr   bool
		wantDelay int
	}{
		{"defaults missing delay", `{"nodeId":"n"}`, false, rebootDefaultDelay},
		{"clamps negative delay", `{"nodeId":"n","delaySeconds":-5}`, false, rebootDefaultDelay},
		{"clamps over-max delay", `{"nodeId":"n","delaySeconds":99}`, false, rebootDefaultDelay},
		{"passes valid delay", `{"nodeId":"n","delaySeconds":7}`, false, 7},
		{"missing nodeId", `{}`, true, 0},
		{"invalid json", `{not-json`, true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseRebootSpec(json.RawMessage(tc.input))
			if tc.wantErr {
				if err == nil {
					t.Errorf("want error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got.DelaySeconds != tc.wantDelay {
				t.Errorf("DelaySeconds: got %d want %d", got.DelaySeconds, tc.wantDelay)
			}
		})
	}
}

// A specless job must persist "{}" rather than "". spec is stored verbatim in
// a TEXT column and scanned straight back into a json.RawMessage, so an empty
// spec round-trips to RawMessage("") — which fails to marshal and blanks the
// ENTIRE /api/jobs response, not just the bad row. One specless job (obs.enable
// was the first) takes the whole Tasks page down with it.
func TestRunner_Submit_NormalizesEmptySpec(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec json.RawMessage
	}{
		{"nil", nil},
		{"empty", json.RawMessage("")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newStore(t)
			r := NewRunner(store, nil)
			r.Register(Workflow{Kind: "obs.enable"})

			j, err := r.Submit(context.Background(), "obs.enable", tc.spec, "test")
			if err != nil {
				t.Fatalf("Submit: %v", err)
			}
			r.Wait()

			got, err := store.GetJob(context.Background(), j.ID)
			if err != nil {
				t.Fatalf("GetJob: %v", err)
			}
			if string(got.Spec) != "{}" {
				t.Errorf("persisted spec = %q; want %q", got.Spec, "{}")
			}
			// The real symptom: marshaling the read-back job must not error.
			if _, err := json.Marshal([]*Job{got}); err != nil {
				t.Errorf("marshal round-tripped job: %v — this is what blanks /api/jobs", err)
			}
		})
	}
}

// Guard the invariant the fix relies on: an empty RawMessage genuinely cannot
// marshal, so "" in the spec column is never merely cosmetic.
func TestEmptyRawMessage_FailsToMarshal(t *testing.T) {
	if _, err := json.Marshal(json.RawMessage("")); err == nil {
		t.Fatal("expected empty json.RawMessage to fail marshaling; if this ever passes, Submit's normalization can be revisited")
	}
}
