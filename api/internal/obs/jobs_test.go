package obs

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// recordingSupervisor notes lifecycle calls so tests can assert ordering.
type recordingSupervisor struct {
	fakeSupervisor
	events   *[]string
	startErr error
	stopErr  error
}

func (r *recordingSupervisor) Start(context.Context) error {
	*r.events = append(*r.events, "start")
	return r.startErr
}

func (r *recordingSupervisor) Stop(context.Context) error {
	*r.events = append(*r.events, "stop")
	return r.stopErr
}

// runSteps executes a workflow's steps in order against a bare StepCtx,
// stopping at the first error. The saga runner is exercised elsewhere; what
// matters here is each step's own behavior and the order they're declared in.
func runSteps(t *testing.T, w jobs.Workflow) error {
	t.Helper()
	for _, step := range w.Steps {
		sc := &jobs.StepCtx{
			Ctx: context.Background(),
			Log: func(string, string) {},
		}
		if _, err := step.Do(sc); err != nil {
			return err
		}
	}
	return nil
}

func TestEnableWorkflow_PersistsBeforeStarting(t *testing.T) {
	// Order is a durability guarantee, not cosmetics: a cold enable spends
	// minutes pulling images. If the api dies mid-pull with the intent
	// unwritten, the operator's click is silently lost and the next boot
	// comes up off. Persist first and the next boot finishes the job.
	var events []string
	sup := &recordingSupervisor{events: &events}
	set := func(_ context.Context, on bool) error {
		events = append(events, "persist:"+boolStr(on))
		return nil
	}
	setSink := func(on bool) { events = append(events, "sink:"+boolStr(on)) }

	if err := runSteps(t, EnableWorkflow(sup, set, setSink, func() bool { return true })); err != nil {
		t.Fatalf("EnableWorkflow: %v", err)
	}
	want := []string{"persist:on", "start", "sink:on"}
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Errorf("events = %v; want %v", events, want)
	}
}

func TestEnableWorkflow_PreflightFailsFastWithoutRuntime(t *testing.T) {
	// Fail in seconds with a readable message rather than surfacing a
	// compose error five minutes into a pull that was never going to work.
	var events []string
	sup := &recordingSupervisor{events: &events}
	set := func(context.Context, bool) error {
		events = append(events, "persist")
		return nil
	}

	err := runSteps(t, EnableWorkflow(sup, set, nil, func() bool { return false }))
	if err == nil || !strings.Contains(err.Error(), "no container runtime") {
		t.Fatalf("err = %v; want a no-container-runtime failure", err)
	}
	if len(events) != 0 {
		t.Errorf("events = %v; want none — preflight must run before anything is persisted or started", events)
	}
}

func TestEnableWorkflow_StartFailureLeavesIntentPersisted(t *testing.T) {
	// The stack failing to come up doesn't un-choose the operator's choice:
	// the setting stays on so a retry (or the next boot) resumes, and the
	// sink is not installed against a stack that isn't there.
	var events []string
	sup := &recordingSupervisor{events: &events, startErr: errors.New("pull timed out")}
	set := func(_ context.Context, on bool) error {
		events = append(events, "persist:"+boolStr(on))
		return nil
	}
	setSink := func(on bool) { events = append(events, "sink:"+boolStr(on)) }

	err := runSteps(t, EnableWorkflow(sup, set, setSink, func() bool { return true }))
	if err == nil || !strings.Contains(err.Error(), "pull timed out") {
		t.Fatalf("err = %v; want the underlying start failure", err)
	}
	want := []string{"persist:on", "start"}
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Errorf("events = %v; want %v — the sink must not be installed when start failed", events, want)
	}
}

func TestDisableWorkflow_StopsFanOutBeforeTheStack(t *testing.T) {
	// Removing the sink before stopping the containers keeps teardown from
	// generating a burst of "vm not healthy" write errors.
	var events []string
	sup := &recordingSupervisor{events: &events}
	set := func(_ context.Context, on bool) error {
		events = append(events, "persist:"+boolStr(on))
		return nil
	}
	setSink := func(on bool) { events = append(events, "sink:"+boolStr(on)) }

	if err := runSteps(t, DisableWorkflow(sup, set, setSink)); err != nil {
		t.Fatalf("DisableWorkflow: %v", err)
	}
	want := []string{"persist:off", "sink:off", "stop"}
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Errorf("events = %v; want %v", events, want)
	}
}

func TestWorkflowKinds(t *testing.T) {
	// The handlers submit by string; a rename here without one there is a
	// runtime 503, not a compile error.
	if got := EnableWorkflow(&recordingSupervisor{events: &[]string{}}, nil, nil, nil).Kind; got != "obs.enable" {
		t.Errorf("enable kind = %q; want obs.enable", got)
	}
	if got := DisableWorkflow(&recordingSupervisor{events: &[]string{}}, nil, nil).Kind; got != "obs.disable" {
		t.Errorf("disable kind = %q; want obs.disable", got)
	}
}

// steps must declare a JSON-encodable result contract; assert none of them
// return junk that the runner would fail to record.
func TestWorkflowSteps_ReturnNilResults(t *testing.T) {
	var events []string
	sup := &recordingSupervisor{events: &events}
	set := func(context.Context, bool) error { return nil }
	w := EnableWorkflow(sup, set, func(bool) {}, func() bool { return true })
	for _, step := range w.Steps {
		sc := &jobs.StepCtx{Ctx: context.Background(), Log: func(string, string) {}}
		res, err := step.Do(sc)
		if err != nil {
			t.Fatalf("step %s: %v", step.Name, err)
		}
		if res != nil {
			var v any
			if err := json.Unmarshal(res, &v); err != nil {
				t.Errorf("step %s returned non-JSON result: %v", step.Name, err)
			}
		}
	}
}

func boolStr(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
