package bmc

import (
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/credmac/credmactest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// TC-825-25 (bmc): a registration whose advertised hash does not match fires
// the reconciler's re-push through its spec-any SubmitFn into a real Runner.
// The job is created, with no ErrRawSpec, and its stored spec is
// json.Marshal of the ConfigureSpec the reconciler passed.
func TestReconcile_SubmitsATypedConfigureSpecToARealRunner(t *testing.T) {
	ctx := context.Background()
	st := newSetupStore(t)
	desired := desiredMock(t, st)
	js, err := jobs.OpenStore(ctx, filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.Close() })
	runner := jobs.NewRunner(js, nil)
	runner.Register(jobs.Workflow{Kind: "bmc.configure"})

	var passed any
	var jobID string
	r := &reconciler{
		st:   st,
		busy: func(context.Context) (bool, error) { return false, nil },
		submit: func(ctx context.Context, kind string, spec any, by string) error {
			passed = spec
			j, err := runner.Submit(ctx, kind, spec, by)
			if j != nil {
				jobID = j.ID
			}
			return err
		},
		log: slog.New(slog.DiscardHandler),
		mac: credmactest.Key(t),
	}
	r.onRegistered(regMsg(t, "host-1", nil))
	runner.Wait()

	cs, ok := passed.(ConfigureSpec)
	if !ok {
		t.Fatalf("the reconciler passed a %T, want a ConfigureSpec", passed)
	}
	if cs.Kind != "mock" || cs.HostNodeID != "host-1" || cs.ConfigHash != desired {
		t.Errorf("passed %+v, want kind mock, host host-1, configHash %s", cs, desired)
	}
	if jobID == "" {
		t.Fatal("no job was created")
	}
	got, err := js.GetJob(ctx, jobID)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(cs)
	if string(got.Spec) != string(want) {
		t.Errorf("stored spec %s, want json.Marshal(ConfigureSpec) %s", got.Spec, want)
	}
}
