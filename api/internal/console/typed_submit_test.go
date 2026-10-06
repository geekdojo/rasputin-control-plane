package console

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-825-25 (console): a node registering without the root password is pushed
// it through the converger's spec-any Submitter into a real Runner. The job is
// created, with no ErrRawSpec, and its stored spec is json.Marshal of the
// PushSpec the converger passed.
func TestConverger_SubmitsATypedPushSpecToARealRunner(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	if _, err := st.SetPassword(ctx, goodPassword); err != nil {
		t.Fatal(err)
	}
	js, err := jobs.OpenStore(ctx, filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.Close() })
	runner := jobs.NewRunner(js, nil)
	runner.Register(jobs.Workflow{Kind: PushKind})

	var passed any
	var jobID string
	c := NewConverger(st, func(ctx context.Context, kind string, spec any, by string) error {
		passed = spec
		j, err := runner.Submit(ctx, kind, spec, by)
		if j != nil {
			jobID = j.ID
		}
		return err
	})
	c.OnRegistered(ctx, &proto.Node{ID: "newcomer", Status: proto.StatusOnline})
	runner.Wait()

	ps, ok := passed.(PushSpec)
	if !ok {
		t.Fatalf("the converger passed a %T, want a PushSpec", passed)
	}
	if wantSpec := (PushSpec{NodeIDs: []string{"newcomer"}, Reason: "registration of newcomer"}); !reflect.DeepEqual(ps, wantSpec) {
		t.Errorf("passed %+v, want %+v", ps, wantSpec)
	}
	if jobID == "" {
		t.Fatal("no job was created")
	}
	got, err := js.GetJob(ctx, jobID)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(ps)
	if string(got.Spec) != string(want) {
		t.Errorf("stored spec %s, want json.Marshal(PushSpec) %s", got.Spec, want)
	}
}
