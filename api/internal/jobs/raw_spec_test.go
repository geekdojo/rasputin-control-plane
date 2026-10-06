package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// TC-825-17: Submit, SubmitPrepared and SubmitChild refuse every pre-marshalled
// spec form, empty or not, with ErrRawSpec naming the kind: before prepare runs
// and before a job row, a job event or a bus message exists.
func TestSubmit_RefusesARawSpecAtEveryEntryPoint(t *testing.T) {
	g := newSpecRig(t)
	ctx := context.Background()
	nonEmpty := json.RawMessage(`{"a":1}`)
	forms := []struct {
		name string
		spec any
	}{
		{"non-empty json.RawMessage", nonEmpty},
		{"empty json.RawMessage", json.RawMessage{}},
		{"*json.RawMessage", &nonEmpty},
		{"non-empty []byte", []byte(`{"b":2}`)},
		{"empty []byte", []byte{}},
	}
	for _, f := range forms {
		prepared := false
		entries := map[string]func() error{
			"Submit": func() error {
				_, err := g.r.Submit(ctx, specKind, f.spec, "test")
				return err
			},
			"SubmitPrepared": func() error {
				_, err := g.r.SubmitPrepared(ctx, specKind, f.spec, "test", func(string) error { prepared = true; return nil })
				return err
			},
			"SubmitChild": func() error {
				_, err := g.r.SubmitChild(ctx, specKind, f.spec, "test", "parent-1")
				return err
			},
		}
		for entry, call := range entries {
			label := entry + " " + f.name
			err := call()
			if !errors.Is(err, ErrRawSpec) {
				t.Fatalf("%s: err = %v, want ErrRawSpec", label, err)
			}
			if !strings.Contains(err.Error(), specKind) {
				t.Errorf("%s: error %q does not name the kind", label, err)
			}
			g.assertNothingPersisted(t, label)
		}
		if prepared {
			t.Errorf("%s: prepare ran for a refused spec", f.name)
		}
	}
	g.r.Wait()
}

// TC-825-19: SubmitRawSpec stores non-empty raw JSON byte for byte and the
// workflow sees exactly those bytes in StepCtx.Spec; an empty spec is stored
// as {}; an unknown kind is refused with nothing persisted.
func TestSubmitRawSpec(t *testing.T) {
	g := newSpecRig(t)
	ctx := context.Background()
	const seenKind = "test.raw.seen"
	seen := make(chan json.RawMessage, 1)
	g.r.Register(Workflow{Kind: seenKind, Steps: []WorkflowStep{{Name: "see", Timeout: time.Second,
		Do: func(sc *StepCtx) (json.RawMessage, error) {
			seen <- append(json.RawMessage(nil), sc.Spec...)
			return nil, nil
		}}}})

	given := json.RawMessage(`{ "nodeId" : "n1",  "n": [1,2] }`)
	j, err := g.r.SubmitRawSpec(ctx, seenKind, given, "test")
	if err != nil {
		t.Fatalf("SubmitRawSpec: %v", err)
	}
	done := waitForStatus(t, g.store, j.ID, StatusSucceeded, 5*time.Second)
	if string(done.Spec) != string(given) {
		t.Errorf("stored spec %s, want the given bytes %s", done.Spec, given)
	}
	if got := <-seen; string(got) != string(given) {
		t.Errorf("StepCtx.Spec = %s, want the given bytes %s", got, given)
	}

	j, err = g.r.SubmitRawSpec(ctx, specKind, nil, "test")
	if err != nil {
		t.Fatalf("SubmitRawSpec empty: %v", err)
	}
	if done := waitForStatus(t, g.store, j.ID, StatusSucceeded, 5*time.Second); string(done.Spec) != `{}` {
		t.Errorf("empty spec stored as %q, want {}", done.Spec)
	}
	g.r.Wait()

	before, err := g.store.ListJobs(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.r.SubmitRawSpec(ctx, "test.no.such.kind", given, "test"); err == nil || !strings.Contains(err.Error(), "test.no.such.kind") {
		t.Fatalf("unknown kind: err = %v, want an error naming the kind", err)
	}
	after, err := g.store.ListJobs(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Errorf("an unknown kind persisted a job: %d rows before, %d after", len(before), len(after))
	}
}
