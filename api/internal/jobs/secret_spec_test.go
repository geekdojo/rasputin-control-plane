package jobs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// secretSpec is a typed spec that carries a secret: what ADR-0009 forbids.
type secretSpec struct {
	Name string       `json:"name"`
	Key  secret.Value `json:"key"`
}

type plainSpec struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// specRig is a Runner on a real store and a real bus, with workflow kind k
// registered and every job event on the bus captured.
type specRig struct {
	store *Store
	nc    *nats.Conn
	r     *Runner
	sub   *nats.Subscription
}

const specKind = "test.spec"

func newSpecRig(t *testing.T) *specRig {
	t.Helper()
	store := newStore(t)
	nc := startNATS(t)
	r := NewRunner(store, nc)
	r.Register(Workflow{Kind: specKind, Steps: []WorkflowStep{{Name: "noop", Timeout: time.Second,
		Do: func(*StepCtx) (json.RawMessage, error) { return nil, nil }}}})
	sub, err := nc.SubscribeSync("rasputin.job.>")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	return &specRig{store: store, nc: nc, r: r, sub: sub}
}

// assertNothingPersisted proves a refused submit left no job row, no
// job_events row and no message on the job subjects. The flush is a round
// trip on the connection the runner publishes on, so any message it had
// published is already in the subscription's queue when Pending is read.
func (g *specRig) assertNothingPersisted(t *testing.T, label string) {
	t.Helper()
	ctx := context.Background()
	if js, err := g.store.ListJobsByKind(ctx, specKind, 10); err != nil || len(js) != 0 {
		t.Errorf("%s: %d job rows (%v), want none", label, len(js), err)
	}
	var events int
	if err := g.store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_events`).Scan(&events); err != nil || events != 0 {
		t.Errorf("%s: %d job_events rows (%v), want none", label, events, err)
	}
	if err := g.nc.Flush(); err != nil {
		t.Fatal(err)
	}
	if n, _, err := g.sub.Pending(); err != nil || n != 0 {
		t.Errorf("%s: %d messages on the job subjects (%v), want none", label, n, err)
	}
}

// TC-732-09: every entry point refuses a spec that carries a secret.Value,
// before the id is minted, before prepare, and before anything is persisted
// or published.
func TestSubmit_RefusesASpecCarryingASecret(t *testing.T) {
	g := newSpecRig(t)
	raw := bytes.Repeat([]byte{0x5a, 0xc3}, 16)
	spec := secretSpec{Name: "n", Key: secret.New(raw)}
	ctx := context.Background()

	prepared := false
	calls := map[string]func() error{
		"Submit": func() error {
			_, err := g.r.Submit(ctx, specKind, spec, "test")
			return err
		},
		"SubmitPrepared": func() error {
			_, err := g.r.SubmitPrepared(ctx, specKind, spec, "test", func(string) error { prepared = true; return nil })
			return err
		},
		"SubmitChild": func() error {
			_, err := g.r.SubmitChild(ctx, specKind, &spec, "test", "parent-1")
			return err
		},
	}
	for name, call := range calls {
		err := call()
		if !errors.Is(err, ErrSecretInSpec) {
			t.Fatalf("%s: err = %v, want ErrSecretInSpec", name, err)
		}
		msg := err.Error()
		if !strings.Contains(msg, specKind) {
			t.Errorf("%s: error %q does not name the kind", name, msg)
		}
		for _, enc := range []string{string(raw), hex.EncodeToString(raw), base64.StdEncoding.EncodeToString(raw), base64.RawURLEncoding.EncodeToString(raw)} {
			if strings.Contains(msg, enc) {
				t.Errorf("%s: error %q carries the secret", name, msg)
			}
		}
		g.assertNothingPersisted(t, name)
	}
	if prepared {
		t.Error("prepare ran for a refused spec")
	}
	g.r.Wait()
}

// TC-732-10: every spec form a current caller passes is accepted and stored
// as before, and each job runs to its terminal status. Since
// geekdojo/geekdojo-brain#825 the raw forms are passed to SubmitRawSpec, the
// one entry point that accepts them; Submit refuses them (raw_spec_test.go).
func TestSubmit_AcceptsEveryCurrentSpecForm(t *testing.T) {
	g := newSpecRig(t)
	ctx := context.Background()
	typed := plainSpec{Name: "n", Count: 3}
	typedJSON, _ := json.Marshal(typed)
	submit := func(spec any) (*Job, error) { return g.r.Submit(ctx, specKind, spec, "test") }
	raw := func(spec json.RawMessage) func(any) (*Job, error) {
		return func(any) (*Job, error) { return g.r.SubmitRawSpec(ctx, specKind, spec, "test") }
	}
	cases := []struct {
		name   string
		spec   any
		submit func(any) (*Job, error)
		want   string
	}{
		{"typed struct", typed, submit, string(typedJSON)},
		{"nil", nil, submit, `{}`},
		{"non-empty raw JSON", nil, raw(json.RawMessage(`{"a": 1}`)), `{"a": 1}`},
		{"empty raw JSON", nil, raw(json.RawMessage{}), `{}`},
	}
	for _, c := range cases {
		j, err := c.submit(c.spec)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		done := waitForStatus(t, g.store, j.ID, StatusSucceeded, 5*time.Second)
		if string(done.Spec) != c.want {
			t.Errorf("%s: stored spec %s, want %s", c.name, done.Spec, c.want)
		}
	}
	g.r.Wait()
}

// TC-732-11: a spec that cannot be marshalled is refused before prepare
// runs and before anything is persisted, with the json error wrapped.
func TestSubmitPrepared_SpecMarshalFailure(t *testing.T) {
	g := newSpecRig(t)
	type bad struct{ C chan int }
	prepared := false
	_, err := g.r.SubmitPrepared(context.Background(), specKind, bad{C: make(chan int)}, "test",
		func(string) error { prepared = true; return nil })
	var ute *json.UnsupportedTypeError
	if !errors.As(err, &ute) {
		t.Fatalf("err = %v, want a wrapped *json.UnsupportedTypeError", err)
	}
	if !strings.Contains(err.Error(), specKind) {
		t.Errorf("error %q does not name the kind", err)
	}
	if prepared {
		t.Error("prepare ran for a spec that could not be marshalled")
	}
	g.assertNothingPersisted(t, "marshal failure")
}
