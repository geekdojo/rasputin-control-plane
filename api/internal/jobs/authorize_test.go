package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/nats-io/nats.go"
)

// refusing is an Authorizer that refuses everything with a KindRefusal and
// records what it was asked.
type refusing struct{ asked []string }

func (a *refusing) Authorize(_ context.Context, kind string, spec []byte, by authz.Submitter) error {
	a.asked = append(a.asked, kind+" "+string(spec)+" "+by.CreatedBy())
	return &authz.KindRefusal{Code: authz.CodeNotPermitted, Sentence: "no"}
}

// noApps is an authz.AppReader that knows no app.
type noApps struct{}

func (noApps) AppFacts(context.Context, string, string) (authz.AppFacts, error) {
	return authz.AppFacts{}, authz.ErrNoApp
}

func noopWorkflow(kind string) Workflow {
	return Workflow{Kind: kind, Steps: []WorkflowStep{{Name: "a", Timeout: time.Second,
		Do: func(*StepCtx) (json.RawMessage, error) { return nil, nil }}}}
}

// realRunner is the api's runner: the real kind table over no apps.
func realRunner(t *testing.T, store *Store, nc *nats.Conn) *Runner {
	t.Helper()
	policy, err := authz.NewKindPolicy(noApps{})
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewAuthorizedRunner(store, nc, policy)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var testAdmin = authz.Person(authz.Subject{Sub: "s-1", Roles: []string{"admin"}})

// TC-1001-12: a refusal leaves nothing behind: prepare never runs, no job or
// step row exists and no event is published, and the error is the
// KindRefusal.
func TestSubmitFor_TC1001_12_RefusalLeavesNothing(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	az := &refusing{}
	r, err := NewAuthorizedRunner(store, nc, az)
	if err != nil {
		t.Fatal(err)
	}
	r.Register(noopWorkflow("bmc.power"))
	events := make(chan *nats.Msg, 8)
	sub, err := nc.ChanSubscribe("rasputin.job.>", events)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Unsubscribe() }()
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}

	prepared := false
	j, err := r.SubmitFor(t.Context(), testAdmin, "bmc.power", map[string]string{"targetNodeId": "n1"}, func(string) error {
		prepared = true
		return nil
	})
	var kr *authz.KindRefusal
	if j != nil || !errors.As(err, &kr) || kr.Code != authz.CodeNotPermitted {
		t.Fatalf("SubmitFor = %v, %v; want the KindRefusal", j, err)
	}
	if prepared {
		t.Error("prepare ran for a refused job")
	}
	if len(az.asked) != 1 || az.asked[0] != `bmc.power {"targetNodeId":"n1"} s-1` {
		t.Errorf("the authorizer was asked %q, want the kind, the encoded spec and the submitter", az.asked)
	}
	if list, err := store.ListJobs(t.Context(), 10); err != nil || len(list) != 0 {
		t.Errorf("%d job rows (%v), want none", len(list), err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-events:
		t.Errorf("an event was published for a refused job: %s %s", m.Subject, m.Data)
	default:
	}
}

// TC-1001-13 (jobs part): NewRunner runs the system and refuses every other
// submitter with ErrNotSystem; NewAuthorizedRunner refuses a nil authorizer.
func TestRunner_TC1001_13_Modes(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	r := NewRunner(store, nc)
	r.Register(noopWorkflow("test.kind"))
	for name, by := range map[string]authz.Submitter{
		"person": testAdmin, "repair": authz.RepairSession(), "bridge": authz.BridgeGrant("s-2"), "zero": {},
	} {
		if j, err := r.SubmitFor(t.Context(), by, "test.kind", nil, nil); j != nil || !errors.Is(err, ErrNotSystem) {
			t.Errorf("%s on NewRunner = %v, %v; want ErrNotSystem", name, j, err)
		}
	}
	if j, err := r.SubmitFor(t.Context(), authz.SystemSubmitter("sched"), "test.kind", nil, nil); err != nil || j == nil {
		t.Errorf("the system on NewRunner = %v, %v; want it run", j, err)
	}
	r.Wait()
	if list, err := store.ListJobs(t.Context(), 10); err != nil || len(list) != 1 {
		t.Errorf("%d job rows (%v), want the system's one", len(list), err)
	}
	if got, err := NewAuthorizedRunner(store, nc, nil); err == nil || got != nil {
		t.Errorf("NewAuthorizedRunner(nil) = %v, %v; want an error", got, err)
	}
}

// TC-1001-14 (jobs part): the job and the step record the submitter's
// CreatedBy: a person's sub, never their name; the system's subsystem name;
// "break-glass" for a repair session; the account for a bridge grant.
func TestSubmitFor_TC1001_14_CreatedBy(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	r, err := NewAuthorizedRunner(store, nc, allowAll{})
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 8)
	r.Register(Workflow{Kind: "test.createdby", Steps: []WorkflowStep{{Name: "a", Timeout: time.Second,
		Do: func(sc *StepCtx) (json.RawMessage, error) { got <- sc.CreatedBy; return nil, nil }}}})
	for _, tc := range []struct {
		by   authz.Submitter
		want string
	}{
		{authz.Person(authz.Subject{Sub: "s-1", Roles: []string{"admin"}}), "s-1"},
		{authz.SystemSubmitter("scheduler"), "scheduler"},
		{authz.RepairSession(), "break-glass"},
		{authz.BridgeGrant("s-2"), "s-2"},
	} {
		j, err := r.SubmitFor(t.Context(), tc.by, "test.createdby", nil, nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.want, err)
		}
		r.Wait()
		row, err := store.GetJob(t.Context(), j.ID)
		if err != nil || row.CreatedBy != tc.want {
			t.Errorf("row CreatedBy = %v, %v; want %q", row, err, tc.want)
		}
		if who := <-got; who != tc.want {
			t.Errorf("sc.CreatedBy = %q, want %q", who, tc.want)
		}
	}
	if j, err := r.Submit(t.Context(), "test.createdby", nil, "mesh-leaf-sweep"); err != nil || j.CreatedBy != "mesh-leaf-sweep" {
		t.Errorf("Submit = %v, %v; want the subsystem name kept", j, err)
	}
	r.Wait()
	<-got
}

// allowAll allows every submission.
type allowAll struct{}

func (allowAll) Authorize(context.Context, string, []byte, authz.Submitter) error { return nil }

// TC-1001-21: the system path runs under the real policy: a scheduler fire of
// apps.reconcile and SubmitChild of node.update under system.update run, and
// a system submission of an unmapped kind is refused unknown_kind.
func TestSystemPath_TC1001_21_RealPolicy(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	r := realRunner(t, store, nc)
	for _, k := range []string{"apps.reconcile", "system.update", "node.update", "test.unmapped"} {
		r.Register(noopWorkflow(k))
	}
	if j, err := r.SubmitRawSpec(t.Context(), "apps.reconcile", nil, "scheduler"); err != nil || j == nil {
		t.Errorf("scheduler fire of apps.reconcile = %v, %v; want it run", j, err)
	}
	parent, err := r.Submit(t.Context(), "system.update", nil, "test")
	if err != nil {
		t.Fatalf("system.update: %v", err)
	}
	if j, err := r.SubmitChild(t.Context(), "node.update", nil, "system.update", parent.ID); err != nil || j == nil {
		t.Errorf("SubmitChild node.update = %v, %v; want it run", j, err)
	}
	_, err = r.Submit(t.Context(), "test.unmapped", nil, "test")
	var kr *authz.KindRefusal
	if !errors.As(err, &kr) || kr.Code != authz.CodeUnknownKind {
		t.Errorf("system submit of an unmapped kind = %v, want unknown_kind", err)
	}
	r.Wait()
	for _, k := range []string{"apps.reconcile", "system.update", "node.update"} {
		if list, err := store.ListAllJobsByKind(t.Context(), k); err != nil || len(list) != 1 {
			t.Errorf("%s: %d rows (%v), want 1", k, len(list), err)
		}
	}
	if list, _ := store.ListAllJobsByKind(t.Context(), "test.unmapped"); len(list) != 0 {
		t.Errorf("test.unmapped: %d rows, want none", len(list))
	}
}

// SubmitOperatorSpec refuses a System kind before asking the policy, decides
// everything else through it, and stores an empty spec as {}.
func TestSubmitOperatorSpec_Authorizes(t *testing.T) {
	nc := startNATS(t)
	store := newStore(t)
	r := realRunner(t, store, nc)
	r.Register(Workflow{Kind: "identity.recover", System: true, Steps: noopWorkflow("x").Steps})
	r.Register(noopWorkflow("diag.ping"))
	viewer := authz.Person(authz.Subject{Sub: "s-v", Roles: []string{"viewer"}})
	if _, err := r.SubmitOperatorSpec(t.Context(), "identity.recover", nil, testAdmin); !errors.Is(err, ErrSystemKind) {
		t.Errorf("System kind = %v, want ErrSystemKind", err)
	}
	var kr *authz.KindRefusal
	if _, err := r.SubmitOperatorSpec(t.Context(), "diag.ping", nil, viewer); !errors.As(err, &kr) || kr.Code != authz.CodeNotPermitted {
		t.Errorf("viewer diag.ping = %v, want not_permitted", err)
	}
	j, err := r.SubmitOperatorSpec(t.Context(), "diag.ping", nil, testAdmin)
	if err != nil || string(j.Spec) != "{}" || j.CreatedBy != "s-1" {
		t.Errorf("admin diag.ping = %+v, %v; want {} created by s-1", j, err)
	}
	r.Wait()
}
