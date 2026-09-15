package mesh

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// An enroll targets a valid, registered node. The saga checks that itself —
// a spec can reach it from the jobs endpoint without passing the HTTP handler
// — and refuses in its validate step, before a key is minted or anything is
// sent to a node.

var invalidEnrollNodeIDs = []string{"*", ">", "a.b", "a b", "Alpha", "node_1", "-alpha", strings.Repeat("a", 64)}

func TestParseEnrollSession_RejectsInvalidNodeID(t *testing.T) {
	for _, id := range invalidEnrollNodeIDs {
		spec, _ := json.Marshal(EnrollSpec{NodeID: id})
		if _, err := parseEnrollSession(spec); err == nil {
			t.Errorf("parseEnrollSession accepted nodeId %q", id)
		}
	}
	spec, _ := json.Marshal(EnrollSpec{NodeID: "alpha"})
	if s, err := parseEnrollSession(spec); err != nil || s.NodeID != "alpha" {
		t.Errorf("parseEnrollSession(alpha) = %+v, %v; want accepted", s, err)
	}
}

func TestEnrollWorkflow_ValidateRequiresRegisteredNode(t *testing.T) {
	f := newConvergeFixture(t)
	f.addNode(t, "alpha", proto.RoleCompute, time.Now().UTC())
	validate := enrollStep(t, EnrollNodeWorkflow(f.svc, f.inv, f.nc), "validate")

	run := func(id string) error {
		spec, _ := json.Marshal(EnrollSpec{NodeID: id})
		_, err := validate.Do(&jobs.StepCtx{Ctx: f.ctx, JobID: "test-job", Spec: spec, NATS: f.nc,
			PriorResults: map[string]json.RawMessage{}, Log: func(string, string) {}})
		return err
	}
	if err := run("alpha"); err != nil {
		t.Errorf("validate refused a registered node: %v", err)
	}
	if err := run("beta"); err == nil || !strings.Contains(err.Error(), "beta is not registered") {
		t.Errorf("validate on an unregistered node = %v; want it refused as not registered", err)
	}
	for _, id := range invalidEnrollNodeIDs {
		if err := run(id); err == nil {
			t.Errorf("validate accepted nodeId %q", id)
		}
	}

	// Without inventory the check cannot be made, so the step fails closed.
	spec, _ := json.Marshal(EnrollSpec{NodeID: "alpha"})
	noInv := enrollStep(t, EnrollNodeWorkflow(f.svc, nil, f.nc), "validate")
	if _, err := noInv.Do(&jobs.StepCtx{Ctx: f.ctx, JobID: "test-job", Spec: spec, NATS: f.nc,
		PriorResults: map[string]json.RawMessage{}, Log: func(string, string) {}}); err == nil {
		t.Error("validate without inventory accepted the enroll")
	}
}

// Through the real runner, as a job submitted with an arbitrary spec: an
// invalid or unregistered target fails the job, mints no key, and publishes
// nothing on any node subject.
func TestEnrollJob_InvalidOrUnregisteredTargetSendsNothing(t *testing.T) {
	f := newConvergeFixture(t)
	f.addNode(t, "alpha", proto.RoleCompute, time.Now().UTC())

	jst, err := jobs.OpenStore(f.ctx, filepath.Join(t.TempDir(), "enroll-jobs.db"))
	if err != nil {
		t.Fatalf("jobs.OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = jst.Close() })
	runner := jobs.NewRunner(jst, f.nc)
	runner.Register(EnrollNodeWorkflow(f.svc, f.inv, f.nc))

	nodeMsgs, err := f.nc.SubscribeSync("rasputin.node.>")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer func() { _ = nodeMsgs.Unsubscribe() }()
	if err := f.nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	targets := append([]string{"beta"}, invalidEnrollNodeIDs...)
	ids := make([]string, 0, len(targets))
	for _, id := range targets {
		spec, _ := json.Marshal(EnrollSpec{NodeID: id})
		j, err := runner.Submit(f.ctx, "mesh.enroll_node", spec, "test")
		if err != nil {
			t.Fatalf("Submit(%q): %v", id, err)
		}
		ids = append(ids, j.ID)
	}
	runner.Wait()

	for i, jobID := range ids {
		j, err := jst.GetJob(f.ctx, jobID)
		if err != nil || j == nil {
			t.Fatalf("GetJob(%s): %v", jobID, err)
		}
		if j.Status != jobs.StatusFailed {
			t.Errorf("enroll of %q finished %s; want failed", targets[i], j.Status)
		}
		steps, err := jst.ListSteps(f.ctx, jobID)
		if err != nil {
			t.Fatalf("ListSteps(%s): %v", jobID, err)
		}
		for _, st := range steps {
			if st.Name != "validate" && st.Status != jobs.StepPending {
				t.Errorf("enroll of %q ran step %s (%s); want only validate to run", targets[i], st.Name, st.Status)
			}
		}
	}

	if err := f.nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if m, err := nodeMsgs.NextMsg(200 * time.Millisecond); err == nil {
		t.Errorf("a refused enroll published %s", m.Subject)
	}
	if keys, _ := f.svc.Client().ListPreAuthKeys(f.ctx, f.svc.cfg.DefaultUser); len(keys) != 0 {
		t.Errorf("a refused enroll minted %d preauth key(s); want 0", len(keys))
	}
}
