package mesh

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Mesh membership decisions read the api's one in-memory node registry
// (geekdojo-brain#585) rather than the nodes table: same question, one list.

// converge_enrollment takes its node SET from the registry, not the nodes
// table: with the database closed it still converges the members it holds,
// and a node removed from inventory drops out of the set at once.
func TestConvergeEnrollment_NodeSetComesFromTheRegistry(t *testing.T) {
	f := newConvergeFixture(t)
	now := time.Now().UTC()
	f.addNode(t, "compute1", proto.RoleCompute, now)
	f.addNode(t, "compute2", proto.RoleCompute, now)
	if err := f.inv.Delete(f.ctx, "compute2"); err != nil {
		t.Fatal(err)
	}
	if err := f.inv.Close(); err != nil {
		t.Fatal(err)
	}

	out, err := reconcileConvergeEnrollment(f.svc, f.inv, f.jstore, f.runner)(stepCtx(f.ctx, f.nc, struct{}{}))
	if err != nil {
		t.Fatalf("converge_enrollment with the nodes table closed: %v", err)
	}
	var res struct {
		Submitted []string `json:"submitted"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("decode %s: %v", out, err)
	}
	if !slices.Equal(res.Submitted, []string{"compute1"}) {
		t.Errorf("submitted = %v, want [compute1]", res.Submitted)
	}
}

// The enroll job's validate step answers from the registry too: it accepts a
// member with the database closed, and refuses a node that is not one.
func TestEnrollValidate_MembershipComesFromTheRegistry(t *testing.T) {
	f := newConvergeFixture(t)
	f.addNode(t, "alpha", proto.RoleCompute, time.Now().UTC())
	validate := enrollStep(t, EnrollNodeWorkflow(f.svc, f.inv, f.nc), "validate")
	run := func(id string) error {
		spec, _ := json.Marshal(EnrollSpec{NodeID: id})
		_, err := validate.Do(&jobs.StepCtx{Ctx: f.ctx, JobID: "test-job", Spec: spec, NATS: f.nc,
			PriorResults: map[string]json.RawMessage{}, Log: func(string, string) {}})
		return err
	}
	if err := f.inv.Close(); err != nil {
		t.Fatal(err)
	}
	if err := run("alpha"); err != nil {
		t.Errorf("validate refused a member with the database closed: %v", err)
	}
	if err := run("beta"); err == nil || !strings.Contains(err.Error(), "beta is not registered") {
		t.Errorf("validate on a non-member = %v; want it refused as not registered", err)
	}
}
