package converge

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

type noMigrations struct{}

func (noMigrations) RunJob(context.Context, string) ([]int, error) { return nil, nil }

// TC-981-14: with the three workflows registered, identity.converge goes
// through SubmitOperatorSpec and identity.migrate and identity.arm are
// refused with ErrSystemKind before any job row exists.
func TestWorkflows_WhoMaySubmit(t *testing.T) {
	store, err := jobs.OpenStore(t.Context(), filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	policy, err := authz.NewKindPolicy(noAppReader{})
	if err != nil {
		t.Fatal(err)
	}
	r, err := jobs.NewAuthorizedRunner(store, nil, policy)
	if err != nil {
		t.Fatal(err)
	}
	admin := authz.Person(authz.Subject{Sub: "s-admin", Roles: []string{"admin"}})
	rig := newRig(t)
	a := newArmRig(t)
	for _, wf := range []jobs.Workflow{
		ConvergeWorkflow(rig.c, time.Minute), MigrateWorkflow(noMigrations{}, time.Minute), ArmWorkflow(a.a, time.Minute),
	} {
		r.Register(wf)
	}
	for _, kind := range []string{MigrateKind, ArmKind} {
		if _, err := r.SubmitOperatorSpec(t.Context(), kind, nil, admin); !errors.Is(err, jobs.ErrSystemKind) {
			t.Errorf("operator submit of %s = %v, want ErrSystemKind", kind, err)
		}
		if list, err := store.ListAllJobsByKind(t.Context(), kind); err != nil || len(list) != 0 {
			t.Errorf("%s: %d job rows (%v), want none", kind, len(list), err)
		}
	}
	j, err := r.SubmitOperatorSpec(t.Context(), ConvergeKind, nil, admin)
	if err != nil || j == nil {
		t.Fatalf("operator submit of %s = %v, %v; want accepted", ConvergeKind, j, err)
	}
	r.Wait()
	if list, err := store.ListAllJobsByKind(t.Context(), ConvergeKind); err != nil || len(list) != 1 {
		t.Errorf("%s: %d job rows (%v), want 1", ConvergeKind, len(list), err)
	}
}

// noAppReader is an authz.AppReader that knows no app.
type noAppReader struct{}

func (noAppReader) AppFacts(context.Context, string, string) (authz.AppFacts, error) {
	return authz.AppFacts{}, authz.ErrNoApp
}
