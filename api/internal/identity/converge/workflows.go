package converge

import (
	"context"
	"encoding/json"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// The job kinds.
const (
	ConvergeKind = "identity.converge"
	MigrateKind  = "identity.migrate"
	ArmKind      = "identity.arm"
)

// ConvergeWorkflow is identity.converge's one step. It is not System, so an
// iam operator may re-run it through POST /api/jobs. stepTimeout only marks
// a run gone far outside normal as dead.
func ConvergeWorkflow(c *Converger, stepTimeout time.Duration) jobs.Workflow {
	return jobs.Workflow{Kind: ConvergeKind, Steps: []jobs.WorkflowStep{{
		Name: "converge", Timeout: stepTimeout,
		Do: func(sc *jobs.StepCtx) (json.RawMessage, error) {
			fields, err := c.RunJob(sc.Ctx, sc.JobID)
			if err != nil {
				return nil, err
			}
			return json.Marshal(map[string]any{"repaired": nonNil(fields)})
		},
	}}}
}

// migrator is the migrations runner (migrations.Runner).
type migrator interface {
	RunJob(ctx context.Context, jobID string) ([]int, error)
}

// MigrateWorkflow is identity.migrate's one step, running the runner it is
// given (migrations.All only). It is System: only its trigger submits it.
func MigrateWorkflow(r migrator, stepTimeout time.Duration) jobs.Workflow {
	return jobs.Workflow{Kind: MigrateKind, System: true, Steps: []jobs.WorkflowStep{{
		Name: "migrate", Timeout: stepTimeout,
		Do: func(sc *jobs.StepCtx) (json.RawMessage, error) {
			ids, err := r.RunJob(sc.Ctx, sc.JobID)
			if err != nil {
				return nil, err
			}
			if ids == nil {
				ids = []int{}
			}
			return json.Marshal(map[string]any{"applied": ids})
		},
	}}}
}

// ArmWorkflow is identity.arm's one step. It is System: only its trigger
// submits it.
func ArmWorkflow(a *Armer, stepTimeout time.Duration) jobs.Workflow {
	return jobs.Workflow{Kind: ArmKind, System: true, Steps: []jobs.WorkflowStep{{
		Name: "arm", Timeout: stepTimeout,
		Do: func(sc *jobs.StepCtx) (json.RawMessage, error) {
			if err := a.RunJob(sc.Ctx, sc.JobID); err != nil {
				return nil, err
			}
			return json.RawMessage(`{"armed":true}`), nil
		},
	}}}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
