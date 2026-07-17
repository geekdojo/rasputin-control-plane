package obs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// Enabling observability is a job, not a request handler, for one blunt
// reason: a cold enable pulls ~500 MB of images. The supervisor's own pull
// budget is 5 minutes and its health wait another 90s — well past any sane
// HTTP timeout, and past the point an operator will keep a spinner open.
//
// Modeling it as a saga buys the progress story for free: /tasks already
// renders a live step timeline + event log for every job, so "pulling
// images…" shows up without a toast system (the UI has none) or a bespoke
// progress endpoint.

// SetEnabledFn persists the operator's observability opt-in. Injected as a
// closure so this package never imports the settings store.
type SetEnabledFn func(ctx context.Context, on bool) error

// SetSinkFn installs (on) or removes (off) the metrics fan-out to
// VictoriaMetrics. Injected rather than taking a *metrics.Service: metrics
// already imports obs for the Sink implementation, so importing it back
// would be a cycle.
//
// The fan-out has to be toggled, not left installed — VMSink.Write returns
// an error when the stack is down and metrics.Service logs every one, so a
// permanently-installed sink would spam the log every 10s per node while
// observability is off.
type SetSinkFn func(on bool)

// RuntimePresent reports whether a container runtime is usable on this
// host. Injected; main owns the lookup.
type RuntimePresent func() bool

// EnableWorkflow turns observability on.
//
//  1. preflight — no container runtime ⇒ fail now with a readable message,
//     rather than a compose error five minutes into a pull.
//  2. persist   — record the intent BEFORE starting. If the api dies
//     mid-pull the operator's choice survives and the next boot finishes
//     the job. The reverse order loses it.
//  3. start     — render compose, pull, up, wait for health.
//  4. fan_out   — install the sink so samples start landing in VM.
//
// Idempotent end to end: the supervisor's Start is a no-op on an already
// running stack, and persist/fan_out are both writes of a fixed value. A
// double-click costs a health check, not a second stack.
func EnableWorkflow(sup Supervisor, set SetEnabledFn, setSink SetSinkFn, runtime RuntimePresent) jobs.Workflow {
	return jobs.Workflow{
		Kind: "obs.enable",
		Steps: []jobs.WorkflowStep{
			{
				Name:    "preflight",
				Timeout: 10 * time.Second,
				Do: func(sc *jobs.StepCtx) (json.RawMessage, error) {
					if runtime != nil && !runtime() {
						return nil, errors.New("no container runtime found on this control plane — observability needs one to run")
					}
					return nil, nil
				},
			},
			{
				Name:    "persist",
				Timeout: 5 * time.Second,
				Do: func(sc *jobs.StepCtx) (json.RawMessage, error) {
					if err := set(sc.Ctx, true); err != nil {
						return nil, fmt.Errorf("persist observability setting: %w", err)
					}
					sc.Log("info", "observability turned on — bringing up metrics and logs")
					return nil, nil
				},
			},
			{
				Name: "start",
				// 12m: the supervisor's 5m pull budget + 90s health wait,
				// with headroom for a slow link. Deliberately not retried —
				// a second attempt would cost another 12 minutes and a
				// failed pull rarely succeeds on an immediate retry. The
				// operator re-runs from the UI instead.
				Timeout: 12 * time.Minute,
				Do: func(sc *jobs.StepCtx) (json.RawMessage, error) {
					sc.Log("info", "pulling images and starting services — first run downloads roughly 500 MB and can take several minutes")
					if err := sup.Start(sc.Ctx); err != nil {
						return nil, fmt.Errorf("start observability stack: %w", err)
					}
					sc.Log("info", "observability stack is up and answering health checks")
					return nil, nil
				},
			},
			{
				Name:    "fan_out",
				Timeout: 5 * time.Second,
				Do: func(sc *jobs.StepCtx) (json.RawMessage, error) {
					if setSink != nil {
						setSink(true)
					}
					sc.Log("info", "node metrics are now being recorded for history")
					return nil, nil
				},
			},
		},
	}
}

// DisableWorkflow turns observability off.
//
//  1. persist — record the intent first, so a crash mid-teardown doesn't
//     resurrect the stack on the next boot.
//  2. fan_out — stop writing before the target goes away, so teardown
//     doesn't generate a burst of "vm not healthy" errors.
//  3. stop    — `docker compose stop`. Volumes persist, so re-enabling
//     later comes back with its history intact rather than starting blind.
func DisableWorkflow(sup Supervisor, set SetEnabledFn, setSink SetSinkFn) jobs.Workflow {
	return jobs.Workflow{
		Kind: "obs.disable",
		Steps: []jobs.WorkflowStep{
			{
				Name:    "persist",
				Timeout: 5 * time.Second,
				Do: func(sc *jobs.StepCtx) (json.RawMessage, error) {
					if err := set(sc.Ctx, false); err != nil {
						return nil, fmt.Errorf("persist observability setting: %w", err)
					}
					return nil, nil
				},
			},
			{
				Name:    "fan_out",
				Timeout: 5 * time.Second,
				Do: func(sc *jobs.StepCtx) (json.RawMessage, error) {
					if setSink != nil {
						setSink(false)
					}
					return nil, nil
				},
			},
			{
				Name:    "stop",
				Timeout: 2 * time.Minute,
				Do: func(sc *jobs.StepCtx) (json.RawMessage, error) {
					if err := sup.Stop(sc.Ctx); err != nil {
						return nil, fmt.Errorf("stop observability stack: %w", err)
					}
					sc.Log("info", "observability stopped — recorded history is kept and will be there if you turn it back on")
					return nil, nil
				},
			},
		},
	}
}
