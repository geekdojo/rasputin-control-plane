package appsecret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
)

// The store reference check (geekdojo/geekdojo-brain#800).
//
// After an OS update falls back to the slot it left, the secret store's data
// is put back from the copy taken before the update (#801). An entry created
// after that copy is then gone while the row that names it is not. The check
// runs once per api process, on the first reading that finds the store
// ready, and fails its job naming every recorded reference whose entry the
// store no longer holds: the job-failed alert carries the sentence, and each
// reference gets an ERROR record. The references are the ones StoreSource
// recorded when it confirmed an entry, so an app the cluster never created
// an entry for (never deployed through the store, or last deployed before
// the store existed) is never reported (F-800-01).

// ReferenceCheckKind is the check's job kind.
const ReferenceCheckKind = "store.reference_check"

// referenceCheckTimeout bounds the one step's I/O: one database read and
// one metadata read per reference, each under its own client bound. Running
// out of it fails the check as could-not-check; it decides nothing else.
const referenceCheckTimeout = 5 * time.Minute

// SecretRef is one recorded store entry: app AppID's ${secret:Name}.
type SecretRef struct {
	AppID string
	Name  string
}

// RefLister lists every recorded reference (apps.Store.ListSecretRefs, as
// main adapts it).
type RefLister interface {
	ListSecretRefs(ctx context.Context) ([]SecretRef, error)
}

// SecretChecker asks whether an entry exists (secrets.Service.Exists).
type SecretChecker interface {
	Exists(ctx context.Context, a secrets.Actor, r secrets.Ref) (bool, error)
}

// ReferenceCheckDeps is everything the check needs. ReferenceCheckWorkflow
// refuses a nil one.
type ReferenceCheckDeps struct {
	Refs    RefLister
	Secrets SecretChecker
	Log     *slog.Logger
}

// referenceCheckResult is the job's result when nothing is missing.
type referenceCheckResult struct {
	Checked int `json:"checked"`
	Missing int `json:"missing"`
}

// errReferencesUnchecked is the check that could not finish: a reference
// that could not be listed, parsed or asked about is never counted present
// (ERR-CLOSED).
const errReferencesUnchecked jobError = "The secret store's references could not be checked, so a secret lost when its data was put back would not be noticed. The api log names the cause; the check runs again at the next api start."

// jobError is an error whose text is a sentence the job records and the
// job-failed alert carries (ERR-MESSAGE).
type jobError string

func (e jobError) Error() string { return string(e) }

// ReferenceCheckWorkflow returns the store.reference_check workflow.
func ReferenceCheckWorkflow(d ReferenceCheckDeps) (jobs.Workflow, error) {
	switch {
	case d.Refs == nil:
		return jobs.Workflow{}, errors.New("appsecret: ReferenceCheckWorkflow: Deps.Refs is nil")
	case d.Secrets == nil:
		return jobs.Workflow{}, errors.New("appsecret: ReferenceCheckWorkflow: Deps.Secrets is nil")
	case d.Log == nil:
		return jobs.Workflow{}, errors.New("appsecret: ReferenceCheckWorkflow: Deps.Log is nil")
	}
	c := &referenceCheck{d: d}
	return jobs.Workflow{
		Kind:  ReferenceCheckKind,
		Steps: []jobs.WorkflowStep{{Name: "check_references", Timeout: referenceCheckTimeout, Do: c.check}},
	}, nil
}

type referenceCheck struct{ d ReferenceCheckDeps }

// check asks the store about every recorded reference.
func (c *referenceCheck) check(sc *jobs.StepCtx) (json.RawMessage, error) {
	ctx := jobs.ContextWithJobID(sc.Ctx, sc.JobID)
	refs, err := c.d.Refs.ListSecretRefs(ctx)
	if err != nil {
		c.unchecked(ctx, sc, "", "", slog.String("err", err.Error()))
		return nil, errReferencesUnchecked
	}
	var missing []string
	for _, rr := range refs {
		ref, err := secrets.AppSecret(rr.AppID, rr.Name)
		if err != nil {
			c.unchecked(ctx, sc, rr.AppID, rr.Name, slog.String("err", err.Error()))
			return nil, errReferencesUnchecked
		}
		ok, err := c.d.Secrets.Exists(ctx, secrets.CheckActor(), ref)
		if err != nil {
			attrs := []slog.Attr{slog.String("ref", ref.String())}
			var se *secretstore.Error
			if errors.As(err, &se) {
				attrs = append(attrs, se.LogAttrs()...)
			} else {
				attrs = append(attrs, slog.String("err", err.Error()))
			}
			c.unchecked(ctx, sc, rr.AppID, rr.Name, attrs...)
			return nil, errReferencesUnchecked
		}
		if ok {
			continue
		}
		missing = append(missing, ref.String())
		c.d.Log.LogAttrs(ctx, slog.LevelError, "secret store entry missing for a recorded reference",
			slog.String("component", "appsecret"), slog.String("event", "appsecret.dangling_ref"),
			slog.String("app_id", rr.AppID), slog.String("ref", ref.String()), slog.String("job_id", sc.JobID))
		sc.Log("error", "missing from the secret store: "+ref.String())
	}
	if len(missing) > 0 {
		c.d.Log.LogAttrs(ctx, slog.LevelError, "secret store reference check found missing entries",
			slog.String("component", "appsecret"), slog.String("event", "appsecret.reference_check"),
			slog.String("outcome", "dangling"), slog.Int("checked", len(refs)), slog.Int("missing", len(missing)),
			slog.String("job_id", sc.JobID))
		return nil, danglingRefs(missing)
	}
	c.d.Log.LogAttrs(ctx, slog.LevelInfo, "secret store reference check passed",
		slog.String("component", "appsecret"), slog.String("event", "appsecret.reference_check"),
		slog.String("outcome", "ok"), slog.Int("checked", len(refs)), slog.Int("missing", 0),
		slog.String("job_id", sc.JobID))
	sc.Log("info", fmt.Sprintf("checked %d recorded secret reference(s): none missing", len(refs)))
	return json.Marshal(referenceCheckResult{Checked: len(refs)})
}

// unchecked logs a check that could not finish at ERROR, with its cause.
func (c *referenceCheck) unchecked(ctx context.Context, sc *jobs.StepCtx, appID, name string, extra ...slog.Attr) {
	attrs := append([]slog.Attr{
		slog.String("component", "appsecret"), slog.String("event", "appsecret.reference_check"),
		slog.String("outcome", "unchecked"), slog.String("app_id", appID), slog.String("name", name),
		slog.String("job_id", sc.JobID),
	}, extra...)
	c.d.Log.LogAttrs(ctx, slog.LevelError, "secret store reference check could not finish", attrs...)
	sc.Log("error", "the secret store's references could not be checked; the api log names the cause")
}

// danglingRefs is the failed check's sentence, naming every missing entry.
func danglingRefs(missing []string) error {
	what := "1 secret"
	if len(missing) > 1 {
		what = fmt.Sprintf("%d secrets", len(missing))
	}
	return jobError("The secret store no longer holds " + what + " this cluster created: " + strings.Join(missing, ", ") +
		". The next deploy of each app creates it again with its first value, so a secret an operator had replaced must be set again.")
}
