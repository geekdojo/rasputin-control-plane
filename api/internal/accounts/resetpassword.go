package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/pwpolicy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// ResetKind is the administrator's password reset job kind
// (geekdojo/geekdojo-brain#992, Identity 4.10).
const ResetKind = "accounts.reset_password"

// StepSetTemporary is the reset's first step; #991's sign_out steps follow.
const StepSetTemporary = "set_temporary"

// ResetSpec is accounts.reset_password's spec: the account's id, never the
// password, which travels beside the job in Held.
type ResetSpec struct {
	AccountID string `json:"accountId"`
}

// The set_temporary step's sentences (ERR-MESSAGE).
const (
	sentenceSetFailed = "The sign-in service couldn't set the temporary password. Nothing was changed."
	sentenceNotHeld   = "The temporary password is no longer held. Start the reset again."
)

// ResetUsers is the account calls the reset makes (*Users).
type ResetUsers interface {
	Read(ctx context.Context, sub string) (Person, error)
	SetTemporaryPassword(ctx context.Context, sub string, pw secret.Value) (int, error)
}

// PasswordChecker is the realm's password policy (*pwpolicy.Checker).
type PasswordChecker interface {
	Check(pw secret.Value, username, email string) (pwpolicy.Refusal, error)
}

// SignOutSteps are #991's identity.revoke steps for a kind (*Revoker).
type SignOutSteps interface {
	Steps(kind RevokeKind) []jobs.WorkflowStep
}

// ResetDeps are ResetPasswordWorkflow's collaborators.
type ResetDeps struct {
	Users   ResetUsers
	Held    *Held
	Checker PasswordChecker
	Revoker SignOutSteps
	// Lock is the one accounts lock, held for set_temporary's write
	// (geekdojo/geekdojo-brain#994).
	Lock sync.Locker
	Log  *slog.Logger
	// StepTimeout bounds set_temporary; it marks work gone far outside
	// normal and decides nothing else.
	StepTimeout time.Duration
}

// ResetPasswordWorkflow is accounts.reset_password: set_temporary, then
// #991's sign_out steps, which end every session of the target. Its
// terminal hook destroys a password still held, on success, failure and
// Recover alike. It refuses a missing collaborator.
func ResetPasswordWorkflow(d ResetDeps) (jobs.Workflow, error) {
	if d.Users == nil || d.Held == nil || d.Checker == nil || d.Revoker == nil || d.Lock == nil || d.Log == nil {
		return jobs.Workflow{}, errors.New("accounts: ResetPasswordWorkflow: a collaborator is nil")
	}
	if d.StepTimeout <= 0 {
		return jobs.Workflow{}, fmt.Errorf("accounts: ResetPasswordWorkflow: StepTimeout %v is not positive", d.StepTimeout)
	}
	log := d.Log.With("component", "accounts")
	steps := append([]jobs.WorkflowStep{{Name: StepSetTemporary, Timeout: d.StepTimeout, Do: setTemporary(d, log)}},
		d.Revoker.Steps(SignOut)...)
	return jobs.Workflow{
		Kind:  ResetKind,
		Steps: steps,
		OnTerminal: func(_ context.Context, jobID string, _ bool, _ string) {
			d.Held.Drop(jobID)
		},
	}, nil
}

// setTemporary takes the held password and sets it, marked temporary. A
// 500 is re-checked against the policy: a rule it names is the step's
// sentence, since Keycloak answers a refusal with the same status as a
// fault. No attempt is retried.
func setTemporary(d ResetDeps, log *slog.Logger) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		fail := func(sentence string, err error, level slog.Level, msg string, attrs ...any) error {
			jobs.LogStep(log, sc, level, msg, attrs...)
			return failStep(StepSetTemporary, sentence, err)
		}
		pw, ok := d.Held.Take(sc.JobID)
		if !ok {
			return nil, fail(sentenceNotHeld, errors.New("no password is held for the job"), slog.LevelWarn,
				StepSetTemporary+": nothing held", "event", "reset.not_held")
		}
		defer pw.Destroy()
		var spec ResetSpec
		if err := json.Unmarshal(sc.Spec, &spec); err != nil || spec.AccountID == "" {
			return nil, fail(sentenceSpec, errors.New("the spec names no account"), slog.LevelWarn,
				StepSetTemporary+": failed", "event", "reset.set_failed", "cause", "spec")
		}
		d.Lock.Lock()
		status, err := d.Users.SetTemporaryPassword(sc.Ctx, spec.AccountID, pw)
		d.Lock.Unlock()
		switch {
		case err == nil:
			jobs.LogStep(log, sc, slog.LevelInfo, StepSetTemporary+": set", "event", "reset.set")
			return json.RawMessage(`{"outcome":"set"}`), nil
		case status == http.StatusInternalServerError:
			if ref, ok := refusedByPolicy(sc.Ctx, d, spec.AccountID, pw); ok {
				return nil, fail(ref.Sentence, err, slog.LevelWarn, StepSetTemporary+": refused by the password policy",
					"event", "reset.refused_by_policy", "rule", ref.Rule)
			}
		}
		return nil, fail(sentenceSetFailed, err, slog.LevelError, StepSetTemporary+": failed",
			"event", "reset.set_failed", "status", statusText(status))
	}
}

// refusedByPolicy re-runs the policy for the account's own name and email,
// and reports the rule the password breaks, if it names one. A read or a
// check that fails here reports none: the step then fails with the fault
// sentence, whose record carries the Admin API's status.
func refusedByPolicy(ctx context.Context, d ResetDeps, sub string, pw secret.Value) (pwpolicy.Refusal, bool) {
	p, err := d.Users.Read(ctx, sub)
	if err != nil {
		return pwpolicy.Refusal{}, false
	}
	ref, err := d.Checker.Check(pw, p.Username, p.Email)
	if err != nil || !ref.Refused() {
		return pwpolicy.Refusal{}, false
	}
	return ref, true
}
