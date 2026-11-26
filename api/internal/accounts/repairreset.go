package accounts

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/markers"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The break-glass repair reset (geekdojo/geekdojo-brain#321, C1): a repair
// session resets one administrator's or designated account's sign-in. The
// account's privileged levels are recorded as its designation (reason
// repair), its second steps and recovery codes are deleted, recovery codes
// become a required action, its roles are taken away, and it gets a
// temporary password; then its sessions end. Once its setup is complete
// again, accounts.grant_designated_role gives its roles back (C29).

// RepairResetKind is the repair reset's job kind. The kind table lets only a
// repair session submit it (authz repairOnly).
const RepairResetKind = "accounts.repair_reset"

// StepClearSecondSteps is the repair reset's first step.
const StepClearSecondSteps = "clear_second_steps"

// outcomeCleared is clear_second_steps' outcome.
const outcomeCleared = "cleared"

// ErrNotRepairTarget is a reset of an account that neither holds the
// console's admin role nor has a designation.
var ErrNotRepairTarget = errors.New("accounts: the account is not an administrator or a designated account")

// The repair reset job's sentences (ERR-MESSAGE, F-321-27). Each is true at
// the step that stopped, and none promises a retry this session can make:
// the session's one reset is spent once its job exists.
const (
	sentenceRepairNotStarted = "Rasputin couldn't start this person's repair reset, so nothing was removed. " +
		"This repair session's reset is spent: make a new repair code to try again."
	sentenceRepairStopped = "The repair reset stopped part way: some of this person's second steps, recovery codes or roles " +
		"may already be removed, and their password wasn't changed, so they may not be able to sign in. " +
		"Make a new repair code and reset their sign-in again."
	sentenceRepairNotSet = "This person's second steps, recovery codes and roles were removed, but the temporary password " +
		"wasn't set, so they can't sign in. Make a new repair code and reset their sign-in again."
	sentenceRepairRefusedHead = "This person's second steps, recovery codes and roles were removed, but the temporary password was refused: "
	sentenceRepairRefusedTail = "Make a new repair code and reset their sign-in again with another password."
	sentenceRepairSessions    = "This person's second steps, recovery codes and roles were removed and the temporary password " +
		"is set, but not all of their sessions could be ended. Make a new repair code and reset their sign-in again to end them."
)

// The parts of clear_second_steps a failure's record names (its kind).
const (
	clearSpec           = "spec"
	clearFacts          = "facts"
	clearDesignation    = "designation"
	clearCredentials    = "credentials"
	clearMarkers        = "markers"
	clearRequiredAction = "required_action"
	clearDemote         = "demote"
)

// RepairTarget is an account a repair session may reset: its id and its
// sign-in name.
type RepairTarget struct {
	ID, Username string
}

// RepairAdmins lists the console's administrators (*Users).
type RepairAdmins interface {
	Administrators(ctx context.Context) ([]Account, error)
}

// RepairDesignations lists the designations (*Designations).
type RepairDesignations interface {
	List(ctx context.Context) ([]Designation, error)
}

// RepairResetsDeps are a RepairResets' collaborators.
type RepairResetsDeps struct {
	Admins       RepairAdmins
	Designations RepairDesignations
	Users        AccountReader
	Checker      PasswordChecker
	Runner       Submitter
	Held         *Held
	Log          *slog.Logger
}

// RepairResets decides and submits a repair session's reset: which accounts
// it may reset, the confirmation's token, and the job.
type RepairResets struct {
	d   RepairResetsDeps
	log *slog.Logger
}

// NewRepairResets checks d and returns a RepairResets. It does no I/O.
func NewRepairResets(d RepairResetsDeps) (*RepairResets, error) {
	if d.Admins == nil || d.Designations == nil || d.Users == nil || d.Checker == nil || d.Runner == nil || d.Held == nil || d.Log == nil {
		return nil, errors.New("accounts: NewRepairResets: a collaborator is nil")
	}
	return &RepairResets{d: d, log: d.Log.With("component", "accounts")}, nil
}

// Targets is every holder of the console's admin role and every designated
// account, each once, sorted by sign-in name. A designated id the realm
// doesn't have is left out; any other read that fails is an error, never a
// shorter list.
func (r *RepairResets) Targets(ctx context.Context) ([]RepairTarget, error) {
	admins, err := r.d.Admins.Administrators(ctx)
	if err != nil {
		return nil, fmt.Errorf("accounts: list the repair targets: %w", err)
	}
	seen := map[string]bool{}
	out := make([]RepairTarget, 0, len(admins))
	for _, a := range admins {
		if !seen[a.ID] {
			seen[a.ID] = true
			out = append(out, RepairTarget{ID: a.ID, Username: a.Username})
		}
	}
	des, err := r.d.Designations.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("accounts: list the repair targets: %w", err)
	}
	for _, x := range des {
		if seen[x.Sub] {
			continue
		}
		seen[x.Sub] = true
		p, err := r.d.Users.Read(ctx, x.Sub)
		switch {
		case errors.Is(err, idclient.ErrNotFound):
			continue
		case err != nil:
			return nil, fmt.Errorf("accounts: list the repair targets: %w", err)
		}
		out = append(out, RepairTarget{ID: x.Sub, Username: p.Username})
	}
	slices.SortFunc(out, func(a, b RepairTarget) int {
		return cmp.Or(cmp.Compare(a.Username, b.Username), cmp.Compare(a.ID, b.ID))
	})
	return out, nil
}

// repairToken is the confirmation's token for the target: it changes when
// the account's sign-in name does.
func repairToken(t RepairTarget) string {
	sum := sha256.Sum256([]byte(RepairResetKind + "\n" + t.ID + "\n" + t.Username))
	return hex.EncodeToString(sum[:])
}

// Confirm is the target id names and its token, or ErrNotRepairTarget; a
// failed read of the targets is an error wrapping ErrIdentityUnavailable.
func (r *RepairResets) Confirm(ctx context.Context, id string) (RepairTarget, string, error) {
	ts, err := r.Targets(ctx)
	if err != nil {
		return RepairTarget{}, "", fmt.Errorf("%w: %w", ErrIdentityUnavailable, err)
	}
	for _, t := range ts {
		if t.ID == id {
			return t, repairToken(t), nil
		}
	}
	return RepairTarget{}, "", ErrNotRepairTarget
}

// Submit checks pw against the policy for the account id names, then
// submits the reset for by with the spec {"accountId":id}. The password is
// held beside the job under its id, never in the spec. It returns the job,
// ErrNotRepairTarget, an error wrapping ErrIdentityUnavailable,
// *PasswordRefused, ErrPasswordCheckUnavailable, or the runner's error, in
// which case nothing stays held.
func (r *RepairResets) Submit(ctx context.Context, by authz.Submitter, id string, pw secret.Value) (*jobs.Job, error) {
	p, err := r.d.Users.Read(ctx, id)
	switch {
	case errors.Is(err, idclient.ErrNotFound):
		return nil, ErrNotRepairTarget
	case err != nil:
		return nil, fmt.Errorf("%w: %w", ErrIdentityUnavailable, err)
	}
	if err := checkPassword(ctx, r.log, r.d.Checker, pw, p.Username, p.Email); err != nil {
		return nil, err
	}
	held := ""
	j, err := r.d.Runner.SubmitFor(ctx, by, RepairResetKind, ResetSpec{AccountID: id}, func(jobID string) error {
		held = jobID
		r.d.Held.Put(jobID, secret.New(pw.Reveal()))
		return nil
	})
	if err != nil {
		if held != "" {
			r.d.Held.Drop(held)
		}
		return nil, fmt.Errorf("accounts: submit the repair reset: %w", err)
	}
	return j, nil
}

// RepairResetUsers is the account calls the repair reset makes beyond the
// change's own (*Users).
type RepairResetUsers interface {
	ResetUsers
	AddRequiredAction(ctx context.Context, sub, action string) error
}

// RepairResetWorkflow is accounts.repair_reset: clear_second_steps, then
// #992's set_temporary, then #991's second_steps_removed steps, each
// failure recording a sentence true at its stop. Its terminal hook drops
// what the job still holds, on success, failure and Recover alike.
func (c *Changes) RepairResetWorkflow(users RepairResetUsers, checker PasswordChecker) (jobs.Workflow, error) {
	if users == nil || checker == nil {
		return jobs.Workflow{}, errors.New("accounts: RepairResetWorkflow: a collaborator is nil")
	}
	set := ResetDeps{Users: users, Held: c.d.Held, Checker: checker, Lock: c.d.Lock}
	steps := []jobs.WorkflowStep{
		{Name: StepClearSecondSteps, Timeout: c.d.StepTimeout, Do: c.clearSecondSteps(users)},
		repairStep(jobs.WorkflowStep{Name: StepSetTemporary, Timeout: c.d.StepTimeout, Do: setTemporary(set, c.log)}, repairSetSentence),
	}
	for _, s := range c.d.Revoker.Steps(SecondStepsRemoved) {
		steps = append(steps, repairStep(s, func(*StepError) string { return sentenceRepairSessions }))
	}
	return jobs.Workflow{Kind: RepairResetKind, Steps: steps, OnTerminal: c.terminal}, nil
}

// repairStep is step with the sentence of a *StepError it fails with
// replaced by sentence's: its step and cause are kept.
func repairStep(step jobs.WorkflowStep, sentence func(se *StepError) string) jobs.WorkflowStep {
	do := step.Do
	step.Do = func(sc *jobs.StepCtx) (json.RawMessage, error) {
		out, err := do(sc)
		var se *StepError
		if err != nil && errors.As(err, &se) {
			return out, &StepError{Step: se.Step, Sentence: sentence(se), Err: se.Err}
		}
		return out, err
	}
	return step
}

// repairSetSentence is set_temporary's sentence in a repair reset: the
// password refused by a rule names the rule; any other failure says the
// password wasn't set.
func repairSetSentence(se *StepError) string {
	switch se.Sentence {
	case sentenceSetFailed, sentenceNotHeld, sentenceSpec:
		return sentenceRepairNotSet
	}
	return sentenceRepairRefusedHead + se.Sentence + " " + sentenceRepairRefusedTail
}

// clearSecondSteps is the repair reset's first step, under the one accounts
// lock: the account's privileged levels recorded as its designation (reason
// repair, keeping the higher), every second step and the recovery codes
// deleted (the password kept), the markers recomputed, recovery codes made
// a required action, then the levels taken away. A run that stops part way
// leaves the account locked out, never open, with every level not yet taken
// still recorded, and never reaches set_temporary.
func (c *Changes) clearSecondSteps(users RepairResetUsers) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		var spec ResetSpec
		if err := json.Unmarshal(sc.Spec, &spec); err != nil || spec.AccountID == "" {
			return nil, c.clearFailed(sc, clearSpec, errors.New("the spec names no account"))
		}
		c.d.Lock.Lock()
		defer c.d.Lock.Unlock()
		n, part, err := c.clearAccount(sc.Ctx, users, spec.AccountID)
		if err != nil {
			return nil, c.clearFailed(sc, part, err)
		}
		jobs.LogStep(c.log, sc, slog.LevelInfo, StepClearSecondSteps+": "+outcomeCleared+" credentials="+fmt.Sprint(n),
			"event", "repair_reset.cleared", "outcome", outcomeCleared, "credentials", n)
		return json.Marshal(map[string]any{"outcome": outcomeCleared, "credentials": n})
	}
}

// clearAccount is clearSecondSteps' writes, in order, under the lock. It
// returns how many credentials it deleted, and on a failure the part that
// failed.
func (c *Changes) clearAccount(ctx context.Context, users RepairResetUsers, sub string) (int, string, error) {
	f, err := c.d.Facts.Facts(ctx, sub)
	if err != nil {
		return 0, clearFacts, err
	}
	lv := authz.PrivilegedLevels(f)
	if err := designateLevels(ctx, c.d.Designations, sub, lv, ReasonRepair); err != nil {
		return 0, clearDesignation, err
	}
	n, err := deleteCredentials(ctx, c.d.Users, sub, func(t string) bool { return markers.IsSecondStep(t) || t == typeRecoveryCodes })
	if err != nil {
		return n, clearCredentials, err
	}
	if err := c.d.Markers.AfterRemoval(ctx, sub); err != nil {
		return n, clearMarkers, err
	}
	if err := users.AddRequiredAction(ctx, sub, flows.ActionRecoveryCodes); err != nil {
		return n, clearRequiredAction, err
	}
	if err := demoteLevels(ctx, c.d.Users, sub, lv); err != nil {
		return n, clearDemote, err
	}
	return n, "", nil
}

// clearFailed writes clear_second_steps' one ERROR record, naming the part
// that failed and never the account, and returns the step's failure with
// the sentence true there: nothing removed before the first delete, part
// way after it.
func (c *Changes) clearFailed(sc *jobs.StepCtx, part string, err error) error {
	jobs.LogStep(c.log, sc, slog.LevelError, StepClearSecondSteps+": failed",
		"event", "repair_reset.clear_failed", "kind", part, "cause", errKind(err))
	sentence := sentenceRepairStopped
	switch part {
	case clearSpec, clearFacts, clearDesignation:
		sentence = sentenceRepairNotStarted
	}
	return failStep(StepClearSecondSteps, sentence, err)
}
