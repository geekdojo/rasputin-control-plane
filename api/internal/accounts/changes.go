package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/markers"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The account workflows of Identity 4.12 (geekdojo/geekdojo-brain#994).
// Each change step runs under the one accounts lock: through the guard,
// which holds it while it decides and applies, or taking it itself. Each
// writes one INFO line with its outcome, and a failure one WARN line
// (ERROR for a write the identity service did not keep) with the step and
// an Admin API error's status and kind or a refusal's code, never the
// account.

// The steps this file adds before and after #991's.
const (
	// StepWithdraw withdraws a designation field after a change took
	// access away.
	StepWithdraw = "withdraw"
)

// The outcomes the change steps record.
const (
	outcomeApplied    = "applied"
	outcomeDesignated = "designated"
	outcomeChanged    = "changed"
	outcomeWithdrawn  = "withdrawn"
)

// The change steps' sentences (ERR-MESSAGE).
const (
	sentenceFresh       = "This change needs a fresh sign-in. Start it again and sign in when asked."
	sentenceValueGone   = "The value for this change is no longer held. Start it again."
	sentenceNotKept     = "The sign-in service didn't keep this change. Try again."
	sentenceDesignation = "Rasputin couldn't record this person's designated role, so nothing was changed. Try again."
	sentenceEmailTaken  = "Another account already uses that email address."
	sentenceEmailListed = "That email address belonged to a removed account and can't be used again."
	sentenceEmailList   = "Rasputin couldn't check the removed-name list, so the email address wasn't changed. Try again."
	sentenceNoEmail     = "This person's account has no email address to confirm."
	sentenceMarkers     = "Rasputin couldn't update this person's sign-in settings. Try again."
)

// ChangeUsers is the account calls the changes make (*Users).
type ChangeUsers interface {
	Read(ctx context.Context, sub string) (Person, error)
	ConsoleRoles(ctx context.Context, sub string) ([]string, error)
	SetConsoleRole(ctx context.Context, sub, role string) error
	SetAppRole(ctx context.Context, sub string, level AppLevel) error
	SetNetwork(ctx context.Context, sub string, grants []string) error
	SetEnabled(ctx context.Context, sub string, enabled bool) error
	SetEmail(ctx context.Context, sub, addr string, confirmed bool) error
	ConfirmEmail(ctx context.Context, sub string) error
	SetDisplayName(ctx context.Context, sub, name string) error
	Unlock(ctx context.Context, sub string) error
	CredentialList(ctx context.Context, sub string) ([]Credential, error)
	DeleteCredential(ctx context.Context, sub, credID string) error
	RenameCredential(ctx context.Context, sub, credID string, label secret.Value) error
}

// LockedGranter gives app access to a caller holding the accounts lock
// (*Access).
type LockedGranter interface {
	grantLocked(ctx context.Context, sub string, level AppLevel) error
}

// ChangeMarkers writes the second-step markers (*markers.Writer).
type ChangeMarkers interface {
	BeforePrivilege(ctx context.Context, userID string) error
	AfterRemoval(ctx context.Context, userID string) error
}

// ChangeDesignations is the designations the changes write (*Designations).
type ChangeDesignations interface {
	Designate(ctx context.Context, x Designation) error
	Choose(ctx context.Context, sub string, level Level, value string) error
	Withdraw(ctx context.Context, sub string, level Level) error
	Clear(ctx context.Context, sub string) error
}

// RemovedNames is the removed-name list an email change checks
// (*removednames.Store).
type RemovedNames interface {
	Removed(ctx context.Context, name, email string) (bool, error)
}

// ChangesDeps are a Changes' collaborators. NewChanges refuses a missing
// one.
type ChangesDeps struct {
	Guard        Guard
	Users        ChangeUsers
	Access       LockedGranter
	Sessions     Sessions
	Markers      ChangeMarkers
	Designations ChangeDesignations
	// Facts reads an account's facts for the credential removals.
	Facts   FactsReader
	Revoker SignOutSteps
	Removed RemovedNames
	Held    *Held
	Fresh   *Fresh
	// Lock is the one accounts lock, for the change steps that do not go
	// through the guard.
	Lock sync.Locker
	Log  *slog.Logger
	// StepTimeout bounds each step; it marks work gone far outside normal
	// and decides nothing else.
	StepTimeout time.Duration
}

// Changes builds the account workflows.
type Changes struct {
	d   ChangesDeps
	log *slog.Logger
}

// NewChanges checks d and returns a Changes. It does no I/O.
func NewChanges(d ChangesDeps) (*Changes, error) {
	if d.Guard == nil || d.Users == nil || d.Access == nil || d.Sessions == nil || d.Markers == nil || d.Designations == nil ||
		d.Facts == nil || d.Revoker == nil || d.Removed == nil || d.Held == nil || d.Fresh == nil || d.Lock == nil || d.Log == nil {
		return nil, errors.New("accounts: NewChanges: a collaborator is nil")
	}
	if d.StepTimeout <= 0 {
		return nil, fmt.Errorf("accounts: NewChanges: StepTimeout %v is not positive", d.StepTimeout)
	}
	return &Changes{d: d, log: d.Log.With("component", "accounts")}, nil
}

// Workflows are the account kinds' workflows, one literal per kind.
func (c *Changes) Workflows() []jobs.Workflow {
	rev := c.d.Revoker.Steps
	then := func(first []jobs.WorkflowStep, more ...[]jobs.WorkflowStep) []jobs.WorkflowStep {
		for _, m := range more {
			first = append(first, m...)
		}
		return first
	}
	one := func(s ...jobs.WorkflowStep) []jobs.WorkflowStep { return s }
	return []jobs.Workflow{
		{Kind: KindSetRoles, OnTerminal: c.terminal,
			Steps: then(one(c.step(KindSetRoles, StepChange, c.setRoles)), rev(RoleChange))},
		{Kind: KindGrantAccess, OnTerminal: c.terminal, Steps: one(c.step(KindGrantAccess, StepChange, c.grantAccess))},
		{Kind: KindRevokeAccess, OnTerminal: c.terminal,
			Steps: then(rev(RemoveAccess), one(c.step(KindRevokeAccess, StepWithdraw, c.withdraw(LevelApp))))},
		{Kind: KindSetNetwork, OnTerminal: c.terminal,
			Steps: then(one(c.step(KindSetNetwork, StepChange, c.setNetwork)), rev(NetworkChange))},
		{Kind: KindDisable, OnTerminal: c.terminal, Steps: rev(Disable)},
		{Kind: KindEnable, OnTerminal: c.terminal, Steps: one(c.step(KindEnable, StepChange, c.locked(c.enable)))},
		{Kind: KindDelete, OnTerminal: c.terminal,
			Steps: then(rev(Delete), one(c.step(KindDelete, StepWithdraw, c.withdrawAll)))},
		{Kind: KindDecline, OnTerminal: c.terminal,
			Steps: then(rev(Delete), one(c.step(KindDecline, StepWithdraw, c.withdrawAll)))},
		{Kind: KindUnlock, OnTerminal: c.terminal, Steps: one(c.step(KindUnlock, StepChange, c.locked(c.unlock)))},
		{Kind: KindSignOut, OnTerminal: c.terminal, Steps: rev(SignOut)},
		{Kind: KindSetEmail, OnTerminal: c.terminal, Steps: one(c.step(KindSetEmail, StepChange, c.locked(c.setEmail)))},
		{Kind: KindConfirmEmail, OnTerminal: c.terminal,
			Steps: one(c.step(KindConfirmEmail, StepChange, c.locked(c.confirmEmail)))},
		{Kind: KindSetDisplayName, OnTerminal: c.terminal,
			Steps: one(c.step(KindSetDisplayName, StepChange, c.locked(c.setDisplayName)))},
		{Kind: KindRemoveSecondSteps, OnTerminal: c.terminal,
			Steps: then(one(c.step(KindRemoveSecondSteps, StepAuthorize, c.authorize),
				c.step(KindRemoveSecondSteps, StepChange, c.removeSecondSteps)), rev(SecondStepsRemoved))},
		{Kind: KindRemoveCredential, OnTerminal: c.terminal,
			Steps: then(one(c.step(KindRemoveCredential, StepAuthorize, c.authorize),
				c.step(KindRemoveCredential, StepChange, c.locked(c.removeCredential))), rev(SignOut))},
		{Kind: KindRenameCredential, OnTerminal: c.terminal,
			Steps: one(c.step(KindRenameCredential, StepChange, c.locked(c.renameCredential)))},
	}
}

// terminal drops whatever the job still holds: its value and its fresh
// mark, on success, failure and Recover alike.
func (c *Changes) terminal(_ context.Context, jobID string, _ bool, _ string) {
	c.d.Held.Drop(jobID)
	c.d.Fresh.Drop(jobID)
}

// changeSpec is every account spec's fields, as a step reads them.
type changeSpec struct {
	AccountID    string   `json:"accountId"`
	Role         string   `json:"role"`
	Level        string   `json:"level"`
	Grants       []string `json:"grants"`
	CredentialID string   `json:"credentialId"`
}

// changeDo is one step's work. It returns the outcome to record, and
// jobs.ErrStopWorkflow to end the job there successfully.
type changeDo func(ctx context.Context, sc *jobs.StepCtx, spec changeSpec) (map[string]any, error)

// step is the workflow step running do: it decodes the spec, runs do,
// writes the step's one log line and records the outcome.
func (c *Changes) step(kind, name string, do changeDo) jobs.WorkflowStep {
	return jobs.WorkflowStep{Name: name, Timeout: c.d.StepTimeout, Do: func(sc *jobs.StepCtx) (json.RawMessage, error) {
		var spec changeSpec
		if err := json.Unmarshal(sc.Spec, &spec); err != nil || spec.AccountID == "" {
			return nil, c.failed(sc, kind, name, failStep(name, sentenceSpec, errors.New("the spec names no account")))
		}
		out, err := do(sc.Ctx, sc, spec)
		stop := errors.Is(err, jobs.ErrStopWorkflow)
		if err != nil && !stop {
			return nil, c.failed(sc, kind, name, err)
		}
		b, merr := json.Marshal(out)
		if merr != nil {
			return nil, c.failed(sc, kind, name, failStep(name, sentenceChange, merr))
		}
		jobs.LogStep(c.log, sc, slog.LevelInfo, stepLine(name, out),
			"event", kind+".step", "step", name, "outcome", out["outcome"])
		if stop {
			return b, jobs.ErrStopWorkflow
		}
		return b, nil
	}}
}

// failed logs a step's failure, with no person data, and returns it as a
// *StepError: WARN, or ERROR for a write the identity service did not keep.
func (c *Changes) failed(sc *jobs.StepCtx, kind, name string, err error) error {
	attrs := []any{"event", kind + ".failed", "step", name}
	var ie *idclient.Error
	var ref *authz.Refusal
	switch {
	case errors.As(err, &ie):
		attrs = append(attrs, "status", ie.Status, "kind", fmt.Sprint(ie.Kind))
	case errors.As(err, &ref):
		attrs = append(attrs, "code", ref.Code)
	}
	level := slog.LevelWarn
	if errors.Is(err, ErrNotKept) {
		level = slog.LevelError
	}
	jobs.LogStep(c.log, sc, level, name+": failed", attrs...)
	var se *StepError
	if !errors.As(err, &se) {
		return failStep(name, sentenceChange, err)
	}
	return err
}

// refusal is a step refused by a rule here, its code logged.
func refusal(step, code, sentence string) error {
	return failStep(step, sentence, &authz.Refusal{Code: code, Sentence: sentence})
}

// written is a write's failure: a write the identity service did not keep,
// or any other.
func written(err error) error {
	if errors.Is(err, ErrNotKept) {
		return failStep(StepChange, sentenceNotKept, err)
	}
	return failStep(StepChange, sentenceChange, err)
}

// locked runs do under the one accounts lock.
func (c *Changes) locked(do changeDo) changeDo {
	return func(ctx context.Context, sc *jobs.StepCtx, spec changeSpec) (map[string]any, error) {
		c.d.Lock.Lock()
		defer c.d.Lock.Unlock()
		return do(ctx, sc, spec)
	}
}

// guarded runs ch through the guard, which holds the lock while it decides
// and runs apply. A refusal fails the step with the guard's sentence.
func (c *Changes) guarded(ctx context.Context, sc *jobs.StepCtx, ch authz.RoleChange, apply func(context.Context, authz.Decision) error) error {
	_, err := c.d.Guard.Change(ctx, sc.CreatedBy, ch, apply)
	var se *StepError
	var ref *authz.Refusal
	switch {
	case err == nil:
		return nil
	case errors.As(err, &se):
		return se
	case errors.As(err, &ref):
		return failStep(StepChange, ref.Sentence, err)
	}
	return failStep(StepChange, sentenceCheck, err)
}

// authorize is a fresh-gated kind's first step: the job's fresh mark,
// taken once. A job with none was not submitted at a fresh sign-in's
// callback, and is refused before anything changes (C18, C24).
func (c *Changes) authorize(_ context.Context, sc *jobs.StepCtx, _ changeSpec) (map[string]any, error) {
	if !c.d.Fresh.Take(sc.JobID) {
		return nil, refusal(StepAuthorize, authz.CodeFreshSignIn, sentenceFresh)
	}
	return map[string]any{"outcome": outcomeAllowed}, nil
}

// raise is C23 before a privileged write: the second-step markers
// (F-987-08), then every identity session, online and offline, ended.
func (c *Changes) raise(ctx context.Context, sub string) error {
	if err := c.d.Markers.BeforePrivilege(ctx, sub); err != nil {
		return failStep(StepChange, sentenceMarkers, err)
	}
	if err := c.d.Sessions.EndAll(ctx, sub); err != nil {
		return failStep(StepChange, SentenceSessions, fmt.Errorf("end online sessions: %w", err))
	}
	if _, err := c.d.Sessions.EndOffline(ctx, sub); err != nil {
		return failStep(StepChange, SentenceSessions, fmt.Errorf("end offline sessions: %w", err))
	}
	return nil
}

// designated is a Designate decision's outcome: the sentence that names
// "this person".
func designated(d authz.Decision) map[string]any {
	return map[string]any{"outcome": outcomeDesignated, "sentence": d.Unnamed}
}

// choose records an administrator's choice of level for sub.
func (c *Changes) choose(ctx context.Context, sub string, level Level, value string) error {
	if err := c.d.Designations.Choose(ctx, sub, level, value); err != nil {
		return failStep(StepChange, sentenceDesignation, err)
	}
	return nil
}

// withdrawField withdraws level's pending field for sub, after the level
// was applied or removed.
func (c *Changes) withdrawField(ctx context.Context, sub string, level Level) error {
	if err := c.d.Designations.Withdraw(ctx, sub, level); err != nil {
		return failStep(StepChange, sentenceDesignation, err)
	}
	return nil
}

// setRoles is set_roles' change: through the guard, at a fresh sign-in
// for a raise. A designation records the choice and ends the job. Applied,
// a raise first ends the identity sessions (C23); then the role, the
// confirmed email for an administrator, and the console field withdrawn.
// #991's role_change steps follow.
func (c *Changes) setRoles(ctx context.Context, sc *jobs.StepCtx, spec changeSpec) (map[string]any, error) {
	sub := spec.AccountID
	var out map[string]any
	ch := authz.RoleChange{Target: sub, Op: authz.OpSetRole, Role: spec.Role, Fresh: c.d.Fresh.Take(sc.JobID)}
	err := c.guarded(ctx, sc, ch, func(ctx context.Context, d authz.Decision) error {
		if d.Kind == authz.Designate {
			out = designated(d)
			return c.choose(ctx, sub, LevelConsole, d.Role)
		}
		if d.Raises {
			if err := c.raise(ctx, sub); err != nil {
				return err
			}
		}
		if err := c.d.Users.SetConsoleRole(ctx, sub, spec.Role); err != nil {
			return written(err)
		}
		if spec.Role == string(authz.Admin) {
			if err := c.d.Users.ConfirmEmail(ctx, sub); err != nil && !errors.Is(err, ErrNoEmail) {
				return written(err)
			}
		}
		out = map[string]any{"outcome": outcomeApplied}
		return c.withdrawField(ctx, sub, LevelConsole)
	})
	switch {
	case err != nil:
		return nil, err
	case out["outcome"] == outcomeDesignated:
		return out, jobs.ErrStopWorkflow
	}
	return out, nil
}

// grantAccess is grant_access' change. A designated app administrator who
// holds no app access gets user at once (F-994-09) and admin is recorded.
// Applied, admin first sets the markers, and the grant ends the identity
// sessions on a level change (C10, C23); the app field is withdrawn.
func (c *Changes) grantAccess(ctx context.Context, sc *jobs.StepCtx, spec changeSpec) (map[string]any, error) {
	sub := spec.AccountID
	var out map[string]any
	ch := authz.RoleChange{Target: sub, Op: authz.OpSetAppAccess, AppRole: spec.Level, Fresh: c.d.Fresh.Take(sc.JobID)}
	err := c.guarded(ctx, sc, ch, func(ctx context.Context, d authz.Decision) error {
		if d.Kind == authz.Designate {
			p, err := c.d.Users.Read(ctx, sub)
			if err != nil {
				return failStep(StepChange, sentenceChange, err)
			}
			if p.AppRole == "" {
				if err := c.grant(ctx, sub, AppUser); err != nil {
					return err
				}
			}
			out = designated(d)
			return c.choose(ctx, sub, LevelApp, string(AppAdmin))
		}
		if AppLevel(spec.Level) == AppAdmin {
			if err := c.d.Markers.BeforePrivilege(ctx, sub); err != nil {
				return failStep(StepChange, sentenceMarkers, err)
			}
		}
		if err := c.grant(ctx, sub, AppLevel(spec.Level)); err != nil {
			return err
		}
		out = map[string]any{"outcome": outcomeApplied}
		return c.withdrawField(ctx, sub, LevelApp)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// grant is Access's grant under the lock the guard holds.
func (c *Changes) grant(ctx context.Context, sub string, level AppLevel) error {
	err := c.d.Access.grantLocked(ctx, sub, level)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errEndSessions):
		return failStep(StepChange, SentenceSessions, err)
	}
	return failStep(StepChange, sentenceChange, err)
}

// setNetwork is set_network's change. A designated gear administrator gets
// the requested set without gear-admin, its additions and removals
// applied, and gear-admin is recorded (F-994-03). Applied, a raise first
// ends the identity sessions (C23), and the network field is withdrawn.
// The set is read back. The job ends there unless a grant was removed,
// which #991's network_change steps follow.
func (c *Changes) setNetwork(ctx context.Context, sc *jobs.StepCtx, spec changeSpec) (map[string]any, error) {
	sub := spec.AccountID
	var out map[string]any
	removed := false
	ch := authz.RoleChange{Target: sub, Op: authz.OpSetNetwork, Network: spec.Grants, Fresh: c.d.Fresh.Take(sc.JobID)}
	err := c.guarded(ctx, sc, ch, func(ctx context.Context, d authz.Decision) error {
		p, err := c.d.Users.Read(ctx, sub)
		if err != nil {
			return failStep(StepChange, sentenceChange, err)
		}
		want := slices.Compact(slices.Sorted(slices.Values(spec.Grants)))
		if d.Kind == authz.Designate {
			want = slices.DeleteFunc(want, func(g string) bool { return g == authz.NetworkGearAdmin })
		} else if d.Raises {
			if err := c.raise(ctx, sub); err != nil {
				return err
			}
		}
		removed = slices.ContainsFunc(p.Network, func(g string) bool { return !slices.Contains(want, g) })
		if err := c.d.Users.SetNetwork(ctx, sub, want); err != nil {
			return written(err)
		}
		if d.Kind == authz.Designate {
			out = designated(d)
			return c.choose(ctx, sub, LevelNetwork, authz.NetworkGearAdmin)
		}
		out = map[string]any{"outcome": outcomeApplied}
		return c.withdrawField(ctx, sub, LevelNetwork)
	})
	if err != nil {
		return nil, err
	}
	out["removed"] = removed
	if !removed {
		return out, jobs.ErrStopWorkflow
	}
	return out, nil
}

// withdraw is the step after a change took level away: its pending field
// is withdrawn, so a later grant can't give it.
func (c *Changes) withdraw(level Level) changeDo {
	return func(ctx context.Context, _ *jobs.StepCtx, spec changeSpec) (map[string]any, error) {
		if err := c.d.Designations.Withdraw(ctx, spec.AccountID, level); err != nil {
			return nil, failStep(StepWithdraw, sentenceDesignation, err)
		}
		return map[string]any{"outcome": outcomeWithdrawn}, nil
	}
}

// withdrawAll is the step after a delete or a decline: the whole
// designation goes.
func (c *Changes) withdrawAll(ctx context.Context, _ *jobs.StepCtx, spec changeSpec) (map[string]any, error) {
	if err := c.d.Designations.Clear(ctx, spec.AccountID); err != nil {
		return nil, failStep(StepWithdraw, sentenceDesignation, err)
	}
	return map[string]any{"outcome": outcomeWithdrawn}, nil
}

// enable enables the account and reads it back.
func (c *Changes) enable(ctx context.Context, _ *jobs.StepCtx, spec changeSpec) (map[string]any, error) {
	if err := c.d.Users.SetEnabled(ctx, spec.AccountID, true); err != nil {
		return nil, written(err)
	}
	p, err := c.d.Users.Read(ctx, spec.AccountID)
	switch {
	case err != nil:
		return nil, written(err)
	case !p.Enabled:
		return nil, written(ErrNotKept)
	}
	return map[string]any{"outcome": outcomeChanged}, nil
}

// unlock releases an account attack detection holds (C19).
func (c *Changes) unlock(ctx context.Context, _ *jobs.StepCtx, spec changeSpec) (map[string]any, error) {
	if err := c.d.Users.Unlock(ctx, spec.AccountID); err != nil {
		return nil, written(err)
	}
	return map[string]any{"outcome": outcomeChanged}, nil
}

// heldText takes the job's held value as text. The caller destroys the
// value; the text is never logged, recorded or put in an error.
func (c *Changes) heldText(sc *jobs.StepCtx) (secret.Value, string, error) {
	v, ok := c.d.Held.Take(sc.JobID)
	if !ok {
		return secret.Value{}, "", failStep(StepChange, sentenceValueGone, errors.New("no value is held for the job"))
	}
	return v, string(v.Reveal()), nil
}

// setEmail sets the held address: refused when it is on the removed-name
// list or the list can't be read; set as confirmed for an administrator
// and unconfirmed (rasputin_email cleared) otherwise; read back.
func (c *Changes) setEmail(ctx context.Context, sc *jobs.StepCtx, spec changeSpec) (map[string]any, error) {
	v, addr, err := c.heldText(sc)
	if err != nil {
		return nil, err
	}
	defer v.Destroy()
	listed, err := c.d.Removed.Removed(ctx, "", addr)
	switch {
	case err != nil:
		return nil, failStep(StepChange, sentenceEmailList, err)
	case listed:
		return nil, refusal(StepChange, "removed_email", sentenceEmailListed)
	}
	roles, err := c.d.Users.ConsoleRoles(ctx, spec.AccountID)
	if err != nil {
		return nil, written(err)
	}
	admin := slices.Contains(roles, string(authz.Admin))
	err = c.d.Users.SetEmail(ctx, spec.AccountID, addr, admin)
	switch {
	case errors.Is(err, idclient.ErrConflict):
		return nil, failStep(StepChange, sentenceEmailTaken, err)
	case err != nil:
		return nil, written(err)
	}
	return map[string]any{"outcome": outcomeChanged, "confirmed": admin}, nil
}

// confirmEmail copies the account's email into rasputin_email, the one
// address apps are given.
func (c *Changes) confirmEmail(ctx context.Context, _ *jobs.StepCtx, spec changeSpec) (map[string]any, error) {
	err := c.d.Users.ConfirmEmail(ctx, spec.AccountID)
	switch {
	case errors.Is(err, ErrNoEmail):
		return nil, refusal(StepChange, "no_email", sentenceNoEmail)
	case err != nil:
		return nil, written(err)
	}
	return map[string]any{"outcome": outcomeChanged}, nil
}

// setDisplayName sets the held name.
func (c *Changes) setDisplayName(ctx context.Context, sc *jobs.StepCtx, spec changeSpec) (map[string]any, error) {
	v, name, err := c.heldText(sc)
	if err != nil {
		return nil, err
	}
	defer v.Destroy()
	if err := c.d.Users.SetDisplayName(ctx, spec.AccountID, name); err != nil {
		return nil, written(err)
	}
	return map[string]any{"outcome": outcomeChanged}, nil
}

// removeSecondSteps is remove_second_steps' change, through the guard
// (one's own account and the last administrator refused): every
// privileged level held is designated again first (reason reset, keeping
// the higher), then each authenticator app, passkey and security key is
// deleted, the markers recomputed, and the account demoted. A run that
// stops part way leaves a privileged account locked out, never open.
// #991's second_steps_removed steps follow.
func (c *Changes) removeSecondSteps(ctx context.Context, sc *jobs.StepCtx, spec changeSpec) (map[string]any, error) {
	sub := spec.AccountID
	var out map[string]any
	err := c.guarded(ctx, sc, authz.RoleChange{Target: sub, Op: authz.OpRemoveSecondSteps, Fresh: true}, func(ctx context.Context, _ authz.Decision) error {
		f, err := c.d.Facts.Facts(ctx, sub)
		if err != nil {
			return failStep(StepChange, sentenceCheck, err)
		}
		lv := authz.PrivilegedLevels(f)
		if err := designateLevels(ctx, c.d.Designations, sub, lv); err != nil {
			return failStep(StepChange, sentenceDesignation, err)
		}
		creds, err := c.d.Users.CredentialList(ctx, sub)
		if err != nil {
			return failStep(StepChange, sentenceChange, err)
		}
		n := 0
		for _, cr := range creds {
			if !markers.IsSecondStep(cr.Type) {
				continue
			}
			if err := c.d.Users.DeleteCredential(ctx, sub, cr.ID); err != nil {
				return failStep(StepChange, sentenceChange, err)
			}
			n++
		}
		if err := c.d.Markers.AfterRemoval(ctx, sub); err != nil {
			return failStep(StepChange, sentenceMarkers, err)
		}
		if err := c.demote(ctx, sub, lv); err != nil {
			return err
		}
		out = map[string]any{"outcome": outcomeRemoved, "credentials": n}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// demote takes the privileged levels lv away (demoteLevels).
func (c *Changes) demote(ctx context.Context, sub string, lv authz.Levels) error {
	if err := demoteLevels(ctx, c.d.Users, sub, lv); err != nil {
		return written(err)
	}
	return nil
}
