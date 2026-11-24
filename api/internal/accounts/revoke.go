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
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// Kind is the identity.revoke job kind.
const Kind = "identity.revoke"

// RevokeKind is what ending a person's access is for.
type RevokeKind string

// The kinds of revocation (identity-authz.md §4.3; app-sso.md §7).
const (
	// SignOut ends every session and changes nothing else.
	SignOut RevokeKind = "sign_out"
	// Privileged ends the identity sessions before a privileged grant
	// (C23), so a password-only session can't carry the new role.
	Privileged RevokeKind = "privileged"
	// RoleChange follows a console role change, made before these steps.
	RoleChange RevokeKind = "role_change"
	// RemoveAccess takes away app access (C10).
	RemoveAccess RevokeKind = "remove_access"
	// Disable disables the account.
	Disable RevokeKind = "disable"
	// Delete deletes the account.
	Delete RevokeKind = "delete"
)

var revokeKinds = []RevokeKind{SignOut, Privileged, RoleChange, RemoveAccess, Disable, Delete}

// Spec is identity.revoke's spec: ids only, never a name or an email. A
// job spec is persisted, shown on the Tasks page and carried in backups.
type Spec struct {
	AccountID string     `json:"accountId"`
	Kind      RevokeKind `json:"kind"`
	// AccessChanged, on a role_change, says the change also lowered app
	// access, which ends the identity sessions too.
	AccessChanged bool `json:"accessChanged,omitempty"`
}

// The steps, in their fixed order.
const (
	StepAuthorize       = "authorize"
	StepOnlineSessions  = "online_sessions"
	StepOfflineSessions = "offline_sessions"
	StepChange          = "change"
	StepConsoleSessions = "console_sessions"
	StepMovedRows       = "moved_rows"
	StepDevices         = "devices"
	StepApps            = "apps"
	StepNetwork         = "network"
)

// stepKinds is which kinds run each step (plan §1's table). A step a kind
// doesn't run records {"outcome":"not_needed"}.
var stepKinds = map[string][]RevokeKind{
	StepAuthorize:       {Disable, Delete},
	StepOnlineSessions:  {SignOut, Privileged, RoleChange, RemoveAccess, Disable, Delete},
	StepOfflineSessions: {SignOut, Privileged, RoleChange, RemoveAccess, Disable, Delete},
	StepChange:          {RemoveAccess, Disable, Delete},
	StepConsoleSessions: {SignOut, RoleChange, RemoveAccess, Disable, Delete},
	StepMovedRows:       {RoleChange, Disable, Delete},
	StepDevices:         {RemoveAccess, Disable, Delete},
	StepApps:            {SignOut, RemoveAccess, Disable, Delete},
	StepNetwork:         {RemoveAccess, Disable, Delete},
}

// The outcomes a step records.
const (
	outcomeNotNeeded      = "not_needed"
	outcomeAllowed        = "allowed"
	outcomeAlreadyDeleted = "already_deleted"
	outcomeEnded          = "ended"
	outcomeAccessRemoved  = "access_removed"
	outcomeDisabled       = "disabled"
	outcomeDeleted        = "deleted"
	outcomeRemoved        = "removed"
)

// The failure sentences a person reads on the job (ERR-MESSAGE).
const (
	SentenceSessions  = "Rasputin couldn't end this person's sessions, so nothing else was changed. Try again."
	sentenceSpec      = "Rasputin couldn't read this request, so nothing was changed."
	sentenceCheck     = "Rasputin couldn't check this change, so nothing was changed. Try again."
	sentenceChange    = "Rasputin couldn't change this account. Try again."
	sentenceAccess    = "Rasputin couldn't check whether this person had app access, so the account wasn't deleted. Try again."
	sentenceList      = "Rasputin couldn't put this person's name on the removed-name list, so the account wasn't deleted. Try again."
	sentenceConsole   = "Rasputin couldn't end this person's console sessions. Try again."
	sentenceMovedRows = "Rasputin couldn't remove this person's old sign-in records. Try again."
)

// StepError is a step's failure: the sentence a person reads, which the
// runner records as the job's error, and the cause, which names the step.
type StepError struct {
	Step, Sentence string
	Err            error
}

func (e *StepError) Error() string { return e.Sentence }

// Unwrap is the cause.
func (e *StepError) Unwrap() error { return e.Err }

func failStep(step, sentence string, err error) *StepError {
	return &StepError{Step: step, Sentence: sentence, Err: fmt.Errorf("%s: %w", step, err)}
}

// Sessions ends identity sessions (sessions.Ender).
type Sessions interface {
	EndAll(ctx context.Context, sub string) error
	EndOffline(ctx context.Context, sub string) (int, error)
}

// RevokeUsers is the account calls the revoker makes (*Users).
type RevokeUsers interface {
	Read(ctx context.Context, sub string) (Person, error)
	ConsoleRoles(ctx context.Context, sub string) ([]string, error)
	SetEnabled(ctx context.Context, sub string, enabled bool) error
	RemoveAppRole(ctx context.Context, sub string) error
	RemoveOfflineAccess(ctx context.Context, sub string) (bool, error)
	Delete(ctx context.Context, sub string) error
}

// Guard decides disables and deletes under the accounts lock
// (*authz.RoleGuard).
type Guard interface {
	Change(ctx context.Context, actorSub string, ch authz.RoleChange, apply func(context.Context, authz.Decision) error) (authz.Decision, error)
}

// ConsoleSessions ends the api's console sessions (*auth.ConsoleSessions).
type ConsoleSessions interface {
	EndBySub(ctx context.Context, sub string) (int64, error)
}

// MovedRows removes a moved person's pre-update rows (*auth.Store).
type MovedRows interface {
	RemoveMovedRows(ctx context.Context, sub string) (creds, sessions int64, err error)
}

// NameRecorder puts a deleted account's name and email on the removed-name
// list (*removednames.Store).
type NameRecorder interface {
	Record(ctx context.Context, name, email string) error
}

// FactHolder reads the app-access fact (removednames.AccessFacts).
type FactHolder interface {
	Held(ctx context.Context, sub string) (bool, error)
}

// RevokerDeps are a Revoker's collaborators. NewRevoker refuses a missing
// one.
type RevokerDeps struct {
	Sessions Sessions
	Users    RevokeUsers
	Guard    Guard
	// Lock is the one accounts lock, held around remove_access's writes.
	// The guard holds it for a disable or a delete.
	Lock    sync.Locker
	Console ConsoleSessions
	Moved   MovedRows
	Removed NameRecorder
	Facts   FactHolder
	// Devices, Apps and Network are the hooks of Identity 8.2, 7.5 and 9.5.
	Devices, Apps, Network Hook
	Log                    *slog.Logger
	// StepTimeout bounds each step; it marks work gone far outside normal
	// and decides nothing else.
	StepTimeout time.Duration
}

// Revoker runs identity.revoke.
type Revoker struct {
	d   RevokerDeps
	log *slog.Logger
}

// NewRevoker checks d and returns a Revoker. It does no I/O.
func NewRevoker(d RevokerDeps) (*Revoker, error) {
	if d.Sessions == nil || d.Users == nil || d.Guard == nil || d.Lock == nil || d.Console == nil || d.Moved == nil ||
		d.Removed == nil || d.Facts == nil || d.Devices == nil || d.Apps == nil || d.Network == nil || d.Log == nil {
		return nil, errors.New("accounts: NewRevoker: a collaborator is nil")
	}
	if d.StepTimeout <= 0 {
		return nil, fmt.Errorf("accounts: NewRevoker: StepTimeout %v is not positive", d.StepTimeout)
	}
	return &Revoker{d: d, log: d.Log.With("component", "accounts")}, nil
}

// Workflow is identity.revoke: a System job, so no person submits it
// through POST /api/jobs, whose kind comes from its spec.
func (r *Revoker) Workflow() jobs.Workflow {
	return jobs.Workflow{Kind: Kind, System: true, Steps: r.steps("")}
}

// Steps are the same steps for kind, fixed, for Identity 4.12's account
// kinds (geekdojo/geekdojo-brain#994) to put inside their own workflows.
// Their spec carries accountId (and, on a role change, accessChanged).
// The contract:
//
//   - role_change runs after the role write, so the moved_rows step reads
//     the new role; accessChanged turns the identity-session steps on when
//     the change also lowers app access.
//   - disable, delete and remove_access must never run while the caller
//     holds the accounts lock: it is not re-entrant.
func (r *Revoker) Steps(kind RevokeKind) []jobs.WorkflowStep { return r.steps(kind) }

// stepDo is one step's work for sub. It returns the outcome to record.
type stepDo func(ctx context.Context, sc *jobs.StepCtx, spec Spec) (map[string]any, error)

func (r *Revoker) steps(fixed RevokeKind) []jobs.WorkflowStep {
	mk := func(name string, do stepDo) jobs.WorkflowStep {
		return jobs.WorkflowStep{Name: name, Timeout: r.d.StepTimeout, Do: r.wrap(name, fixed, do)}
	}
	return []jobs.WorkflowStep{
		mk(StepAuthorize, r.authorize),
		mk(StepOnlineSessions, r.online),
		mk(StepOfflineSessions, r.offline),
		mk(StepChange, r.change),
		mk(StepConsoleSessions, r.console),
		mk(StepMovedRows, r.movedRows),
		mk(StepDevices, r.hook(StepDevices, r.d.Devices)),
		mk(StepApps, r.hook(StepApps, r.d.Apps)),
		mk(StepNetwork, r.hook(StepNetwork, r.d.Network)),
	}
}

// wrap decodes the spec, records not_needed for a step the kind doesn't
// run, runs do otherwise, and writes the step's one log line.
func (r *Revoker) wrap(name string, fixed RevokeKind, do stepDo) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := decodeSpec(sc.Spec, fixed)
		if err != nil {
			return nil, r.failed(sc, name, failStep(name, sentenceSpec, err))
		}
		out := map[string]any{"outcome": outcomeNotNeeded}
		if needed(name, spec, sc.PriorResults) {
			if out, err = do(sc.Ctx, sc, spec); err != nil {
				return nil, r.failed(sc, name, err)
			}
		}
		b, err := json.Marshal(out)
		if err != nil {
			return nil, r.failed(sc, name, failStep(name, sentenceChange, err))
		}
		jobs.LogStep(r.log, sc, slog.LevelInfo, stepLine(name, out),
			"event", "accounts.revoke.step", "step", name, "outcome", out["outcome"])
		return b, nil
	}
}

// stepLine is the job-log line: the step's name, its outcome and its
// counts, nothing else.
func stepLine(name string, out map[string]any) string {
	line := name + ": " + fmt.Sprint(out["outcome"])
	for _, k := range []string{"sessions", "credentials"} {
		if v, ok := out[k]; ok {
			line += " " + k + "=" + fmt.Sprint(v)
		}
	}
	return line
}

// failed logs a step's failure at WARN with no person data: an Admin API
// error by status and kind, a refusal by its code. It returns err.
func (r *Revoker) failed(sc *jobs.StepCtx, name string, err error) error {
	attrs := []any{"event", "accounts.revoke.failed", "step", name}
	var ie *idclient.Error
	var ref *authz.Refusal
	switch {
	case errors.As(err, &ie):
		attrs = append(attrs, "status", ie.Status, "kind", fmt.Sprint(ie.Kind))
	case errors.As(err, &ref):
		attrs = append(attrs, "code", ref.Code)
	}
	jobs.LogStep(r.log, sc, slog.LevelWarn, name+": failed", attrs...)
	var se *StepError
	if !errors.As(err, &se) {
		return failStep(name, sentenceChange, err)
	}
	return err
}

func decodeSpec(raw json.RawMessage, fixed RevokeKind) (Spec, error) {
	var s Spec
	if err := json.Unmarshal(raw, &s); err != nil {
		return Spec{}, fmt.Errorf("decode the spec: %w", err)
	}
	if fixed != "" {
		s.Kind = fixed
	}
	switch {
	case s.AccountID == "":
		return Spec{}, errors.New("the spec names no account")
	case !slices.Contains(revokeKinds, s.Kind):
		return Spec{}, errors.New("the spec names an unknown kind")
	}
	return s, nil
}

// needed reports whether step runs for spec, given the earlier steps'
// outcomes: the kind's table; on a role change the session steps only when
// app access changed; and after a delete whose account was already gone,
// none of the identity steps.
func needed(step string, spec Spec, prior map[string]json.RawMessage) bool {
	if !slices.Contains(stepKinds[step], spec.Kind) {
		return false
	}
	switch step {
	case StepOnlineSessions, StepOfflineSessions:
		if spec.Kind == RoleChange && !spec.AccessChanged {
			return false
		}
	}
	switch step {
	case StepOnlineSessions, StepOfflineSessions, StepChange:
		return !alreadyDeleted(prior[StepAuthorize])
	}
	return true
}

func alreadyDeleted(raw json.RawMessage) bool {
	var o struct {
		Outcome string `json:"outcome"`
	}
	return raw != nil && json.Unmarshal(raw, &o) == nil && o.Outcome == outcomeAlreadyDeleted
}

func op(kind RevokeKind) authz.Op {
	if kind == Delete {
		return authz.OpDelete
	}
	return authz.OpDisable
}

// guarded runs ch through the guard with apply. A refusal fails the step
// with the guard's sentence, except a delete of an account already gone,
// which reports gone.
func (r *Revoker) guarded(ctx context.Context, sc *jobs.StepCtx, step string, spec Spec, apply func(context.Context, authz.Decision) error) (gone bool, err error) {
	_, err = r.d.Guard.Change(ctx, sc.CreatedBy, authz.RoleChange{Target: spec.AccountID, Op: op(spec.Kind)}, apply)
	var ref *authz.Refusal
	var se *StepError
	switch {
	case err == nil:
		return false, nil
	case errors.As(err, &ref) && spec.Kind == Delete && ref.Code == "no_account":
		return true, nil
	case errors.As(err, &ref):
		return false, failStep(step, ref.Sentence, err)
	case errors.As(err, &se):
		return false, se
	}
	return false, failStep(step, sentenceCheck, err)
}

// authorize is step 1: the guard decides, and nothing is applied, so a
// refused change has ended no session.
func (r *Revoker) authorize(ctx context.Context, sc *jobs.StepCtx, spec Spec) (map[string]any, error) {
	gone, err := r.guarded(ctx, sc, StepAuthorize, spec, func(context.Context, authz.Decision) error { return nil })
	switch {
	case err != nil:
		return nil, err
	case gone:
		return map[string]any{"outcome": outcomeAlreadyDeleted}, nil
	}
	return map[string]any{"outcome": outcomeAllowed}, nil
}

// online is step 2: every online identity session ends, and the account's
// not-before is set.
func (r *Revoker) online(ctx context.Context, _ *jobs.StepCtx, spec Spec) (map[string]any, error) {
	if err := r.d.Sessions.EndAll(ctx, spec.AccountID); err != nil {
		return nil, failStep(StepOnlineSessions, SentenceSessions, fmt.Errorf("end online sessions: %w", err))
	}
	return map[string]any{"outcome": outcomeEnded}, nil
}

// offline is step 3: every offline identity session ends.
func (r *Revoker) offline(ctx context.Context, _ *jobs.StepCtx, spec Spec) (map[string]any, error) {
	n, err := r.d.Sessions.EndOffline(ctx, spec.AccountID)
	if err != nil {
		return nil, failStep(StepOfflineSessions, SentenceSessions, fmt.Errorf("end offline sessions: %w", err))
	}
	return map[string]any{"outcome": outcomeEnded, "sessions": n}, nil
}

// change is step 4: app access removed under the accounts lock, or the
// disable or the delete through the guard, decided a second time.
func (r *Revoker) change(ctx context.Context, sc *jobs.StepCtx, spec Spec) (map[string]any, error) {
	sub := spec.AccountID
	switch spec.Kind {
	case RemoveAccess:
		r.d.Lock.Lock()
		defer r.d.Lock.Unlock()
		if err := r.d.Users.RemoveAppRole(ctx, sub); err != nil {
			return nil, failStep(StepChange, sentenceChange, err)
		}
		if _, err := r.d.Users.RemoveOfflineAccess(ctx, sub); err != nil {
			return nil, failStep(StepChange, sentenceChange, err)
		}
		return map[string]any{"outcome": outcomeAccessRemoved}, nil
	case Disable:
		if _, err := r.guarded(ctx, sc, StepChange, spec, func(ctx context.Context, _ authz.Decision) error {
			return r.d.Users.SetEnabled(ctx, sub, false)
		}); err != nil {
			return nil, err
		}
		return map[string]any{"outcome": outcomeDisabled}, nil
	}
	listed := false
	gone, err := r.guarded(ctx, sc, StepChange, spec, func(ctx context.Context, _ authz.Decision) error {
		var err error
		listed, err = r.deleteAccount(ctx, sub)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case gone:
		return map[string]any{"outcome": outcomeAlreadyDeleted}, nil
	}
	return map[string]any{"outcome": outcomeDeleted, "listed": listed}, nil
}

// deleteAccount deletes sub. An account that ever held app access, by the
// fact or by the attribute it still carries, has its name and email put on
// the removed-name list first; if that fails, nothing is deleted.
func (r *Revoker) deleteAccount(ctx context.Context, sub string) (bool, error) {
	p, err := r.d.Users.Read(ctx, sub)
	if err != nil {
		return false, failStep(StepChange, sentenceChange, err)
	}
	held, err := r.d.Facts.Held(ctx, sub)
	if err != nil {
		return false, failStep(StepChange, sentenceAccess, err)
	}
	held = held || p.AppRole != ""
	if held {
		if err := r.d.Removed.Record(ctx, p.Username, p.Email); err != nil {
			return false, failStep(StepChange, sentenceList, err)
		}
	}
	if err := r.d.Users.Delete(ctx, sub); err != nil {
		return false, failStep(StepChange, sentenceChange, err)
	}
	return held, nil
}

// console is step 5: the api's console sessions end.
func (r *Revoker) console(ctx context.Context, _ *jobs.StepCtx, spec Spec) (map[string]any, error) {
	n, err := r.d.Console.EndBySub(ctx, spec.AccountID)
	if err != nil {
		return nil, failStep(StepConsoleSessions, sentenceConsole, err)
	}
	return map[string]any{"outcome": outcomeEnded, "sessions": n}, nil
}

// movedRows is step 6 (C15): a moved person's pre-update credentials and
// sessions rows go. On a role change, only once the person no longer holds
// admin.
func (r *Revoker) movedRows(ctx context.Context, _ *jobs.StepCtx, spec Spec) (map[string]any, error) {
	if spec.Kind == RoleChange {
		roles, err := r.d.Users.ConsoleRoles(ctx, spec.AccountID)
		if err != nil {
			return nil, failStep(StepMovedRows, sentenceMovedRows, err)
		}
		if slices.Contains(roles, string(authz.Admin)) {
			return map[string]any{"outcome": outcomeNotNeeded}, nil
		}
	}
	creds, sessions, err := r.d.Moved.RemoveMovedRows(ctx, spec.AccountID)
	if err != nil {
		return nil, failStep(StepMovedRows, sentenceMovedRows, err)
	}
	return map[string]any{"outcome": outcomeRemoved, "credentials": creds, "sessions": sessions}, nil
}

// hookSentence is a hook step's failure sentence.
var hookSentence = map[string]string{
	StepDevices: "Rasputin couldn't end this person's private-network device access. Try again.",
	StepApps:    "Rasputin couldn't end this person's app sessions. Try again.",
	StepNetwork: "Rasputin couldn't end this person's network access. Try again.",
}

// hook is steps 7 to 9: the hook's outcome, one result per target. Only an
// error fails the step.
func (r *Revoker) hook(step string, h Hook) stepDo {
	return func(ctx context.Context, _ *jobs.StepCtx, spec Spec) (map[string]any, error) {
		out, err := h.Revoke(ctx, spec.AccountID, spec.Kind)
		if err != nil {
			return nil, failStep(step, hookSentence[step], err)
		}
		m := map[string]any{"outcome": out.Outcome}
		if out.What != "" {
			m["what"] = out.What
		}
		if len(out.Targets) > 0 {
			m["targets"] = out.Targets
		}
		return m, nil
	}
}
