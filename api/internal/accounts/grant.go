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
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/markers"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// GrantKind is the designated-role grant (geekdojo/geekdojo-brain#990,
// Identity 4.8): a System job, submitted only by Observer on the fact that a
// designated account's setup is complete (C29), never by a person. Its spec
// is {accountId} and no step reads who submitted it.
const GrantKind = "accounts.grant_designated_role"

// The grant's steps, in order.
const (
	StepCheck     = "check"
	StepGrantRole = "grant"
	StepFinish    = "finish"
)

// The grant's outcomes.
const (
	outcomeNotDesignated = "not_designated"
	outcomeWaiting       = "waiting"
	// outcomeWaitingForAdmin is a waiting designation (C25): it grants
	// nothing until an administrator grants it (accounts.grant_waiting).
	outcomeWaitingForAdmin = "waiting_for_admin"
	outcomeComplete        = "complete"
	outcomeGranted         = "granted"
	outcomeFinished        = "finished"
)

// The grant's failure sentences (ERR-MESSAGE).
const (
	sentenceGrantCheck  = "Rasputin couldn't check this person's designated role, so nothing was changed. It tries again at their next sign-in."
	sentenceGrantRole   = "Rasputin couldn't give this person their designated role. It tries again at their next sign-in."
	sentenceGrantFinish = "Rasputin gave this person their designated role but couldn't finish. It tries again at their next sign-in."
)

// GrantSpec is the grant's spec: the account's id only.
type GrantSpec struct {
	AccountID string `json:"accountId"`
}

// DesignationStore is the designations the grant reads and clears
// (*Designations), and sets waiting for a moved account (C25).
type DesignationStore interface {
	Get(ctx context.Context, sub string) (Designation, bool, error)
	Clear(ctx context.Context, sub string) error
	Wait(ctx context.Context, sub string) error
	WaitMoved(ctx context.Context, except string) error
}

// DesignationReader reads a designation (*Designations): what the Observer
// reads.
type DesignationReader interface {
	Get(ctx context.Context, sub string) (Designation, bool, error)
}

// AdminCounter counts the enabled administrators (RoleAccounts): C25
// reads it before a moved account becomes administrator.
type AdminCounter interface {
	EnabledAdmins(ctx context.Context) (int, error)
}

// FactsReader reads an account's facts (RoleAccounts).
type FactsReader interface {
	Facts(ctx context.Context, sub string) (authz.AccountFacts, error)
}

// MarkerWriter writes the second-step markers before a privileged grant
// (*markers.Writer; F-987-08).
type MarkerWriter interface {
	BeforePrivilege(ctx context.Context, userID string) error
}

// RoleAdder gives an account a console role (*Users).
type RoleAdder interface {
	AddConsoleRole(ctx context.Context, sub, role string) error
}

// AppGranter gives app access (*Access), taking the accounts lock itself.
type AppGranter interface {
	Grant(ctx context.Context, sub string, level AppLevel) error
}

// GrantUsers is the account reads and writes the grant makes besides the
// console role (*Users): the network grants it adds gear-admin to, and the
// confirmed email a console administrator gets (geekdojo/geekdojo-brain#994).
type GrantUsers interface {
	Read(ctx context.Context, sub string) (Person, error)
	SetNetwork(ctx context.Context, sub string, grants []string) error
	ConfirmEmail(ctx context.Context, sub string) error
}

// GranterDeps are a Granter's collaborators. NewGranter refuses a missing
// one.
type GranterDeps struct {
	Designations DesignationStore
	Facts        FactsReader
	Markers      MarkerWriter
	Sessions     Sessions
	Roles        RoleAdder
	Users        GrantUsers
	Access       AppGranter
	Console      ConsoleSessions
	// Admins counts the enabled administrators under the lock (C25).
	Admins AdminCounter
	// Lock is the one accounts lock, held around the console role's grant.
	Lock sync.Locker
	Log  *slog.Logger
	// StepTimeout bounds each step; it marks work gone far outside normal
	// and decides nothing else.
	StepTimeout time.Duration
}

// Granter runs accounts.grant_designated_role.
type Granter struct {
	d   GranterDeps
	log *slog.Logger
}

// NewGranter checks d and returns a Granter. It does no I/O.
func NewGranter(d GranterDeps) (*Granter, error) {
	if d.Designations == nil || d.Facts == nil || d.Markers == nil || d.Sessions == nil || d.Roles == nil ||
		d.Users == nil || d.Access == nil || d.Console == nil || d.Admins == nil || d.Lock == nil || d.Log == nil {
		return nil, errors.New("accounts: NewGranter: a collaborator is nil")
	}
	if d.StepTimeout <= 0 {
		return nil, fmt.Errorf("accounts: NewGranter: StepTimeout %v is not positive", d.StepTimeout)
	}
	return &Granter{d: d, log: d.Log.With("component", "accounts")}, nil
}

// Workflow is the grant: check, grant, finish. A failure stops the job with
// the designation kept, so the next sign-in submits it again (B101).
func (g *Granter) Workflow() jobs.Workflow {
	mk := func(name, sentence string, do func(ctx context.Context, sc *jobs.StepCtx, sub string) (string, error)) jobs.WorkflowStep {
		return jobs.WorkflowStep{Name: name, Timeout: g.d.StepTimeout, Do: g.wrap(name, sentence, do)}
	}
	return jobs.Workflow{Kind: GrantKind, System: true, Steps: []jobs.WorkflowStep{
		mk(StepCheck, sentenceGrantCheck, g.check),
		mk(StepGrantRole, sentenceGrantRole, g.grant),
		mk(StepFinish, sentenceGrantFinish, g.finish),
	}}
}

// wrap decodes the spec, runs do only when the earlier step's outcome
// lets it (grant after a complete check, finish after a grant), records the
// outcome and writes the step's one log line. A failure is logged at WARN
// with the step, and an Admin API error's status and kind, never the
// account.
func (g *Granter) wrap(name, sentence string, do func(ctx context.Context, sc *jobs.StepCtx, sub string) (string, error)) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		var spec GrantSpec
		if err := json.Unmarshal(sc.Spec, &spec); err != nil || spec.AccountID == "" {
			return nil, g.failed(sc, name, failStep(name, sentenceSpec, errors.New("the spec names no account")))
		}
		out := outcomeNotNeeded
		if g.runs(name, sc.PriorResults) {
			var err error
			if out, err = do(sc.Ctx, sc, spec.AccountID); err != nil {
				return nil, g.failed(sc, name, failStep(name, sentence, err))
			}
		}
		jobs.LogStep(g.log, sc, slog.LevelInfo, name+": "+out, "event", "accounts.grant.step", "step", name, "outcome", out)
		b, _ := json.Marshal(map[string]string{"outcome": out})
		return b, nil
	}
}

// runs reports whether step runs given the earlier outcomes.
func (g *Granter) runs(step string, prior map[string]json.RawMessage) bool {
	switch step {
	case StepGrantRole:
		return outcomeOf(prior[StepCheck]) == outcomeComplete
	case StepFinish:
		return outcomeOf(prior[StepGrantRole]) == outcomeGranted
	}
	return true
}

func outcomeOf(raw json.RawMessage) string {
	var o struct {
		Outcome string `json:"outcome"`
	}
	if raw == nil || json.Unmarshal(raw, &o) != nil {
		return ""
	}
	return o.Outcome
}

func (g *Granter) failed(sc *jobs.StepCtx, name string, err error) error {
	attrs := []any{"event", "accounts.grant.failed", "step", name}
	var ie *idclient.Error
	if errors.As(err, &ie) {
		attrs = append(attrs, "status", ie.Status, "kind", fmt.Sprint(ie.Kind))
	}
	jobs.LogStep(g.log, sc, slog.LevelWarn, name+": failed", attrs...)
	return err
}

// designated reads sub's designation and facts: not_designated,
// waiting_for_admin (a waiting designation, C25, which grants nothing),
// waiting (incomplete, C29) or complete.
func (g *Granter) designated(ctx context.Context, sub string) (Designation, string, error) {
	x, found, err := g.d.Designations.Get(ctx, sub)
	switch {
	case err != nil:
		return Designation{}, "", err
	case !found:
		return Designation{}, outcomeNotDesignated, nil
	}
	if err := x.Valid(); err != nil {
		return Designation{}, "", err
	}
	if x.Reason == ReasonWaiting {
		return x, outcomeWaitingForAdmin, nil
	}
	f, err := g.d.Facts.Facts(ctx, sub)
	if err != nil {
		return Designation{}, "", err
	}
	if !authz.DesignationComplete(f) {
		return x, outcomeWaiting, nil
	}
	return x, outcomeComplete, nil
}

// check is step 1: whether sub is designated and its setup is complete.
func (g *Granter) check(ctx context.Context, _ *jobs.StepCtx, sub string) (string, error) {
	_, out, err := g.designated(ctx, sub)
	return out, err
}

// grant is step 2: the second-step markers first (F-987-08; an account with
// no second step is waiting and gets nothing), then under the accounts lock
// the facts read again, the identity sessions ended (C23), the console role
// given (with the confirmed email for an administrator) and gear-admin
// added to the network grants held now (F-994-03), then app access
// (Access.Grant, which takes the lock itself). An empty field grants
// nothing.
func (g *Granter) grant(ctx context.Context, _ *jobs.StepCtx, sub string) (string, error) {
	err := g.d.Markers.BeforePrivilege(ctx, sub)
	switch {
	case errors.Is(err, markers.ErrNoSecondStep):
		return outcomeWaiting, nil
	case err != nil:
		return "", err
	}
	x, out, err := g.lockedRole(ctx, sub)
	if err != nil || out != outcomeComplete {
		return out, err
	}
	if x.AppRole != "" {
		if err := g.d.Access.Grant(ctx, sub, x.AppRole); err != nil {
			return "", err
		}
	}
	return outcomeGranted, nil
}

// lockedRole is the grant under the lock. A moved account (C25) becomes
// administrator only while no enabled administrator exists: then every
// other moved designation is set waiting first. With one, its own
// designation is set waiting and nothing is granted. An unread count fails
// the step with the designation kept.
func (g *Granter) lockedRole(ctx context.Context, sub string) (Designation, string, error) {
	g.d.Lock.Lock()
	defer g.d.Lock.Unlock()
	x, out, err := g.designated(ctx, sub)
	if err != nil || out != outcomeComplete {
		return x, out, err
	}
	if x.Reason == ReasonMoved {
		n, err := g.d.Admins.EnabledAdmins(ctx)
		if err != nil {
			return x, "", fmt.Errorf("count the administrators: %w", err)
		}
		if n > 0 {
			if err := g.d.Designations.Wait(ctx, sub); err != nil {
				return x, "", err
			}
			return x, outcomeWaitingForAdmin, nil
		}
		if err := g.d.Designations.WaitMoved(ctx, sub); err != nil {
			return x, "", err
		}
	}
	if err := g.d.Sessions.EndAll(ctx, sub); err != nil {
		return x, "", fmt.Errorf("end online sessions: %w", err)
	}
	if _, err := g.d.Sessions.EndOffline(ctx, sub); err != nil {
		return x, "", fmt.Errorf("end offline sessions: %w", err)
	}
	if x.ConsoleRole != "" {
		if err := g.d.Roles.AddConsoleRole(ctx, sub, x.ConsoleRole); err != nil {
			return x, "", err
		}
		if x.ConsoleRole == string(authz.Admin) {
			if err := g.d.Users.ConfirmEmail(ctx, sub); err != nil && !errors.Is(err, ErrNoEmail) {
				return x, "", err
			}
		}
	}
	if x.Network != "" {
		p, err := g.d.Users.Read(ctx, sub)
		if err != nil {
			return x, "", err
		}
		if !slices.Contains(p.Network, x.Network) {
			if err := g.d.Users.SetNetwork(ctx, sub, append(slices.Clone(p.Network), x.Network)); err != nil {
				return x, "", err
			}
		}
	}
	return x, outcomeComplete, nil
}

// finish is step 3: the console sessions made before the role end, and the
// designation is cleared.
func (g *Granter) finish(ctx context.Context, _ *jobs.StepCtx, sub string) (string, error) {
	if _, err := g.d.Console.EndBySub(ctx, sub); err != nil {
		return "", err
	}
	if err := g.d.Designations.Clear(ctx, sub); err != nil {
		return "", err
	}
	return outcomeFinished, nil
}

// GrantSubmitter submits a System job (*jobs.Runner).
type GrantSubmitter interface {
	Submit(ctx context.Context, kind string, spec any, createdBy string) (*jobs.Job, error)
}

// ObserverDeps are an Observer's collaborators.
type ObserverDeps struct {
	Designations DesignationReader
	Facts        FactsReader
	Runner       GrantSubmitter
	Log          *slog.Logger
}

// Observer is told of every verified console sign-in (auth.Observer) and
// submits the grant for a designated account whose setup is complete. The
// sign-in is the fact: a grant that failed is submitted again at the
// account's next sign-in (row B101).
type Observer struct {
	d   ObserverDeps
	log *slog.Logger
}

// NewObserver checks d and returns an Observer.
func NewObserver(d ObserverDeps) (*Observer, error) {
	if d.Designations == nil || d.Facts == nil || d.Runner == nil || d.Log == nil {
		return nil, errors.New("accounts: NewObserver: a collaborator is nil")
	}
	return &Observer{d: d, log: d.Log.With("component", "accounts")}, nil
}

// grantSubmitter is the grant's recorded submitter.
const grantSubmitter = "accounts.designation"

var _ events.UserSink = (*Observer)(nil)

// signInEvents are the drained user events after which a designated
// account's setup may be complete: a sign-in at either door, or a second
// step stored.
var signInEvents = []string{"LOGIN", "UPDATE_CREDENTIAL", "UPDATE_TOTP"}

// UserEvent is the Observer as a sink of the sign-in history drain
// (F-994-01): after a sign-in or a stored second step at either door, it
// checks the account as SignedIn does, so an app or gear administrator who
// never opens the console still gets the role. The next drained event tries
// again after any failure.
func (o *Observer) UserEvent(ctx context.Context, e events.UserEvent) {
	if e.Error != "" || !slices.Contains(signInEvents, e.Type) {
		return
	}
	o.SignedIn(ctx, e.UserID)
}

// SignedIn submits the grant when sub is designated, its designation names
// known roles and is not waiting (C25), and its facts are complete. Any read or submit error submits
// nothing and is one WARN record with no account id.
func (o *Observer) SignedIn(ctx context.Context, sub string) {
	if sub == "" {
		return
	}
	warn := func(cause string, err error) {
		o.log.LogAttrs(ctx, slog.LevelWarn, "A designated role could not be checked at sign-in; it is checked again at the next one.",
			slog.String("event", "accounts.designation.check_failed"), slog.String("cause", cause), slog.String("kind", errKind(err)))
	}
	x, found, err := o.d.Designations.Get(ctx, sub)
	switch {
	case err != nil:
		warn("designations", err)
		return
	case !found || x.Reason == ReasonWaiting:
		return
	}
	if err := x.Valid(); err != nil {
		warn("designation", err)
		return
	}
	f, err := o.d.Facts.Facts(ctx, sub)
	if err != nil {
		warn("facts", err)
		return
	}
	if !authz.DesignationComplete(f) {
		return
	}
	if _, err := o.d.Runner.Submit(ctx, GrantKind, GrantSpec{AccountID: sub}, grantSubmitter); err != nil {
		warn("submit", err)
	}
}

// errKind is an error's class for a log record that must not name the
// account: an Admin API error's kind, or "other".
func errKind(err error) string {
	var ie *idclient.Error
	if errors.As(err, &ie) {
		return fmt.Sprint(ie.Kind)
	}
	return "other"
}
