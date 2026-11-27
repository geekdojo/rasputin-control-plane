package accounts

import (
	"context"
	"errors"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// accounts.grant_waiting (geekdojo/geekdojo-brain#1004, F-1004-01): an
// administrator's one-action grant of a waiting entry's pre-fill. A waiting
// entry is a moved operator who finished after another became administrator
// (C25); its designation grants nothing by itself, and every other grant to
// it discards the pre-fill (Designations.Choose, F-1004-02).

// codeNotWaiting is the refusal of a grant to an account that holds no
// waiting entry.
const codeNotWaiting = "not_waiting"

// sentenceNotWaiting is its sentence (ERR-MESSAGE).
const sentenceNotWaiting = "This person isn't waiting for access from before the update."

// WaitingDesignations is the designations grant_waiting reads and confirms
// (*Designations).
type WaitingDesignations interface {
	Get(ctx context.Context, sub string) (Designation, bool, error)
	Confirm(ctx context.Context, sub string) error
}

// GrantWaitingWorkflow is accounts.grant_waiting's workflow over des: the
// change step, then #991's role_change steps, as set_roles has.
func (c *Changes) GrantWaitingWorkflow(des WaitingDesignations) (jobs.Workflow, error) {
	if des == nil {
		return jobs.Workflow{}, errors.New("accounts: GrantWaitingWorkflow: designations is nil")
	}
	steps := append([]jobs.WorkflowStep{c.step(KindGrantWaiting, StepChange, c.grantWaiting(des))}, c.d.Revoker.Steps(RoleChange)...)
	return jobs.Workflow{Kind: KindGrantWaiting, OnTerminal: c.terminal, Steps: steps}, nil
}

// waitingRow reads sub's designation and refuses one that is not waiting.
func waitingRow(ctx context.Context, des WaitingDesignations, sub string) (Designation, error) {
	x, found, err := des.Get(ctx, sub)
	switch {
	case err != nil:
		return Designation{}, failStep(StepChange, sentenceDesignation, err)
	case !found || x.Reason != ReasonWaiting:
		return Designation{}, refusal(StepChange, codeNotWaiting, sentenceNotWaiting)
	}
	if err := x.Valid(); err != nil {
		return Designation{}, failStep(StepChange, sentenceDesignation, err)
	}
	return x, nil
}

// grantWaiting is the change: through the guard, as setting the row's
// console role, at a fresh sign-in. The row is read again under the lock
// and must still be the same waiting entry. Applied (a complete account):
// C23's markers and sessions, the console role, the confirmed email for an
// administrator, the app access at the row's level, then the row cleared;
// #991's role_change steps follow. Designated (an incomplete account): the
// row is confirmed, so the designated-role grant gives it once the
// account's setup is complete, and the job ends there.
func (c *Changes) grantWaiting(des WaitingDesignations) changeDo {
	return func(ctx context.Context, sc *jobs.StepCtx, spec changeSpec) (map[string]any, error) {
		sub := spec.AccountID
		row, err := waitingRow(ctx, des, sub)
		if err != nil {
			return nil, err
		}
		var out map[string]any
		ch := authz.RoleChange{Target: sub, Op: authz.OpSetRole, Role: row.ConsoleRole, Fresh: c.d.Fresh.Take(sc.JobID)}
		err = c.guarded(ctx, sc, ch, func(ctx context.Context, d authz.Decision) error {
			now, err := waitingRow(ctx, des, sub)
			if err != nil {
				return err
			}
			if now.ConsoleRole != row.ConsoleRole || now.AppRole != row.AppRole || now.Network != row.Network {
				return refusal(StepChange, codeNotWaiting, sentenceNotWaiting)
			}
			if d.Kind == authz.Designate {
				if err := des.Confirm(ctx, sub); err != nil {
					return failStep(StepChange, sentenceDesignation, err)
				}
				out = designated(d)
				return nil
			}
			return c.applyWaiting(ctx, sub, now, d.Raises)
		})
		switch {
		case err != nil:
			return nil, err
		case out != nil:
			return out, jobs.ErrStopWorkflow
		}
		return map[string]any{"outcome": outcomeApplied}, nil
	}
}

// applyWaiting gives a complete account its waiting row's roles and clears
// the row, under the lock the guard holds.
func (c *Changes) applyWaiting(ctx context.Context, sub string, x Designation, raises bool) error {
	switch {
	case raises:
		if err := c.raise(ctx, sub); err != nil {
			return err
		}
	case x.AppRole == AppAdmin:
		// As grant_access: app admin sets the markers first (F-987-08).
		if err := c.d.Markers.BeforePrivilege(ctx, sub); err != nil {
			return failStep(StepChange, sentenceMarkers, err)
		}
	}
	if x.ConsoleRole != "" {
		if err := c.d.Users.SetConsoleRole(ctx, sub, x.ConsoleRole); err != nil {
			return written(err)
		}
		if x.ConsoleRole == string(authz.Admin) {
			if err := c.d.Users.ConfirmEmail(ctx, sub); err != nil && !errors.Is(err, ErrNoEmail) {
				return written(err)
			}
		}
	}
	if x.AppRole != "" {
		if err := c.grant(ctx, sub, x.AppRole); err != nil {
			return err
		}
	}
	if err := c.d.Designations.Clear(ctx, sub); err != nil {
		return failStep(StepChange, sentenceDesignation, err)
	}
	return nil
}
