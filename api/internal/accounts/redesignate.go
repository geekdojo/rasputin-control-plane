package accounts

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
)

// Re-designation (C29): an account's privileged levels are recorded as its
// designation, reason reset, and then taken away, so
// accounts.grant_designated_role returns them once the account's setup is
// complete again. remove_second_steps (geekdojo/geekdojo-brain#994) and the
// administrator's password reset (geekdojo/geekdojo-brain#992) both do it.

// Designator records a re-designation (*Designations).
type Designator interface {
	Designate(ctx context.Context, x Designation) error
}

// DemoteUsers is the account calls a demotion makes (*Users).
type DemoteUsers interface {
	Read(ctx context.Context, sub string) (Person, error)
	SetConsoleRole(ctx context.Context, sub, role string) error
	SetAppRole(ctx context.Context, sub string, level AppLevel) error
	SetNetwork(ctx context.Context, sub string, grants []string) error
}

// designateLevels records lv as sub's designation, reason reset, keeping
// the higher of each field already recorded. An empty lv records nothing.
func designateLevels(ctx context.Context, des Designator, sub string, lv authz.Levels) error {
	if lv.Empty() {
		return nil
	}
	x := Designation{Sub: sub, ConsoleRole: lv.Console, Reason: ReasonReset}
	if lv.App {
		x.AppRole = AppAdmin
	}
	if lv.Gear {
		x.Network = authz.NetworkGearAdmin
	}
	return des.Designate(ctx, x)
}

// demoteLevels takes the privileged levels lv away: the console role off,
// app admin to user, gear-admin out of the network grants. It stops at the
// first write that fails.
func demoteLevels(ctx context.Context, users DemoteUsers, sub string, lv authz.Levels) error {
	if lv.Console != "" {
		if err := users.SetConsoleRole(ctx, sub, ""); err != nil {
			return err
		}
	}
	if lv.App {
		if err := users.SetAppRole(ctx, sub, AppUser); err != nil {
			return err
		}
	}
	if lv.Gear {
		p, err := users.Read(ctx, sub)
		if err != nil {
			return err
		}
		rest := slices.DeleteFunc(slices.Clone(p.Network), func(g string) bool { return g == authz.NetworkGearAdmin })
		if err := users.SetNetwork(ctx, sub, rest); err != nil {
			return err
		}
	}
	return nil
}

// RedesignatorDeps are a Redesignator's collaborators.
type RedesignatorDeps struct {
	Facts        FactsReader
	Designations Designator
	Users        DemoteUsers
	// Lock is the one accounts lock, held from the facts read to the last
	// demotion write.
	Lock sync.Locker
}

// Redesignator re-designates an account whose password an administrator
// reset (Identity 4.10): it is accounts.reset_password's redesignate step.
type Redesignator struct{ d RedesignatorDeps }

// NewRedesignator checks d and returns a Redesignator. It does no I/O.
func NewRedesignator(d RedesignatorDeps) (*Redesignator, error) {
	if d.Facts == nil || d.Designations == nil || d.Users == nil || d.Lock == nil {
		return nil, errors.New("accounts: NewRedesignator: a collaborator is nil")
	}
	return &Redesignator{d: d}, nil
}

// Redesignate reads sub's privileged levels under the accounts lock,
// records them as its designation, then takes them away, and returns them.
// An account holding none is left alone, with nothing recorded. The
// designation is written before any role is taken, so a run that stops
// part way leaves the levels still held recorded, and running it again
// takes only what is left. The error names the part that failed.
func (r *Redesignator) Redesignate(ctx context.Context, sub string) (authz.Levels, error) {
	r.d.Lock.Lock()
	defer r.d.Lock.Unlock()
	f, err := r.d.Facts.Facts(ctx, sub)
	if err != nil {
		return authz.Levels{}, fmt.Errorf("read the account's facts: %w", err)
	}
	lv := authz.PrivilegedLevels(f)
	if err := designateLevels(ctx, r.d.Designations, sub, lv); err != nil {
		return lv, fmt.Errorf("record the designation: %w", err)
	}
	if err := demoteLevels(ctx, r.d.Users, sub, lv); err != nil {
		return lv, fmt.Errorf("take the roles away: %w", err)
	}
	return lv, nil
}
