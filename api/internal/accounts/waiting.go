package accounts

import (
	"context"
	"errors"
	"fmt"
)

// WaitingCap is how many accounts may wait for access before the home door
// refuses another sign-up: a count, never a clock
// (geekdojo/geekdojo-brain#990).
const WaitingCap = 20

// WaitingPeople is the account reads Waiting makes (*Users).
type WaitingPeople interface {
	People(ctx context.Context) ([]Account, error)
	ConsoleRoleHolders(ctx context.Context) (map[string]bool, error)
}

// DesignationLister lists the designations (*Designations).
type DesignationLister interface {
	List(ctx context.Context) ([]Designation, error)
}

// Waiting counts the accounts waiting for access: enabled persons with no
// console role, no app access and no designation. The same count backs the
// home door's sign-up cap (policy.Waiting) and GET /api/accounts/waiting.
type Waiting struct {
	people       WaitingPeople
	designations DesignationLister
}

// NewWaiting returns Waiting over its collaborators.
func NewWaiting(people WaitingPeople, designations DesignationLister) (*Waiting, error) {
	if people == nil || designations == nil {
		return nil, errors.New("accounts: NewWaiting: a collaborator is nil")
	}
	return &Waiting{people: people, designations: designations}, nil
}

// Count is how many accounts are waiting. Any read that fails is an error,
// never a short count.
func (w *Waiting) Count(ctx context.Context) (int, error) {
	all, err := w.people.People(ctx)
	if err != nil {
		return 0, fmt.Errorf("accounts: waiting: %w", err)
	}
	holders, err := w.people.ConsoleRoleHolders(ctx)
	if err != nil {
		return 0, fmt.Errorf("accounts: waiting: %w", err)
	}
	ds, err := w.designations.List(ctx)
	if err != nil {
		return 0, fmt.Errorf("accounts: waiting: %w", err)
	}
	designated := make(map[string]bool, len(ds))
	for _, d := range ds {
		designated[d.Sub] = true
	}
	n := 0
	for _, a := range all {
		if a.Enabled && !holders[a.ID] && a.AppRole == "" && !designated[a.ID] {
			n++
		}
	}
	return n, nil
}

// Full reports whether WaitingCap accounts are waiting (policy.Waiting). An
// error is an error: the door then refuses sign-up (ERR-CLOSED).
func (w *Waiting) Full(ctx context.Context) (bool, error) {
	n, err := w.Count(ctx)
	if err != nil {
		return false, err
	}
	return n >= WaitingCap, nil
}
