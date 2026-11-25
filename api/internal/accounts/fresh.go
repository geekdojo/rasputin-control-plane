package accounts

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sync"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
)

// Fresh is the jobs submitted from a fresh sign-in's callback, by job id
// (C24, geekdojo/geekdojo-brain#994): a fresh-gated account job finds its
// mark in its first step, and one without a mark is refused. It lives in
// memory only, so a restart empties it and such a job is refused. It is
// safe for concurrent use.
type Fresh struct {
	mu sync.Mutex
	m  map[string]bool
}

// NewFresh returns an empty Fresh.
func NewFresh() *Fresh { return &Fresh{m: map[string]bool{}} }

// Mark records that jobID was submitted at a fresh sign-in.
func (f *Fresh) Mark(jobID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[jobID] = true
}

// Take reports whether jobID was marked, and removes the mark: a mark is
// taken once.
func (f *Fresh) Take(jobID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	ok := f.m[jobID]
	delete(f.m, jobID)
	return ok
}

// Drop removes jobID's mark, if it has one.
func (f *Fresh) Drop(jobID string) { f.Take(jobID) }

// size is how many marks are held.
func (f *Fresh) size() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.m)
}

// FreshAction is the fresh-sign-in action of every fresh-gated account
// kind (FreshKinds): once the person has signed in again it submits the
// change Requests decided, marked fresh under its job id, and sends the
// browser to the job on the Tasks page. The sign-in has already checked
// that the same person signed in after the action began.
type FreshAction struct {
	runner Submitter
	fresh  *Fresh
}

// NewFreshAction returns the action. It refuses a nil collaborator.
func NewFreshAction(runner Submitter, fresh *Fresh) (*FreshAction, error) {
	if runner == nil || fresh == nil {
		return nil, errors.New("accounts: NewFreshAction: a collaborator is nil")
	}
	return &FreshAction{runner: runner, fresh: fresh}, nil
}

// Run submits payload's change for p, marked fresh.
func (a *FreshAction) Run(ctx context.Context, p auth.Principal, payload auth.ActionPayload) (string, error) {
	pl, ok := payload.(*FreshPayload)
	if !ok || pl == nil || !slices.Contains(FreshKinds, pl.Kind) || pl.Spec == nil {
		return "", errors.New("accounts: the fresh action holds no account change")
	}
	j, err := a.runner.SubmitFor(ctx, p.Submitter(), pl.Kind, pl.Spec, func(jobID string) error {
		a.fresh.Mark(jobID)
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("accounts: submit the change: %w", err)
	}
	return "/tasks?id=" + url.QueryEscape(j.ID), nil
}
