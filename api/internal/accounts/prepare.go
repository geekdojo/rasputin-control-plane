package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/pwpolicy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The administrator's reset before its job (geekdojo/geekdojo-brain#992):
// Resetter.Check decides the request before anything is held, the sign-in
// holds the password through a fresh sign-in (auth.SignIn.PrepareAction),
// and ResetAction submits the job when the administrator comes back.

// Check's refusals, besides the kind table's *authz.KindRefusal.
var (
	// ErrAccountNotFound is a target no account has.
	ErrAccountNotFound = errors.New("accounts: no such account")
	// ErrIdentityUnavailable is an identity service that did not answer.
	ErrIdentityUnavailable = errors.New("accounts: the identity service did not answer")
	// ErrPasswordCheckUnavailable is a policy check that could not finish:
	// the deny list could not be read.
	ErrPasswordCheckUnavailable = errors.New("accounts: the password could not be checked")
)

// PasswordRefused is a password the policy refuses: Sentence is the rule's.
type PasswordRefused struct{ Rule, Sentence string }

func (e *PasswordRefused) Error() string { return "accounts: the password is refused: " + e.Rule }

// ResetAuthorizer is the kind table (*authz.KindPolicy).
type ResetAuthorizer interface {
	Authorize(ctx context.Context, kind string, spec []byte, by authz.Submitter) error
}

// AccountReader reads an account (*Users).
type AccountReader interface {
	Read(ctx context.Context, sub string) (Person, error)
}

// ResetterDeps are a Resetter's collaborators.
type ResetterDeps struct {
	Authorizer ResetAuthorizer
	Users      AccountReader
	Checker    PasswordChecker
	Log        *slog.Logger
}

// Resetter decides an administrator's reset request.
type Resetter struct {
	d   ResetterDeps
	log *slog.Logger
}

// NewResetter checks d and returns a Resetter. It does no I/O.
func NewResetter(d ResetterDeps) (*Resetter, error) {
	if d.Authorizer == nil || d.Users == nil || d.Checker == nil || d.Log == nil {
		return nil, errors.New("accounts: NewResetter: a collaborator is nil")
	}
	return &Resetter{d: d, log: d.Log.With("component", "accounts")}, nil
}

// Check decides whether by may reset target's password to pw, in order:
// the kind table's dry run on the spec the job will carry (so one's own
// account is refused here, before any fresh sign-in), the account read,
// then the password policy for its name and email. It returns nil, a
// *authz.KindRefusal or an error wrapping authz.ErrCheckFailed from the
// kind table, ErrAccountNotFound, ErrIdentityUnavailable, *PasswordRefused,
// or ErrPasswordCheckUnavailable.
func (rs *Resetter) Check(ctx context.Context, by authz.Submitter, target string, pw secret.Value) error {
	spec, err := json.Marshal(ResetSpec{AccountID: target})
	if err != nil {
		return fmt.Errorf("accounts: encode the reset spec: %w", err)
	}
	if err := rs.d.Authorizer.Authorize(ctx, ResetKind, spec, by); err != nil {
		return err
	}
	p, err := rs.d.Users.Read(ctx, target)
	switch {
	case errors.Is(err, idclient.ErrNotFound):
		return ErrAccountNotFound
	case err != nil:
		return fmt.Errorf("%w: %w", ErrIdentityUnavailable, err)
	}
	ref, err := rs.d.Checker.Check(pw, p.Username, p.Email)
	switch {
	case errors.Is(err, pwpolicy.ErrListUnreadable):
		rs.log.LogAttrs(ctx, slog.LevelError, "The password deny list could not be read, so a password reset was refused.",
			slog.String("event", "pwpolicy.list_unreadable"), slog.String("err", err.Error()))
		return ErrPasswordCheckUnavailable
	case err != nil:
		return fmt.Errorf("%w: %w", ErrPasswordCheckUnavailable, err)
	case ref.Refused():
		return &PasswordRefused{Rule: ref.Rule, Sentence: ref.Sentence}
	}
	return nil
}

// ResetPayload is what the fresh sign-in holds for a reset: the target and
// the password. Destroy destroys the password.
type ResetPayload struct {
	Target   string
	Password secret.Value
}

// Destroy destroys the password.
func (p *ResetPayload) Destroy() { p.Password.Destroy() }

// Submitter submits a person's job with a prepare callback (*jobs.Runner).
type Submitter interface {
	SubmitFor(ctx context.Context, by authz.Submitter, kind string, spec any, prepare func(jobID string) error) (*jobs.Job, error)
}

// ResetAction is accounts.reset_password's fresh-sign-in action: once the
// administrator has signed in again it submits the job, the password held
// beside it under its id, and sends the browser to the job on the Tasks
// page.
type ResetAction struct {
	runner Submitter
	held   *Held
}

// NewResetAction returns the action. It refuses a nil collaborator.
func NewResetAction(runner Submitter, held *Held) (*ResetAction, error) {
	if runner == nil || held == nil {
		return nil, errors.New("accounts: NewResetAction: a collaborator is nil")
	}
	return &ResetAction{runner: runner, held: held}, nil
}

// Run submits the job for p. Held gets its own copy of the password: the
// sign-in destroys the payload once Run returns.
func (a *ResetAction) Run(ctx context.Context, p auth.Principal, payload auth.ActionPayload) (string, error) {
	pl, ok := payload.(*ResetPayload)
	if !ok || pl.Target == "" || pl.Password.Len() == 0 {
		return "", errors.New("accounts: the reset action holds no target or password")
	}
	j, err := a.runner.SubmitFor(ctx, p.Submitter(), ResetKind, ResetSpec{AccountID: pl.Target}, func(jobID string) error {
		a.held.Put(jobID, secret.New(pl.Password.Reveal()))
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("accounts: submit the reset: %w", err)
	}
	return "/tasks?id=" + url.QueryEscape(j.ID), nil
}
