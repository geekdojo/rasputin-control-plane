package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/pwpolicy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/removednames"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// A moved account's first password and email (geekdojo/geekdojo-brain#1005,
// Identity 5.2): the bridge (auth/bridge.go) checks the request, then
// submits accounts.set_first_password under the account's bridge grant,
// with the password and the email held beside the job and never in its
// spec, and waits for the job's terminal hook.

// FirstPasswordKind is the job kind. The kind table admits only a bridge
// grant for its own account.
const FirstPasswordKind = "accounts.set_first_password"

// StepSetFirst is its one step.
const StepSetFirst = "set"

// FirstPasswordSpec is the job's spec: the account's id only.
type FirstPasswordSpec struct {
	AccountID string `json:"accountId"`
}

// The step's and the check's sentences (ERR-MESSAGE).
const (
	sentenceFirstNotHeld    = "The password and email are no longer held. Start again from the sign-in page."
	sentenceFirstSetFailed  = "The sign-in service couldn't set your password. Start again from the sign-in page."
	sentenceFirstCheckUnava = "Rasputin couldn't check your password, so it wasn't set. Try again shortly."
)

// FirstPasswordUsers is the account calls the job and its check make
// (*Users).
type FirstPasswordUsers interface {
	Read(ctx context.Context, sub string) (Person, error)
	Credentials(ctx context.Context, sub string) ([]string, error)
	EmailInUse(ctx context.Context, email string) (bool, error)
	SetEmail(ctx context.Context, sub, addr string, confirmed bool) error
	SetPassword(ctx context.Context, sub string, pw secret.Value) (int, error)
}

// PasswordFacts records that a moved account holds a password, which hides
// the bridge's offer (*move.Store).
type PasswordFacts interface {
	RecordPasswordSet(ctx context.Context, sub string) error
}

// FirstPasswordDeps are a FirstPassword's collaborators. NewFirstPassword
// refuses a missing one.
type FirstPasswordDeps struct {
	Users   FirstPasswordUsers
	Checker PasswordChecker
	Removed RemovedNames
	Facts   PasswordFacts
	Runner  Submitter
	// Passwords and Emails hold the two values beside each job, by job id.
	Passwords, Emails *Held
	// Lock is the one accounts lock, held for the step's writes.
	Lock sync.Locker
	Log  *slog.Logger
	// StepTimeout bounds the step; it marks work gone far outside normal
	// and decides nothing else.
	StepTimeout time.Duration
}

// FirstPassword is the bridge's business service: auth.FirstPassword.
type FirstPassword struct {
	d   FirstPasswordDeps
	log *slog.Logger

	mu      sync.Mutex
	waiters map[string]chan terminal
}

// terminal is a job's outcome as its hook reported it.
type terminal struct {
	ok  bool
	msg string
}

var _ auth.FirstPassword = (*FirstPassword)(nil)

// NewFirstPassword checks d and returns a FirstPassword. It does no I/O.
func NewFirstPassword(d FirstPasswordDeps) (*FirstPassword, error) {
	if d.Users == nil || d.Checker == nil || d.Removed == nil || d.Facts == nil || d.Runner == nil ||
		d.Passwords == nil || d.Emails == nil || d.Lock == nil || d.Log == nil {
		return nil, errors.New("accounts: NewFirstPassword: a collaborator is nil")
	}
	if d.StepTimeout <= 0 {
		return nil, fmt.Errorf("accounts: NewFirstPassword: StepTimeout %v is not positive", d.StepTimeout)
	}
	return &FirstPassword{d: d, log: d.Log.With("component", "accounts"), waiters: map[string]chan terminal{}}, nil
}

// emailText is a held email's text, for the one call that takes a string;
// it is never logged, recorded or put in an error.
func emailText(v secret.Value) string { return string(v.Reveal()) }

// heldCopy is v's own copy, for Held: the caller destroys v.
func heldCopy(v secret.Value) secret.Value { return secret.New(v.Reveal()) }

// HasPassword reports whether the account holds a password, and records
// that fact when it does, so the bridge's offer stops. A fact that can't be
// recorded is logged; the answer stands.
func (f *FirstPassword) HasPassword(ctx context.Context, sub string) (bool, error) {
	creds, err := f.d.Users.Credentials(ctx, sub)
	if err != nil {
		return false, fmt.Errorf("accounts: read the account's credentials: %w", err)
	}
	if !slices.Contains(creds, "password") {
		return false, nil
	}
	if err := f.d.Facts.RecordPasswordSet(ctx, sub); err != nil {
		f.log.LogAttrs(ctx, slog.LevelWarn, "The account holds a password, but that fact could not be recorded; the bridge's offer may show until it is.",
			slog.String("event", "first_password.fact_failed"), slog.String("sub", sub))
	}
	return true, nil
}

// Check decides the request before anything is held, in order: an email on
// the removed-name list; an email another account uses (the account's own
// current email is not "in use", so a retry after a half-failed job keeps
// it, F-1005-03); a password the policy refuses for the account's name and
// that email. A refusal is a *auth.BridgeRefusal; any other error is a
// dependency that did not answer.
func (f *FirstPassword) Check(ctx context.Context, sub string, pw, email secret.Value) error {
	p, err := f.d.Users.Read(ctx, sub)
	if err != nil {
		return fmt.Errorf("accounts: read the account: %w", err)
	}
	addr := emailText(email)
	listed, err := f.d.Removed.Removed(ctx, "", addr)
	switch {
	case err != nil:
		return fmt.Errorf("accounts: read the removed-name list: %w", err)
	case listed:
		return &auth.BridgeRefusal{Code: auth.BridgeCodeEmailListed, Sentence: sentenceEmailListed}
	}
	if own := p.Email != "" && removednames.Normal(p.Email) == removednames.Normal(addr); !own {
		used, err := f.d.Users.EmailInUse(ctx, addr)
		switch {
		case err != nil:
			return fmt.Errorf("accounts: look the email up: %w", err)
		case used:
			return &auth.BridgeRefusal{Code: auth.BridgeCodeEmailTaken, Sentence: sentenceEmailTaken}
		}
	}
	ref, err := f.d.Checker.Check(pw, p.Username, addr)
	switch {
	case err != nil:
		if errors.Is(err, pwpolicy.ErrListUnreadable) {
			f.log.LogAttrs(ctx, slog.LevelError, "The password deny list could not be read, so a first password was refused.",
				slog.String("event", "pwpolicy.list_unreadable"))
		}
		return &auth.BridgeRefusal{Code: auth.BridgeCodePasswordCheckUnavailable, Sentence: sentenceFirstCheckUnava}
	case ref.Refused():
		return &auth.BridgeRefusal{Code: auth.BridgeCodePasswordRefused, Sentence: ref.Sentence}
	}
	return nil
}

// Set submits accounts.set_first_password for sub as by, with pw and email
// held beside the job, and returns once its terminal hook has fired: nil on
// success, a *auth.BridgeRefusal with the job's sentence on failure, or the
// context's error when the request ends first. The caller still owns pw
// and email.
func (f *FirstPassword) Set(ctx context.Context, by authz.Submitter, sub string, pw, email secret.Value) error {
	done := make(chan terminal, 1)
	var id string
	_, err := f.d.Runner.SubmitFor(ctx, by, FirstPasswordKind, FirstPasswordSpec{AccountID: sub}, func(jobID string) error {
		id = jobID
		f.d.Passwords.Put(jobID, heldCopy(pw))
		f.d.Emails.Put(jobID, heldCopy(email))
		f.mu.Lock()
		f.waiters[jobID] = done
		f.mu.Unlock()
		return nil
	})
	if err != nil {
		if id != "" {
			f.drop(id)
		}
		return fmt.Errorf("accounts: submit the first password: %w", err)
	}
	select {
	case out := <-done:
		switch {
		case out.ok:
			return nil
		case out.msg == auth.SentenceHasPassword:
			return &auth.BridgeRefusal{Code: auth.BridgeCodeHasPassword, Sentence: out.msg}
		}
		return &auth.BridgeRefusal{Code: auth.BridgeCodeNotSet, Sentence: out.msg}
	case <-ctx.Done():
		f.mu.Lock()
		delete(f.waiters, id)
		f.mu.Unlock()
		return ctx.Err()
	}
}

// drop destroys what is held for jobID and forgets its waiter.
func (f *FirstPassword) drop(jobID string) {
	f.d.Passwords.Drop(jobID)
	f.d.Emails.Drop(jobID)
	f.mu.Lock()
	delete(f.waiters, jobID)
	f.mu.Unlock()
}

// Workflow is accounts.set_first_password: one step, set. Its terminal hook
// destroys anything still held and wakes Set, on success, failure and
// Recover alike.
func (f *FirstPassword) Workflow() jobs.Workflow {
	return jobs.Workflow{
		Kind:  FirstPasswordKind,
		Steps: []jobs.WorkflowStep{{Name: StepSetFirst, Timeout: f.d.StepTimeout, Do: f.set}},
		OnTerminal: func(_ context.Context, jobID string, success bool, errMsg string) {
			f.d.Passwords.Drop(jobID)
			f.d.Emails.Drop(jobID)
			f.mu.Lock()
			w := f.waiters[jobID]
			delete(f.waiters, jobID)
			f.mu.Unlock()
			if w != nil {
				w <- terminal{ok: success, msg: errMsg}
			}
		},
	}
}

// set takes the held values and, under the accounts lock: refuses an
// account that already has a password, writing nothing; refuses a
// removed-listed email; sets the email unconfirmed (the administrator
// grant confirms it later); sets the password, not temporary; records the
// password fact. A 500 from the password write is re-checked against the
// policy, as the reset's set_temporary does. No attempt is retried.
func (f *FirstPassword) set(sc *jobs.StepCtx) (json.RawMessage, error) {
	pw, okPw := f.d.Passwords.Take(sc.JobID)
	email, okEmail := f.d.Emails.Take(sc.JobID)
	defer pw.Destroy()
	defer email.Destroy()
	fail := func(sentence string, err error, level slog.Level, attrs ...any) error {
		jobs.LogStep(f.log, sc, level, StepSetFirst+": failed", append([]any{"event", "first_password.failed"}, attrs...)...)
		return failStep(StepSetFirst, sentence, err)
	}
	refuse := func(code, sentence string) error {
		jobs.LogStep(f.log, sc, slog.LevelWarn, StepSetFirst+": refused", "event", "first_password.refused", "code", code)
		return refusal(StepSetFirst, code, sentence)
	}
	if !okPw || !okEmail {
		return nil, fail(sentenceFirstNotHeld, errors.New("nothing is held for the job"), slog.LevelWarn, "cause", "not_held")
	}
	var spec FirstPasswordSpec
	if err := json.Unmarshal(sc.Spec, &spec); err != nil || spec.AccountID == "" {
		return nil, fail(sentenceSpec, errors.New("the spec names no account"), slog.LevelWarn, "cause", "spec")
	}
	sub, addr := spec.AccountID, emailText(email)
	f.d.Lock.Lock()
	defer f.d.Lock.Unlock()
	creds, err := f.d.Users.Credentials(sc.Ctx, sub)
	switch {
	case err != nil:
		return nil, fail(sentenceFirstSetFailed, err, slog.LevelError, "cause", "credentials", "kind", errKind(err))
	case slices.Contains(creds, "password"):
		return nil, refuse(auth.BridgeCodeHasPassword, auth.SentenceHasPassword)
	}
	listed, err := f.d.Removed.Removed(sc.Ctx, "", addr)
	switch {
	case err != nil:
		return nil, fail(sentenceEmailList, err, slog.LevelError, "cause", "removed_list")
	case listed:
		return nil, refuse(auth.BridgeCodeEmailListed, sentenceEmailListed)
	}
	if err := f.d.Users.SetEmail(sc.Ctx, sub, addr, false); err != nil {
		if errors.Is(err, idclient.ErrConflict) {
			return nil, refuse(auth.BridgeCodeEmailTaken, sentenceEmailTaken)
		}
		return nil, fail(sentenceFirstSetFailed, err, slog.LevelError, "cause", "email", "kind", errKind(err))
	}
	status, err := f.d.Users.SetPassword(sc.Ctx, sub, pw)
	if err != nil {
		if status == http.StatusInternalServerError {
			if ref, ok := f.policyRefusal(sc.Ctx, sub, pw, addr); ok {
				return nil, refuse(auth.BridgeCodePasswordRefused, ref.Sentence)
			}
		}
		return nil, fail(sentenceFirstSetFailed, err, slog.LevelError, "cause", "password", "status", statusText(status))
	}
	if err := f.d.Facts.RecordPasswordSet(sc.Ctx, sub); err != nil {
		// The fact only hides the bridge's offer; HasPassword records it
		// again at the next attempt, so the step still succeeds.
		jobs.LogStep(f.log, sc, slog.LevelWarn, StepSetFirst+": the password fact was not recorded", "event", "first_password.fact_failed")
	}
	jobs.LogStep(f.log, sc, slog.LevelInfo, StepSetFirst+": set", "event", "first_password.set")
	return json.RawMessage(`{"outcome":"set"}`), nil
}

// policyRefusal re-runs the policy for the account's name and addr, and
// reports the rule the password breaks, if it names one (the reset's
// refusedByPolicy pattern). A read or check that fails reports none.
func (f *FirstPassword) policyRefusal(ctx context.Context, sub string, pw secret.Value, addr string) (pwpolicy.Refusal, bool) {
	p, err := f.d.Users.Read(ctx, sub)
	if err != nil {
		return pwpolicy.Refusal{}, false
	}
	ref, err := f.d.Checker.Check(pw, p.Username, addr)
	if err != nil || !ref.Refused() {
		return pwpolicy.Refusal{}, false
	}
	return ref, true
}
