package accounts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"slices"
	"unicode"
	"unicode/utf8"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// Identity 4.12's account changes (geekdojo/geekdojo-brain#994;
// identity-authz.md §9.1): every change to a person's account is one Job of
// one of these kinds, submitted through POST /api/accounts/jobs
// (Requests) or POST /api/jobs, authorized by the kind table, and run
// under the one accounts lock (Changes).

// The account kinds this item registers.
const (
	KindSetRoles          = "accounts.set_roles"
	KindGrantAccess       = "accounts.grant_access"
	KindRevokeAccess      = "accounts.revoke_access"
	KindSetNetwork        = "accounts.set_network"
	KindDisable           = "accounts.disable"
	KindEnable            = "accounts.enable"
	KindDelete            = "accounts.delete"
	KindDecline           = "accounts.decline"
	KindUnlock            = "accounts.unlock"
	KindSignOut           = "accounts.sign_out"
	KindSetEmail          = "accounts.set_email"
	KindConfirmEmail      = "accounts.confirm_email"
	KindSetDisplayName    = "accounts.set_display_name"
	KindRemoveSecondSteps = "accounts.remove_second_steps"
	KindRemoveCredential  = "accounts.remove_credential"
	KindRenameCredential  = "accounts.rename_credential"
)

// FreshKinds are the kinds that run only from a fresh sign-in's callback
// (C18, C24): always for removing second steps or a credential, and for
// the three grants when they raise privilege.
var FreshKinds = []string{KindSetRoles, KindGrantAccess, KindSetNetwork, KindRemoveSecondSteps, KindRemoveCredential}

// The specs. Each carries opaque ids and enums only, never a name, an
// email or a label: a spec is persisted, shown on the Tasks page and
// carried in backups. A value travels beside the job in Held.
type (
	// AccountSpec names the account only.
	AccountSpec struct {
		AccountID string `json:"accountId"`
	}
	// RoleSpec is set_roles': the one console role, "" for none.
	RoleSpec struct {
		AccountID string `json:"accountId"`
		Role      string `json:"role"`
	}
	// AccessSpec is grant_access': user or admin.
	AccessSpec struct {
		AccountID string `json:"accountId"`
		Level     string `json:"level"`
	}
	// NetworkSpec is set_network's: the whole set of grants.
	NetworkSpec struct {
		AccountID string   `json:"accountId"`
		Grants    []string `json:"grants"`
	}
	// SignOutSpec is sign_out's. KeepSID is the request's own session,
	// set by Requests, never by the client.
	SignOutSpec struct {
		AccountID string `json:"accountId"`
		KeepSID   string `json:"keepSid,omitempty"`
	}
	// CredentialSpec is remove_credential's and rename_credential's.
	CredentialSpec struct {
		AccountID    string `json:"accountId"`
		CredentialID string `json:"credentialId"`
		KeepSID      string `json:"keepSid,omitempty"`
	}
)

// requestSpec is a request's spec as the client wrote it, every field a
// pointer so a missing one is told from an empty one.
type requestSpec struct {
	AccountID    *string   `json:"accountId"`
	Role         *string   `json:"role"`
	Level        *string   `json:"level"`
	Grants       *[]string `json:"grants"`
	CredentialID *string   `json:"credentialId"`
	KeepSID      *string   `json:"keepSid"`
}

// valueRule is what a kind's value must be.
type valueRule int

const (
	valueNone valueRule = iota
	valueEmail
	valueText
)

// freshRule is when a kind needs a fresh sign-in.
type freshRule int

const (
	freshNever freshRule = iota
	freshAlways
	freshOnRaise
)

// kindRule is one kind's request rule: the fields its spec takes beside
// accountId (each required), its value, when it needs a fresh sign-in, and
// whether the request's own session is kept.
type kindRule struct {
	fields []string
	value  valueRule
	fresh  freshRule
	keep   bool
	op     authz.Op
	build  func(s requestSpec, keep string) any
}

func account(s requestSpec, _ string) any { return AccountSpec{AccountID: *s.AccountID} }

var requestKinds = map[string]kindRule{
	KindSetRoles: {fields: []string{"role"}, fresh: freshOnRaise, op: authz.OpSetRole,
		build: func(s requestSpec, _ string) any { return RoleSpec{AccountID: *s.AccountID, Role: *s.Role} }},
	KindGrantAccess: {fields: []string{"level"}, fresh: freshOnRaise, op: authz.OpSetAppAccess,
		build: func(s requestSpec, _ string) any { return AccessSpec{AccountID: *s.AccountID, Level: *s.Level} }},
	KindSetNetwork: {fields: []string{"grants"}, fresh: freshOnRaise, op: authz.OpSetNetwork,
		build: func(s requestSpec, _ string) any {
			return NetworkSpec{AccountID: *s.AccountID, Grants: append([]string{}, *s.Grants...)}
		}},
	KindRevokeAccess: {build: account},
	KindDisable:      {build: account},
	KindEnable:       {build: account},
	KindDelete:       {build: account},
	KindDecline:      {build: account},
	KindUnlock:       {build: account},
	KindConfirmEmail: {build: account},
	KindSignOut: {keep: true,
		build: func(s requestSpec, keep string) any { return SignOutSpec{AccountID: *s.AccountID, KeepSID: keep} }},
	KindSetEmail:          {value: valueEmail, build: account},
	KindSetDisplayName:    {value: valueText, build: account},
	KindRemoveSecondSteps: {fresh: freshAlways, build: account},
	KindRemoveCredential: {fields: []string{"credentialId"}, fresh: freshAlways, keep: true,
		build: func(s requestSpec, keep string) any {
			return CredentialSpec{AccountID: *s.AccountID, CredentialID: *s.CredentialID, KeepSID: keep}
		}},
	KindRenameCredential: {fields: []string{"credentialId"}, value: valueText,
		build: func(s requestSpec, _ string) any {
			return CredentialSpec{AccountID: *s.AccountID, CredentialID: *s.CredentialID}
		}},
}

// ErrUnknownRequest is a kind POST /api/accounts/jobs does not take.
var ErrUnknownRequest = errors.New("accounts: not an account change this route takes")

// InvalidRequest is a request whose spec or value is malformed. Cause is a
// fixed word for the log, never the input.
type InvalidRequest struct{ Cause string }

func (e *InvalidRequest) Error() string { return "accounts: invalid request: " + e.Cause }

func invalid(cause string) error { return &InvalidRequest{Cause: cause} }

// RequestInput is one request: its kind, its spec as the client wrote it,
// and its value, when HasValue. Request owns Value from then on.
type RequestInput struct {
	Kind     string
	Spec     json.RawMessage
	Value    secret.Value
	HasValue bool
}

// FreshPayload is what a fresh sign-in holds for a change it must start:
// the kind and the spec Request decided, which the action submits.
type FreshPayload struct {
	Kind string
	Spec any
}

// Destroy is a no-op: a fresh kind carries no value (auth.ActionPayload).
func (*FreshPayload) Destroy() {}

// Answer is Request's answer: the fresh sign-in the change needs, or the
// job it started.
type Answer struct {
	Fresh *FreshPayload
	Job   *jobs.Job
}

// RequestsDeps are a Requests' collaborators. NewRequests refuses a
// missing one.
type RequestsDeps struct {
	// Authorizer is the kind table (*authz.KindPolicy), the dry run.
	Authorizer ResetAuthorizer
	// Runner submits the job (*jobs.Runner).
	Runner Submitter
	Held   *Held
	// Facts reads the target without the lock, to tell whether a grant
	// raises privilege; the job decides again under the lock.
	Facts FactsReader
	Log   *slog.Logger
}

// Requests decides an account change request (geekdojo/geekdojo-brain#994).
type Requests struct {
	d   RequestsDeps
	log *slog.Logger
}

// NewRequests checks d and returns a Requests. It does no I/O.
func NewRequests(d RequestsDeps) (*Requests, error) {
	if d.Authorizer == nil || d.Runner == nil || d.Held == nil || d.Facts == nil || d.Log == nil {
		return nil, errors.New("accounts: NewRequests: a collaborator is nil")
	}
	return &Requests{d: d, log: d.Log.With("component", "accounts")}, nil
}

// Request decides in for by, whose request came from the identity session
// sid, in order: the kind must be one this route takes (ErrUnknownRequest);
// the spec is decoded strictly and the value checked (*InvalidRequest);
// keepSid is the request's own session, on one's own account only; the
// kind table's dry run decides (*authz.KindRefusal, or an error wrapping
// authz.ErrCheckFailed); a change that needs a fresh sign-in answers Fresh
// and submits nothing; anything else is submitted, its value held beside
// the job. Request owns in.Value and destroys it unless it is held.
func (rq *Requests) Request(ctx context.Context, by authz.Submitter, sid string, in RequestInput) (Answer, error) {
	held := false
	defer func() {
		if !held {
			in.Value.Destroy()
		}
	}()
	rule, ok := requestKinds[in.Kind]
	if !ok {
		return Answer{}, ErrUnknownRequest
	}
	raw, err := decodeRequestSpec(in.Spec, rule)
	if err != nil {
		return Answer{}, err
	}
	switch {
	case rule.value == valueNone && in.HasValue:
		return Answer{}, invalid("value_unexpected")
	case rule.value != valueNone && !in.HasValue:
		return Answer{}, invalid("value_missing")
	case rule.value != valueNone:
		if cause := validValue(rule.value, in.Value); cause != "" {
			return Answer{}, invalid(cause)
		}
	}
	keep := ""
	if rule.keep && *raw.AccountID == by.CreatedBy() {
		keep = sid
	}
	spec := rule.build(raw, keep)
	b, err := json.Marshal(spec)
	if err != nil {
		return Answer{}, fmt.Errorf("accounts: encode the spec: %w", err)
	}
	if err := rq.d.Authorizer.Authorize(ctx, in.Kind, b, by); err != nil {
		return Answer{}, err
	}
	if rq.needsFresh(ctx, in.Kind, rule, raw) {
		return Answer{Fresh: &FreshPayload{Kind: in.Kind, Spec: spec}}, nil
	}
	var prepare func(string) error
	if rule.value != valueNone {
		v := in.Value
		prepare = func(jobID string) error {
			rq.d.Held.Put(jobID, v)
			held = true
			return nil
		}
	}
	j, err := rq.d.Runner.SubmitFor(ctx, by, in.Kind, spec, prepare)
	if err != nil {
		return Answer{}, err
	}
	return Answer{Job: j}, nil
}

// needsFresh reports whether the change needs a fresh sign-in: always for
// the kinds that remove a second step or a credential, and for a grant
// that raises privilege on the facts read now, without the lock. A read
// that fails needs one (ERR-CLOSED).
func (rq *Requests) needsFresh(ctx context.Context, kind string, rule kindRule, s requestSpec) bool {
	switch rule.fresh {
	case freshAlways:
		return true
	case freshNever:
		return false
	}
	f, err := rq.d.Facts.Facts(ctx, *s.AccountID)
	if err != nil {
		rq.log.LogAttrs(ctx, slog.LevelWarn, "An account could not be read to decide on a fresh sign-in, so one is asked for.",
			slog.String("event", "accounts.request.facts_unreadable"), slog.String("kind", tableKind(kind)), slog.String("err_kind", errKind(err)))
		return true
	}
	ch := authz.RoleChange{Op: rule.op}
	switch {
	case s.Role != nil:
		ch.Role = *s.Role
	case s.Level != nil:
		ch.AppRole = *s.Level
	case s.Grants != nil:
		ch.Network = *s.Grants
	}
	return authz.RaisesPrivilege(f, ch)
}

// tableKind is the request table's own key equal to kind, "" for none: the
// kind constant a record names, never the requester's text (CodeQL
// go/log-injection, F-994-15).
func tableKind(kind string) string {
	for k := range requestKinds {
		if k == kind {
			return k
		}
	}
	return ""
}

// decodeRequestSpec decodes raw strictly: a JSON object with no unknown
// field, no field the kind does not take, a non-empty accountId and every
// field the kind needs. keepSid is taken and ignored where the kind keeps a
// session: it is Request's to set.
func decodeRequestSpec(raw json.RawMessage, rule kindRule) (requestSpec, error) {
	if t := bytes.TrimSpace(raw); len(t) == 0 || bytes.Equal(t, []byte("null")) {
		return requestSpec{}, invalid("spec_missing")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var s requestSpec
	if err := dec.Decode(&s); err != nil {
		return requestSpec{}, invalid("spec_not_json")
	}
	if dec.More() {
		return requestSpec{}, invalid("spec_not_json")
	}
	present := map[string]bool{"role": s.Role != nil, "level": s.Level != nil, "grants": s.Grants != nil,
		"credentialId": s.CredentialID != nil, "keepSid": s.KeepSID != nil}
	for field, there := range present {
		takes := slices.Contains(rule.fields, field) || field == "keepSid" && rule.keep
		switch {
		case there && !takes:
			return requestSpec{}, invalid("spec_field")
		case !there && slices.Contains(rule.fields, field):
			return requestSpec{}, invalid("spec_field")
		}
	}
	if s.AccountID == nil || *s.AccountID == "" || s.CredentialID != nil && *s.CredentialID == "" {
		return requestSpec{}, invalid("spec_target")
	}
	return s, nil
}

// maxText is the longest display name or credential label, in characters.
const maxText = 255

// validValue checks a value against its rule, and returns the fixed cause
// of a refusal or "". An email must parse back exactly as one bare
// address; a display name or a label is 1 to 255 characters of valid UTF-8
// with no control character.
func validValue(rule valueRule, v secret.Value) string {
	b := v.Reveal()
	switch rule {
	case valueEmail:
		a, err := mail.ParseAddress(string(b))
		if err != nil || a.Name != "" || a.Address != string(b) {
			return "value_email"
		}
	case valueText:
		n := utf8.RuneCount(b)
		if !utf8.Valid(b) || n < 1 || n > maxText || bytes.ContainsFunc(b, unicode.IsControl) {
			return "value_text"
		}
	}
	return ""
}
