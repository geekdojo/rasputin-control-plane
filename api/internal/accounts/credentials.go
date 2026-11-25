package accounts

import (
	"context"
	"errors"
	"slices"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/markers"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// A person's own credentials (geekdojo/geekdojo-brain#994): removing one
// (C18, at a fresh sign-in) and renaming one.

// The credential refusals' sentences (ERR-MESSAGE).
const (
	sentenceNoCredential = "That sign-in method no longer exists."
	sentencePassword     = "Your password can't be removed. Change it instead."
	sentenceKeepCodes    = "An account with a privileged role keeps its recovery codes, so they weren't removed."
	sentenceKeepLast     = "An account with a privileged role keeps at least one passkey, security key or authenticator app, so this one wasn't removed."
)

// typePassword is Keycloak 26.8.2's password credential type.
const typePassword = "password"

// removeCredential removes one of the person's credentials under the lock.
// The password is never removed, nor an unknown id; a privileged account
// (authz.HoldsPrivilege) keeps its recovery codes and its last second step.
// The markers are recomputed from what remains. #991's sign_out steps
// follow, keeping the request's own session.
func (c *Changes) removeCredential(ctx context.Context, _ *jobs.StepCtx, spec changeSpec) (map[string]any, error) {
	sub := spec.AccountID
	f, err := c.d.Facts.Facts(ctx, sub)
	if err != nil {
		return nil, failStep(StepChange, sentenceCheck, err)
	}
	creds, err := c.d.Users.CredentialList(ctx, sub)
	if err != nil {
		return nil, failStep(StepChange, sentenceCheck, err)
	}
	i := slices.IndexFunc(creds, func(cr Credential) bool { return cr.ID == spec.CredentialID })
	if i < 0 {
		return nil, refusal(StepChange, "no_credential", sentenceNoCredential)
	}
	typ := creds[i].Type
	steps := 0
	for _, cr := range creds {
		if markers.IsSecondStep(cr.Type) {
			steps++
		}
	}
	switch {
	case typ == typePassword:
		return nil, refusal(StepChange, "password", sentencePassword)
	case authz.HoldsPrivilege(f) && typ == typeRecoveryCodes:
		return nil, refusal(StepChange, "keep_codes", sentenceKeepCodes)
	case authz.HoldsPrivilege(f) && markers.IsSecondStep(typ) && steps <= 1:
		return nil, refusal(StepChange, "keep_last_second_step", sentenceKeepLast)
	}
	if err := c.d.Users.DeleteCredential(ctx, sub, spec.CredentialID); err != nil {
		return nil, written(err)
	}
	if err := c.d.Markers.AfterRemoval(ctx, sub); err != nil {
		return nil, failStep(StepChange, sentenceMarkers, err)
	}
	return map[string]any{"outcome": outcomeRemoved}, nil
}

// renameCredential gives one of the person's credentials the held label.
func (c *Changes) renameCredential(ctx context.Context, sc *jobs.StepCtx, spec changeSpec) (map[string]any, error) {
	v, ok := c.d.Held.Take(sc.JobID)
	if !ok {
		return nil, failStep(StepChange, sentenceValueGone, errors.New("no value is held for the job"))
	}
	defer v.Destroy()
	err := c.d.Users.RenameCredential(ctx, spec.AccountID, spec.CredentialID, v)
	switch {
	case errors.Is(err, idclient.ErrNotFound):
		return nil, refusal(StepChange, "no_credential", sentenceNoCredential)
	case err != nil:
		return nil, written(err)
	}
	return map[string]any{"outcome": outcomeChanged}, nil
}
