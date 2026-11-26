package accounts

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// Identity 4.12's definitions and their values (geekdojo/geekdojo-brain#994,
// PR 2; identity-authz.md §3.4): the groups and custom claims an
// administrator defines, and each person's groups and claim values. Each is
// one Job, submitted through the same Requests seam as every account change,
// and its one step runs under the one accounts lock, so a write of a whole
// account here never overlaps another account change.

// The definition kinds.
const (
	KindDefineGroup = "accounts.define_group"
	KindDeleteGroup = "accounts.delete_group"
	KindSetGroups   = "accounts.set_groups"
	KindDefineClaim = "accounts.define_claim"
	KindDeleteClaim = "accounts.delete_claim"
	KindSetClaims   = "accounts.set_claims"
)

// The definition specs. Each carries ids, a definition's own name, its kind
// and its allowed values only; a person's claim values travel beside the
// job in Held, never in its spec.
type (
	// GroupSpec is define_group's: the group's name.
	GroupSpec struct {
		Name string `json:"name"`
	}
	// GroupIDSpec is delete_group's.
	GroupIDSpec struct {
		GroupID string `json:"groupId"`
	}
	// GroupsSpec is set_groups': the account's whole set of groups.
	GroupsSpec struct {
		AccountID string   `json:"accountId"`
		GroupIDs  []string `json:"groupIds"`
	}
	// ClaimSpec is define_claim's. Clients chosen to receive the claim
	// are refused for now (claimDef).
	ClaimSpec struct {
		Name    string   `json:"name"`
		Kind    string   `json:"kind"`
		Values  []string `json:"values,omitempty"`
		Clients []string `json:"clients,omitempty"`
	}
	// ClaimNameSpec is delete_claim's.
	ClaimNameSpec struct {
		Name string `json:"name"`
	}
)

// The definition steps' outcomes and sentences (ERR-MESSAGE).
const (
	outcomeDefined = "defined"
	outcomeExists  = "exists"

	sentenceDefinition   = "Rasputin couldn't change this definition at the sign-in service. Try again."
	sentenceUnknownGroup = "One of the chosen groups doesn't exist, so nothing was changed."
	sentenceUnknownClaim = "One of these claims isn't defined, so nothing was changed."
	sentenceClaimValues  = "The claim values for this change couldn't be read, so nothing was changed."
	sentenceClaimRefused = "A value doesn't fit its claim's kind or allowed values, so nothing was changed."
)

// DefinitionUsers is the identity-service calls the definitions make
// (*Users).
type DefinitionUsers interface {
	Groups(ctx context.Context) ([]Group, error)
	DefineGroup(ctx context.Context, name string) (string, bool, error)
	DeleteGroup(ctx context.Context, id string) error
	SetGroups(ctx context.Context, sub string, want []string) (int, int, error)
	Claims(ctx context.Context) ([]string, error)
	DefineClaim(ctx context.Context, d ClaimDef) error
	DeleteClaim(ctx context.Context, name string) (int, error)
	SetClaims(ctx context.Context, sub string, values map[string][]string) error
}

// defSpec is every definition spec's fields, as a step reads them.
type defSpec struct {
	AccountID string   `json:"accountId"`
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Values    []string `json:"values"`
	Clients   []string `json:"clients"`
	GroupID   string   `json:"groupId"`
	GroupIDs  []string `json:"groupIds"`
}

// defDo is one definition step's work.
type defDo func(ctx context.Context, sc *jobs.StepCtx, users DefinitionUsers, spec defSpec) (map[string]any, error)

// DefinitionWorkflows are the definition kinds' workflows, one literal per
// kind, over users. Each is one change step under the one accounts lock.
func (c *Changes) DefinitionWorkflows(users DefinitionUsers) ([]jobs.Workflow, error) {
	if users == nil {
		return nil, errors.New("accounts: DefinitionWorkflows: a collaborator is nil")
	}
	one := func(kind string, do defDo) []jobs.WorkflowStep {
		return []jobs.WorkflowStep{c.defStep(kind, users, do)}
	}
	return []jobs.Workflow{
		{Kind: KindDefineGroup, OnTerminal: c.terminal, Steps: one(KindDefineGroup, c.defineGroup)},
		{Kind: KindDeleteGroup, OnTerminal: c.terminal, Steps: one(KindDeleteGroup, c.deleteGroup)},
		{Kind: KindSetGroups, OnTerminal: c.terminal, Steps: one(KindSetGroups, c.setGroups)},
		{Kind: KindDefineClaim, OnTerminal: c.terminal, Steps: one(KindDefineClaim, c.defineClaim)},
		{Kind: KindDeleteClaim, OnTerminal: c.terminal, Steps: one(KindDeleteClaim, c.deleteClaim)},
		{Kind: KindSetClaims, OnTerminal: c.terminal, Steps: one(KindSetClaims, c.setClaims)},
	}, nil
}

// defStep is kind's change step: the spec decoded, then do under the one
// accounts lock.
func (c *Changes) defStep(kind string, users DefinitionUsers, do defDo) jobs.WorkflowStep {
	return c.stepOf(kind, StepChange, func(sc *jobs.StepCtx) (map[string]any, error) {
		var spec defSpec
		if err := json.Unmarshal(sc.Spec, &spec); err != nil {
			return nil, failStep(StepChange, sentenceSpec, errors.New("the spec does not decode"))
		}
		c.d.Lock.Lock()
		defer c.d.Lock.Unlock()
		return do(sc.Ctx, sc, users, spec)
	})
}

// definitionWritten is a definition write's failure.
func definitionWritten(err error) error {
	if errors.Is(err, ErrNotKept) {
		return failStep(StepChange, sentenceNotKept, err)
	}
	return failStep(StepChange, sentenceDefinition, err)
}
