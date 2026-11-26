package accounts

import (
	"context"
	"regexp"
	"slices"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// The group kinds (identity-authz.md §3.4): flat realm groups an
// administrator defines, and each person's membership of them.

// groupName is a group's name: 1 to 40 letters, digits, spaces, dots,
// dashes or underscores.
var groupName = regexp.MustCompile(`^[A-Za-z0-9 _.-]{1,40}$`)

const (
	sentenceGroupName = "A group name is 1 to 40 letters, digits, spaces, dots, dashes or underscores."
	sentenceNoGroup   = "This request doesn't say which group it acts on, so nothing was changed."
)

// defineGroup creates the group; a name the realm already holds reads that
// group back, with no error.
func (c *Changes) defineGroup(ctx context.Context, _ *jobs.StepCtx, users DefinitionUsers, spec defSpec) (map[string]any, error) {
	if !groupName.MatchString(spec.Name) {
		return nil, refusal(StepChange, "group_name", sentenceGroupName)
	}
	id, existed, err := users.DefineGroup(ctx, spec.Name)
	if err != nil {
		return nil, definitionWritten(err)
	}
	out := map[string]any{"outcome": outcomeDefined, "groupId": id}
	if existed {
		out["outcome"] = outcomeExists
	}
	return out, nil
}

// deleteGroup deletes the group; one already gone counts as deleted.
func (c *Changes) deleteGroup(ctx context.Context, _ *jobs.StepCtx, users DefinitionUsers, spec defSpec) (map[string]any, error) {
	if spec.GroupID == "" {
		return nil, refusal(StepChange, "no_group", sentenceNoGroup)
	}
	if err := users.DeleteGroup(ctx, spec.GroupID); err != nil {
		return nil, definitionWritten(err)
	}
	return map[string]any{"outcome": outcomeRemoved}, nil
}

// setGroups makes the spec's groups the account's: every one must exist,
// and only the difference is applied.
func (c *Changes) setGroups(ctx context.Context, _ *jobs.StepCtx, users DefinitionUsers, spec defSpec) (map[string]any, error) {
	all, err := users.Groups(ctx)
	if err != nil {
		return nil, failStep(StepChange, sentenceCheck, err)
	}
	want := slices.Compact(slices.Sorted(slices.Values(spec.GroupIDs)))
	for _, g := range want {
		if !slices.ContainsFunc(all, func(x Group) bool { return x.ID == g }) {
			return nil, refusal(StepChange, "unknown_group", sentenceUnknownGroup)
		}
	}
	joined, left, err := users.SetGroups(ctx, spec.AccountID, want)
	if err != nil {
		return nil, written(err)
	}
	return map[string]any{"outcome": outcomeChanged, "joined": joined, "left": left}, nil
}
