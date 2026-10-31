package apps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
)

// AppSecretDeleter is what the app.delete saga needs of the secrets service:
// deleting one entry, every version and its metadata, on an actor's behalf.
// *secrets.Service satisfies it.
type AppSecretDeleter interface {
	Delete(ctx context.Context, a secrets.Actor, r secrets.Ref) error
}

// SecretStoreState is what the app.delete saga needs to know about the secret
// store before it destroys anything (geekdojo/geekdojo-brain#783, F-783-04):
// whether one is configured at all, and whether it is ready now. main backs it
// with the readiness monitor the deploy gate reads.
type SecretStoreState interface {
	// Configured is false when the cluster has no store: no backend is
	// requested and the switch marker is unset, so every secret the app's
	// compose names was derived and never stored.
	Configured() bool
	// State reads the store's state once.
	State(ctx context.Context) (storestate.State, error)
}

// DeleteSecretsDeps are the secret-store collaborators of every path that
// destroys an app's secrets: the app.delete saga, the release step of
// app.upgrade and app.edit, and node removal (geekdojo/geekdojo-brain#783).
type DeleteSecretsDeps struct {
	Secrets AppSecretDeleter
	Store   SecretStoreState
	Log     *slog.Logger
}

// check refuses a nil field, naming caller, the constructor refusing.
func (d DeleteSecretsDeps) check(caller string) error {
	switch {
	case d.Secrets == nil:
		return fmt.Errorf("apps: %s: DeleteSecretsDeps.Secrets is nil", caller)
	case d.Store == nil:
		return fmt.Errorf("apps: %s: DeleteSecretsDeps.Store is nil", caller)
	case d.Log == nil:
		return fmt.Errorf("apps: %s: DeleteSecretsDeps.Log is nil", caller)
	}
	return nil
}

// storeCheck is what the secret store can do about a set of deletes.
type storeCheck int

const (
	// storeNothingStored: no store is configured and no reference is
	// recorded, so every name was derived on each deploy and never stored.
	storeNothingStored storeCheck = iota
	// storeReady: the store reads Ready.
	storeReady
	// storeUnconfigured: no store is configured, but references are
	// recorded, so entries exist that nothing can delete.
	storeUnconfigured
	// storeNotReady: the store is sealed, unreachable or quiesced, or its
	// state could not be read.
	storeNotReady
)

// checkStoreForDeletes reads whether the store can take deletes for an app's
// (or a node's apps') secrets, of which recordedRefs are recorded. The state
// is read only when a store is configured. Each caller words its own
// sentence (ERR-MESSAGE). A state read that fails is storeNotReady with the
// error.
func checkStoreForDeletes(ctx context.Context, st SecretStoreState, recordedRefs int) (storeCheck, storestate.State, error) {
	if !st.Configured() {
		if recordedRefs > 0 {
			return storeUnconfigured, "", nil
		}
		return storeNothingStored, "", nil
	}
	state, err := st.State(ctx)
	if err != nil {
		return storeNotReady, state, err
	}
	if state != storestate.Ready {
		return storeNotReady, state, nil
	}
	return storeReady, state, nil
}

// destroyAppSecrets deletes every entry refs names, every version and its
// metadata, on actor's behalf. Every ref is tried; it returns the refs that
// failed, each with its cause at the same index.
func destroyAppSecrets(ctx context.Context, d AppSecretDeleter, actor secrets.Actor, refs []SecretRef) (failed []SecretRef, causes []error) {
	for _, r := range refs {
		if err := destroyAppSecret(ctx, d, actor, r.AppID, r.Name); err != nil {
			failed = append(failed, r)
			causes = append(causes, err)
		}
	}
	return failed, causes
}

// refNames is the Name of each ref.
func refNames(refs []SecretRef) []string {
	out := make([]string, len(refs))
	for i, r := range refs {
		out[i] = r.Name
	}
	return out
}

// appRefs is name of app appID as SecretRefs.
func appRefs(appID string, names []string) []SecretRef {
	out := make([]SecretRef, len(names))
	for i, n := range names {
		out[i] = SecretRef{AppID: appID, Name: n}
	}
	return out
}

// causeText joins label i with cause i, for an ERROR record's err field:
// store text and names, never a value.
func causeText(labels []string, causes []error) string {
	parts := make([]string, len(causes))
	for i, c := range causes {
		parts[i] = labels[i] + ": " + c.Error()
	}
	return strings.Join(parts, "; ")
}

// sentenceError is an error whose text is a sentence a person reads as the
// job's error (ERR-MESSAGE); the string type follows storage's and updater's
// sentenceError, which are unexported there.
type sentenceError string

func (e sentenceError) Error() string { return string(e) }

// errRefsUnreadable is the preflight's refusal when the app's references
// cannot be read; the cause follows the sentence.
const errRefsUnreadable sentenceError = "The app's recorded secrets could not be read, so nothing was deleted"

// deleteSecretsPreflight refuses a delete, with or without volumes, whose
// secrets the store cannot take the deletes for, before anything is stopped
// or deleted (F-783-04, F-783-05). The runner never resumes a failed job, and once the row is gone
// the delete cannot be submitted again, so a store that is down is found here
// rather than after the app and its data are gone. The row is not touched.
// A compose the scanner refuses names no secret (F-783-24).
func deleteSecretsPreflight(ctx context.Context, store *Store, st SecretStoreState, app *App) error {
	refs, err := store.SecretRefNames(ctx, app.ID)
	if err != nil {
		return fmt.Errorf("%s: %w", errRefsUnreadable, err)
	}
	if len(secretNames(refs, app.ComposeYAML, app.PreviousComposeYAML)) == 0 {
		return nil
	}
	check, state, err := checkStoreForDeletes(ctx, st, len(refs))
	switch check {
	case storeUnconfigured:
		return sentenceError(fmt.Sprintf("No secret store is configured, so the app's %d stored %s cannot be deleted; nothing was deleted.", len(refs), plural(len(refs), "secret", "secrets")))
	case storeNotReady:
		sentence := "The secret store " + storestate.Clause(state) + ", so the app's secrets could not be deleted; nothing was deleted. Retry when the store is ready."
		if err != nil {
			return fmt.Errorf("%s Reading its state failed: %w", sentence, err)
		}
		return errors.New(sentence)
	}
	// Ready, or no store and no recorded reference: the names were derived
	// on every deploy and never stored, so there is nothing to delete.
	return nil
}

// removeResult is the remove step's result: the secret names the row had,
// which destroy_secrets reads. Names only, never a value.
type removeResult struct {
	AppID       string   `json:"appId"`
	Deleted     string   `json:"deleted"`
	SecretNames []string `json:"secretNames"`
}

// deleteDestroySecrets is the app.delete saga's last step. On every delete,
// with the volumes kept or deleted (F-783-05), every entry the app had is
// deleted, every version and its metadata, on behalf of the operator who
// submitted the job. Every name is tried; any failure fails the job, naming
// the entries still in the store.
func deleteDestroySecrets(d DeleteSecretsDeps) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parseDeleteSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		var removed removeResult
		raw, ok := sc.PriorResults["remove"]
		if !ok {
			return nil, errors.New("the remove step left no result, so the app's secrets are unknown")
		}
		if err := json.Unmarshal(raw, &removed); err != nil {
			return nil, fmt.Errorf("decode the remove step's result: %w", err)
		}
		names := removed.SecretNames
		n := len(names)
		if n == 0 {
			sc.Log("info", "the app had no secrets in the secret store")
			return json.Marshal(map[string]string{"secrets": "none"})
		}
		if !d.Store.Configured() {
			// The preflight refused this delete if any reference was recorded.
			sc.Log("info", fmt.Sprintf("the app's %d %s derived on each deploy and never stored, so there is nothing to delete", n, plural(n, "secret was", "secrets were")))
			return json.Marshal(map[string]string{"secrets": "none-stored"})
		}
		ctx := jobs.ContextWithJobID(sc.Ctx, sc.JobID)
		failedRefs, causes := destroyAppSecrets(ctx, d.Secrets, secrets.OperatorActor(sc.CreatedBy), appRefs(spec.AppID, names))
		if len(failedRefs) > 0 {
			failed := refNames(failedRefs)
			d.Log.LogAttrs(ctx, slog.LevelError, "app secrets not deleted from the secret store",
				slog.String("component", "apps"),
				slog.String("event", "apps.secrets_destroy_failed"),
				slog.String("app_id", spec.AppID),
				slog.String("job_id", sc.JobID),
				slog.String("user", sc.CreatedBy),
				slog.Any("failed", failed),
				slog.String("err", causeText(failed, causes)))
			msg := fmt.Sprintf("The app was removed, but %d of its secrets could not be deleted from the secret store and are still in it: %s.",
				len(failed), strings.Join(failed, ", "))
			sc.Log("error", msg)
			return nil, errors.New(msg)
		}
		sc.Log("info", fmt.Sprintf("deleted the app's %d %s from the secret store, every version", n, plural(n, "secret", "secrets")))
		return json.Marshal(map[string]any{"secrets": "deleted", "count": n})
	}
}

// destroyAppSecret deletes app appID's secret name.
func destroyAppSecret(ctx context.Context, d AppSecretDeleter, actor secrets.Actor, appID, name string) error {
	ref, err := secrets.AppSecret(appID, name)
	if err != nil {
		return err
	}
	return d.Delete(ctx, actor, ref)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
