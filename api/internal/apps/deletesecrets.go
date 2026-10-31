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

// DeleteSecretsDeps are the app.delete saga's secret-store collaborators.
type DeleteSecretsDeps struct {
	Secrets AppSecretDeleter
	Store   SecretStoreState
	Log     *slog.Logger
}

func (d DeleteSecretsDeps) check() error {
	switch {
	case d.Secrets == nil:
		return errors.New("apps: DeleteWorkflow: DeleteSecretsDeps.Secrets is nil")
	case d.Store == nil:
		return errors.New("apps: DeleteWorkflow: DeleteSecretsDeps.Store is nil")
	case d.Log == nil:
		return errors.New("apps: DeleteWorkflow: DeleteSecretsDeps.Log is nil")
	}
	return nil
}

// sentenceError is an error whose text is a sentence a person reads as the
// job's error (ERR-MESSAGE); the string type follows storage's and updater's
// sentenceError, which are unexported there.
type sentenceError string

func (e sentenceError) Error() string { return string(e) }

// The preflight's refusals that wrap a cause; the cause follows the sentence.
const (
	errRefsUnreadable sentenceError = "The app's recorded secrets could not be read, so nothing was deleted"
	errScanRefused    sentenceError = "The app's compose could not be scanned for secrets, so nothing was deleted"
)

// deleteSecretsPreflight refuses a delete with volumes whose secrets the store
// cannot take the deletes for, before anything is stopped or deleted
// (F-783-04). The runner never resumes a failed job, and once the row is gone
// the delete cannot be submitted again, so a store that is down is found here
// rather than after the app and its data are gone. The row is not touched.
func deleteSecretsPreflight(ctx context.Context, store *Store, st SecretStoreState, app *App) error {
	refs, err := store.SecretRefNames(ctx, app.ID)
	if err != nil {
		return fmt.Errorf("%s: %w", errRefsUnreadable, err)
	}
	names, err := secretNames(refs, app.ComposeYAML, app.PreviousComposeYAML)
	if err != nil {
		return fmt.Errorf("%s: %w", errScanRefused, err)
	}
	if len(names) == 0 {
		return nil
	}
	if !st.Configured() {
		if len(refs) > 0 {
			return sentenceError(fmt.Sprintf("No secret store is configured, so the app's %d stored %s cannot be deleted; nothing was deleted.", len(refs), plural(len(refs), "secret", "secrets")))
		}
		// With no store and no recorded reference, the names were derived on
		// every deploy and never stored: there is nothing to delete.
		return nil
	}
	state, err := st.State(ctx)
	sentence := "The secret store " + storestate.Clause(state) + ", so the app's secrets could not be deleted; nothing was deleted. Retry when the store is ready."
	if err != nil {
		return fmt.Errorf("%s Reading its state failed: %w", sentence, err)
	}
	if state != storestate.Ready {
		return errors.New(sentence)
	}
	return nil
}

// removeResult is the remove step's result: the secret names the row had,
// which destroy_secrets reads. Names only, never a value.
type removeResult struct {
	AppID       string   `json:"appId"`
	Deleted     string   `json:"deleted"`
	SecretNames []string `json:"secretNames"`
}

// deleteDestroySecrets is the app.delete saga's last step. With the volumes
// kept, the app's store entries are kept too and nothing is called. With the
// volumes deleted, every entry the app had is deleted, every version and its
// metadata, on behalf of the operator who submitted the job. Every name is
// tried; any failure fails the job, naming the entries still in the store.
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
		if len(spec.DeleteVolumes) == 0 {
			sc.Log("info", fmt.Sprintf("the app's %d %s kept in the secret store with its volumes", n, plural(n, "secret is", "secrets are")))
			return json.Marshal(map[string]string{"secrets": "kept"})
		}
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
		actor := secrets.OperatorActor(sc.CreatedBy)
		var failed, causes []string
		for _, name := range names {
			if err := destroyAppSecret(ctx, d.Secrets, actor, spec.AppID, name); err != nil {
				failed = append(failed, name)
				causes = append(causes, name+": "+err.Error())
			}
		}
		if len(failed) > 0 {
			d.Log.LogAttrs(ctx, slog.LevelError, "app secrets not deleted from the secret store",
				slog.String("component", "apps"),
				slog.String("event", "apps.secrets_destroy_failed"),
				slog.String("app_id", spec.AppID),
				slog.String("job_id", sc.JobID),
				slog.String("user", sc.CreatedBy),
				slog.Any("failed", failed),
				slog.String("err", strings.Join(causes, "; ")))
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
