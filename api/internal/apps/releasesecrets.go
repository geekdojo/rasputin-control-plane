package apps

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
)

// releaseRetryClause ends a release sentence when every ref it could not
// delete is recorded again, so a later attempt finds it.
const releaseRetryClause = " They are deleted at the app's next compose change or with the app."

// releaseUnusedSecrets is the last step of app.upgrade and app.edit
// (geekdojo/geekdojo-brain#783, F-783-19): it destroys the store entries of
// the secrets the app no longer uses, now that the new compose is up.
// "No longer used" is UnusedSecretRefs: a recorded ref that neither compose
// nor either operator-secret declaration names, so the rollback target keeps
// its secrets.
//
// It deletes the refs before the entries (S15), only once the store reads
// Ready, and records again the ref of every entry it could not delete, on a
// context the step's deadline cannot cancel (F-783-21), so the next compose
// change or the app's delete retries it. An app deleted meanwhile is left to
// its delete job (F-783-26). It never writes the app's status.
func releaseUnusedSecrets(store *Store, d DeleteSecretsDeps, appID specAppID) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		id, err := appID(sc.Spec)
		if err != nil {
			return nil, err
		}
		unused, err := store.UnusedSecretRefs(sc.Ctx, id)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return releaseAppRemoved(sc)
		case err != nil:
			return nil, fmt.Errorf("reading the secrets the app no longer uses: %w", err)
		case len(unused) == 0:
			return json.Marshal(map[string]string{"secrets": "none"})
		}
		n := len(unused)
		check, state, err := checkStoreForDeletes(sc.Ctx, d.Store, n)
		switch check {
		case storeUnconfigured:
			return nil, sentenceError(fmt.Sprintf("The new compose is running, but no secret store is configured, so the %d stored %s the app no longer uses were not deleted: %s.",
				n, plural(n, "secret", "secrets"), strings.Join(unused, ", ")))
		case storeNotReady:
			sentence := fmt.Sprintf("The new compose is running, but the secret store %s, so the %d %s the app no longer uses were not deleted: %s.%s",
				storestate.Clause(state), n, plural(n, "secret", "secrets"), strings.Join(unused, ", "), releaseRetryClause)
			if err != nil {
				return nil, fmt.Errorf("%s Reading its state failed: %w", sentence, err)
			}
			return nil, errors.New(sentence)
		}
		dropped, err := store.DropUnusedSecretRefs(sc.Ctx, id)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return releaseAppRemoved(sc)
		case err != nil:
			return nil, fmt.Errorf("dropping the references of the secrets the app no longer uses: %w", err)
		case len(dropped) == 0:
			return json.Marshal(map[string]string{"secrets": "none"})
		}
		ctx := jobs.ContextWithJobID(sc.Ctx, sc.JobID)
		failedRefs, causes := destroyAppSecrets(ctx, d.Secrets, secrets.OperatorActor(sc.CreatedBy), appRefs(id, dropped))
		if len(failedRefs) == 0 {
			sc.Log("info", fmt.Sprintf("deleted the %d %s the app no longer uses from the secret store, every version: %s",
				len(dropped), plural(len(dropped), "secret", "secrets"), strings.Join(dropped, ", ")))
			return json.Marshal(map[string]any{"secrets": "released", "names": dropped})
		}
		failed := refNames(failedRefs)
		labels := failed
		// Each entry is still in the store, so its record is true again. The
		// step's context may be what failed the delete, so the put-back gets
		// its own (F-783-21).
		pctx, cancel := detachCtx(ctx)
		unrecorded := []string{}
		for _, name := range failed {
			if err := store.RecordSecretRef(pctx, id, name); err != nil {
				unrecorded = append(unrecorded, name)
				labels = append(labels, "put back "+name)
				causes = append(causes, err)
			}
		}
		cancel()
		d.Log.LogAttrs(ctx, slog.LevelError, "unused app secrets not deleted from the secret store",
			slog.String("component", "apps"),
			slog.String("event", "apps.secrets_release_failed"),
			slog.String("app_id", id),
			slog.String("job_id", sc.JobID),
			slog.String("user", sc.CreatedBy),
			slog.Any("failed", failed),
			slog.Any("unrecorded", unrecorded),
			slog.String("err", causeText(labels, causes)))
		msg := fmt.Sprintf("The new compose is running, but %d %s the app no longer uses could not be deleted from the secret store: %s.",
			len(failed), plural(len(failed), "secret", "secrets"), strings.Join(failed, ", "))
		if len(unrecorded) == 0 {
			msg += releaseRetryClause
		}
		sc.Log("error", msg)
		return nil, errors.New(msg)
	}
}

// releaseAppRemoved ends the release of an app whose row is gone: its delete
// job owns its secrets (F-783-26).
func releaseAppRemoved(sc *jobs.StepCtx) (json.RawMessage, error) {
	sc.Log("info", "the app was removed while its compose changed; its delete deletes its secrets")
	return json.Marshal(map[string]string{"secrets": "app-removed"})
}
