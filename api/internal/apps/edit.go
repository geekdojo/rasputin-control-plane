package apps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// ComposeStash holds the composes owners submit to replace a custom app's
// compose (geekdojo/geekdojo-brain#410), keyed by the id of the app.edit job
// that installs each one, from before that job runs until it ends.
//
// The compose cannot travel in the job's spec. Specs are persisted and
// rendered on the Tasks page, and a custom compose is unvalidated text that
// can inline secrets. Nor can it go on the app row first: the pull runs
// before the row is written, so that a failed pull leaves the row as it was
// (pull.go). So it is held here, where the pull and persist steps read it by
// their own job id, and the workflow's OnTerminal hook discards it however
// the job ends.
//
// In memory, deliberately. Nothing here needs to outlive the process: an api
// restart fails every in-flight job (jobs.Runner.Recover), so a job that
// could still read a held compose cannot survive a restart either — and a
// compose kept only in memory never reaches the disk outside the app row it
// was submitted for.
type ComposeStash struct {
	mu   sync.Mutex
	held map[string]HeldEdit
}

// HeldEdit is what an owner submitted for one app.edit job: the compose, and
// the web port declared beside it (geekdojo/geekdojo-brain#1089). The port
// travels here rather than in the spec for the same reason the compose does:
// only PUT /api/apps/{id}/compose writes the stash, while any POST /api/jobs
// caller can write a spec.
type HeldEdit struct {
	ComposeYAML string
	// WebPort is the custom app's web port, 1-65535, or 0 when the owner
	// declared none, which leaves the stored port as it is.
	WebPort int
}

func NewComposeStash() *ComposeStash {
	return &ComposeStash{held: make(map[string]HeldEdit)}
}

// Put holds e for jobID. Refuses an empty id and an id already holding one: a
// job id is minted fresh for every job, so a second Put is a bug, and
// replacing a compose a running job may already have pulled would install
// one nobody pulled.
func (s *ComposeStash) Put(jobID string, e HeldEdit) error {
	if jobID == "" {
		return errors.New("apps: compose stash: empty job id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.held[jobID]; ok {
		return fmt.Errorf("apps: compose stash: job %s already holds a compose", jobID)
	}
	s.held[jobID] = e
	return nil
}

// Get returns the edit held for jobID.
func (s *ComposeStash) Get(jobID string) (HeldEdit, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.held[jobID]
	return e, ok
}

// Discard drops the compose held for jobID, if any. Idempotent, as an
// OnTerminal hook must be.
func (s *ComposeStash) Discard(jobID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.held, jobID)
}

// Len is how many composes are held — for tests, and for anyone asking
// whether a job left one behind.
func (s *ComposeStash) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.held)
}

// errEditComposeNotHeld is an app.edit job that finds no compose held for it:
// it was not submitted through PUT /api/apps/{id}/compose (POST /api/jobs can
// name any kind), or the api restarted and the job is somehow still running.
// Either way there is nothing to install, and nothing has been touched.
var errEditComposeNotHeld = errors.New("compose edit not applied: the submitted compose is not held for this job, so there is nothing to install — submit the compose again with PUT /api/apps/{id}/compose")

// EditWorkflow drives app.edit (geekdojo/geekdojo-brain#410): replace a custom
// app's compose with one its owner submitted, and redeploy it in place.
//
//  1. load    — the app and its node, checked as a deploy checks them; a
//     catalog app is refused
//  2. pull    — the submitted compose's images, read from stash; nothing
//     else on the node or the row changes (#411, see pull.go)
//  3. persist — Store.EditCompose writes the submitted compose onto the row,
//     refusing any compose other than the one just pulled
//  4. push    — the deploy saga's push, unchanged
//  5. leaf    — the deploy saga's leaf step
//  6. drop_volumes — delete the volumes the new compose drops that the owner
//     named in deleteVolumes, now that `up` has succeeded (#412)
//  7. release_secrets — destroy the store entries of the secrets neither
//     compose nor either operator-secret declaration names any more
//     (geekdojo/geekdojo-brain#783, releasesecrets.go)
//
// In place is the point, as for the upgrade: the app keeps its ULID, so its
// Compose project (proto.AppProjectName) and named volumes
// (proto.AppVolumeName) keep their names and its data stays with it. The
// agent records the app's anonymous volumes around every `up` (#413), so an
// edit that drops a service or an anonymous mount leaves them findable by a
// later delete with data exactly as an upgrade does.
//
// The ordering, the dropped-volume gate and the failure branches are
// UpgradeWorkflow's, for the same reasons: a failed pull changes nothing, the row is written before the push,
// and a failure after the pull is not reverted — going back is the owner's
// re-apply of the previous compose, by hash (RevertWorkflow).
//
// The compose is not validated, as it is not at custom create (ADR-0006 D12).
// It never appears in the job's spec, a step result or a log line: the steps
// record its hash, and stash holds the text until OnTerminal discards it.
//
// It refuses a nil secrets source or a DeleteSecretsDeps with a nil field,
// returning the zero Workflow.
func EditWorkflow(store *Store, inv *inventory.Store, nc *nats.Conn, rotate LeafRotator, stash *ComposeStash, secrets SecretSource, d DeleteSecretsDeps, identity AppIdentity) (jobs.Workflow, error) {
	const kind = "app.edit"
	if err := requireSecretSource(kind, secrets); err != nil {
		return jobs.Workflow{}, err
	}
	if err := d.check("EditWorkflow"); err != nil {
		return jobs.Workflow{}, err
	}
	return jobs.Workflow{
		Kind: kind,
		Steps: []jobs.WorkflowStep{
			{Name: "load", Timeout: 2 * time.Second, Do: editLoad(store, inv)},
			// Backstops, as in UpgradeWorkflow; the real deadline is the app's
			// own budget, applied inside each step.
			{Name: "pull", Timeout: proto.AppDeployRPCFor(int(proto.AppDeployWorkMax.Seconds())), Do: pullStep(store, inv, nc, "compose edit", composeChangeSpecAppID, composeChangeSpecDeleteVolumes, editPullSource(stash))},
			{Name: "persist", Timeout: 2 * time.Second, Do: editPersist(store, inv, nc, stash)},
			{Name: "push", Timeout: proto.AppDeployRPCFor(int(proto.AppDeployWorkMax.Seconds())), Do: pushStep(store, inv, nc, composeChangeSpecAppID, secrets, identity)},
			{Name: "leaf", Timeout: 15 * time.Second, Do: leafStep(store, inv, nc, rotate, composeChangeSpecAppID)},
			{Name: "drop_volumes", Timeout: 90 * time.Second, Do: dropVolumesStep(store, inv, nc, composeChangeSpecAppID)},
			// Last, so it runs only once the new compose is up. One store call
			// per unused entry; never retried, as destroy_secrets is not: the
			// next compose change or the app's delete is the retry (#783).
			{Name: "release_secrets", Timeout: 60 * time.Second, Do: releaseUnusedSecrets(store, d, composeChangeSpecAppID)},
		},
		// Every terminal path — success, a failed step, and an orphan failed at
		// startup — ends here, so a held compose never outlives its job.
		OnTerminal: func(_ context.Context, jobID string, _ bool, _ string) {
			if stash != nil {
				stash.Discard(jobID)
			}
		},
	}, nil
}

func editLoad(store *Store, inv *inventory.Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		app, err := loadAppFor(sc, store, inv, composeChangeSpecAppID)
		if err != nil {
			return nil, err
		}
		if app.SourceTile != "" {
			return nil, ErrEditCatalogApp
		}
		sc.Log("info", fmt.Sprintf("replacing the compose of %q on %s", app.Name, app.TargetNode))
		return json.Marshal(map[string]string{"appId": app.ID, "targetNode": app.TargetNode})
	}
}

// editPullSource is the compose an edit is about to write: the one held for
// this job, under the app's own budget.
func editPullSource(stash *ComposeStash) pullSource {
	return func(sc *jobs.StepCtx, app *App) (pullTarget, error) {
		if app.SourceTile != "" {
			return pullTarget{}, ErrEditCatalogApp
		}
		held, ok := heldCompose(stash, sc.JobID)
		if !ok {
			return pullTarget{}, errEditComposeNotHeld
		}
		return pullTarget{ComposeYAML: held.ComposeYAML, DeployBudgetSeconds: app.DeployBudgetSeconds}, nil
	}
}

func heldCompose(stash *ComposeStash, jobID string) (HeldEdit, bool) {
	if stash == nil {
		return HeldEdit{}, false
	}
	return stash.Get(jobID)
}

// editPersist writes the held compose onto the app row, if it is the one whose
// images were pulled.
func editPersist(store *Store, inv *inventory.Store, nc *nats.Conn, stash *ComposeStash) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		pulled, err := pulledCompose(sc)
		if err != nil {
			return nil, err
		}
		abandon := func(err error) (json.RawMessage, error) {
			abandonAfterPull(sc, store, nc, pulled, err.Error())
			return nil, err
		}
		app, err := loadAppFor(sc, store, inv, composeChangeSpecAppID)
		if err != nil {
			return abandon(fmt.Errorf("compose edit not applied: %w", err))
		}
		held, ok := heldCompose(stash, sc.JobID)
		if !ok {
			return abandon(errEditComposeNotHeld)
		}
		toHash := ComposeHash(held.ComposeYAML)
		if toHash != pulled.ComposeSHA256 {
			return abandon(fmt.Errorf("compose edit not applied: the compose held for this job is not the one pulled, and nothing on the node was changed: %w", ErrComposeChanged))
		}
		if app.ComposeSHA256 == toHash {
			if held.WebPort != 0 && held.WebPort != app.PublishedPort {
				// A port-only edit (geekdojo/geekdojo-brain#1089): the handler
				// starts a job for the installed compose only when the owner
				// declared a different web port beside it.
				if err := store.SetCustomWebPort(sc.Ctx, app.ID, app.ComposeSHA256, held.WebPort, time.Now().UTC()); err != nil {
					return abandon(editWriteError("set web port", err))
				}
				sc.Log("info", fmt.Sprintf("web port set to %d (was %d)", held.WebPort, app.PublishedPort))
				return json.Marshal(map[string]any{"appId": app.ID, "persisted": true, "composeSha256": toHash, "webPort": held.WebPort})
			}
			// The handler answers a compose that is already installed with a
			// no-op and starts no job, so another job installed it during the
			// pull. Pushing it is still what this job was asked to bring about.
			sc.Log("info", "the row already holds the submitted compose; deploying it")
			return json.Marshal(map[string]any{"appId": app.ID, "persisted": false, "composeSha256": toHash})
		}
		if err := store.EditCompose(sc.Ctx, app.ID, app.ComposeSHA256, held.ComposeYAML, held.WebPort, time.Now().UTC()); err != nil {
			return abandon(editWriteError("persist compose", err))
		}
		sc.Log("info", fmt.Sprintf("compose replaced (%.12s → %.12s)", app.ComposeSHA256, toHash))
		result := map[string]any{
			"appId": app.ID, "persisted": true, "fromComposeSha256": app.ComposeSHA256, "toComposeSha256": toHash,
		}
		if held.WebPort != 0 {
			result["webPort"] = held.WebPort
		}
		return json.Marshal(result)
	}
}

// editWriteError words a failed write of an edit to the app row. what names
// the write, for an error that is neither of the store's refusals.
func editWriteError(what string, err error) error {
	switch {
	case errors.Is(err, ErrComposeChanged):
		return fmt.Errorf("compose edit not applied: the app's compose changed while this edit was starting, and nothing on the node was changed — check the app and submit the compose again: %w", err)
	case errors.Is(err, ErrEditCatalogApp):
		return err
	}
	return fmt.Errorf("compose edit not applied: %s: %w", what, err)
}
