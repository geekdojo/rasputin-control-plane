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
	held map[string]string
}

func NewComposeStash() *ComposeStash {
	return &ComposeStash{held: make(map[string]string)}
}

// Put holds compose for jobID. Refuses an empty id and an id already holding
// one: a job id is minted fresh for every job, so a second Put is a bug, and
// replacing a compose a running job may already have pulled would install
// one nobody pulled.
func (s *ComposeStash) Put(jobID, compose string) error {
	if jobID == "" {
		return errors.New("apps: compose stash: empty job id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.held[jobID]; ok {
		return fmt.Errorf("apps: compose stash: job %s already holds a compose", jobID)
	}
	s.held[jobID] = compose
	return nil
}

// Get returns the compose held for jobID.
func (s *ComposeStash) Get(jobID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.held[jobID]
	return c, ok
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
//
// In place is the point, as for the upgrade: the app keeps its ULID, so its
// Compose project (proto.AppProjectName) and named volumes
// (proto.AppVolumeName) keep their names and its data stays with it. The
// agent records the app's anonymous volumes around every `up` (#413), so an
// edit that drops a service or an anonymous mount leaves them findable by a
// later delete with data exactly as an upgrade does.
//
// The ordering and failure branches are UpgradeWorkflow's, for the same
// reasons: a failed pull changes nothing, the row is written before the push,
// and a failure after the pull is not reverted — going back is the owner's
// re-apply of the previous compose, by hash (RevertWorkflow).
//
// The compose is not validated, as it is not at custom create (ADR-0006 D12).
// It never appears in the job's spec, a step result or a log line: the steps
// record its hash, and stash holds the text until OnTerminal discards it.
func EditWorkflow(store *Store, inv *inventory.Store, nc *nats.Conn, mint LeafMinter, stash *ComposeStash) jobs.Workflow {
	return jobs.Workflow{
		Kind: "app.edit",
		Steps: []jobs.WorkflowStep{
			{Name: "load", Timeout: 2 * time.Second, Do: editLoad(store, inv)},
			// Backstops, as in UpgradeWorkflow; the real deadline is the app's
			// own budget, applied inside each step.
			{Name: "pull", Timeout: proto.AppDeployRPCFor(int(proto.AppDeployWorkMax.Seconds())), Do: pullStep(store, inv, nc, "compose edit", deploySpecAppID, editPullSource(stash))},
			{Name: "persist", Timeout: 2 * time.Second, Do: editPersist(store, inv, nc, stash)},
			{Name: "push", Timeout: proto.AppDeployRPCFor(int(proto.AppDeployWorkMax.Seconds())), Do: deployPush(store, inv, nc)},
			{Name: "leaf", Timeout: 15 * time.Second, Do: deployLeaf(store, inv, nc, mint)},
		},
		// Every terminal path — success, a failed step, and an orphan failed at
		// startup — ends here, so a held compose never outlives its job.
		OnTerminal: func(_ context.Context, jobID string, _ bool, _ string) {
			if stash != nil {
				stash.Discard(jobID)
			}
		},
	}
}

func editLoad(store *Store, inv *inventory.Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		app, err := loadApp(sc, store, inv)
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
		compose, ok := heldCompose(stash, sc.JobID)
		if !ok {
			return pullTarget{}, errEditComposeNotHeld
		}
		return pullTarget{ComposeYAML: compose, DeployBudgetSeconds: app.DeployBudgetSeconds}, nil
	}
}

func heldCompose(stash *ComposeStash, jobID string) (string, bool) {
	if stash == nil {
		return "", false
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
		app, err := loadApp(sc, store, inv)
		if err != nil {
			return abandon(fmt.Errorf("compose edit not applied: %w", err))
		}
		compose, ok := heldCompose(stash, sc.JobID)
		if !ok {
			return abandon(errEditComposeNotHeld)
		}
		toHash := ComposeHash(compose)
		if toHash != pulled.ComposeSHA256 {
			return abandon(fmt.Errorf("compose edit not applied: the compose held for this job is not the one pulled, and nothing on the node was changed: %w", ErrComposeChanged))
		}
		if app.ComposeSHA256 == toHash {
			// The handler answers a compose that is already installed with a
			// no-op and starts no job, so another job installed it during the
			// pull. Pushing it is still what this job was asked to bring about.
			sc.Log("info", "the row already holds the submitted compose; deploying it")
			return json.Marshal(map[string]any{"appId": app.ID, "persisted": false, "composeSha256": toHash})
		}
		if err := store.EditCompose(sc.Ctx, app.ID, app.ComposeSHA256, compose, time.Now().UTC()); err != nil {
			switch {
			case errors.Is(err, ErrComposeChanged):
				return abandon(fmt.Errorf("compose edit not applied: the app's compose changed while this edit was starting, and nothing on the node was changed — check the app and submit the compose again: %w", err))
			case errors.Is(err, ErrEditCatalogApp):
				return abandon(err)
			}
			return abandon(fmt.Errorf("compose edit not applied: persist compose: %w", err))
		}
		sc.Log("info", fmt.Sprintf("compose replaced (%.12s → %.12s)", app.ComposeSHA256, toHash))
		return json.Marshal(map[string]any{
			"appId": app.ID, "persisted": true, "fromComposeSha256": app.ComposeSHA256, "toComposeSha256": toHash,
		})
	}
}
