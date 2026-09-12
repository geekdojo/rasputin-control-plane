package apps

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// CanRevert decides whether app has a previous compose to re-apply. One answer
// for the revertAvailable flag and for POST /api/apps/{id}/revert, so the UI
// cannot offer a re-apply the route refuses.
func CanRevert(app *App) error {
	if app.PreviousComposeYAML == "" {
		return ErrNoPreviousCompose
	}
	return nil
}

// RevertWorkflow drives app.revert (geekdojo/geekdojo-brain#411): re-apply the
// compose an app ran before its compose was last replaced, in place. It is the
// owner's way back after a change whose pull succeeded and whose `up` did not
// — the one failure the upgrade saga deliberately does not undo on its own.
//
//  1. load  — the app and its node, checked as a deploy checks them
//  2. pull  — the previous compose's images; nothing else on the node or the
//     row changes, and a failure ends the job with the status put back
//  3. swap  — Store.RevertCompose: the installed record and the previous one
//     trade places, conditional on both being what was read and pulled
//  4. push  — the deploy saga's push, unchanged
//  5. leaf  — the deploy saga's leaf step: the swap restored the previous
//     compose's port and scheme, and the route is built from the row
//
// It is a re-deploy of a compose that already ran on this node, not a catalog
// operation, and it asks the catalog nothing:
//
//   - The compose comes from the row, where UpgradeCompose (or, later, the
//     custom edit) put it. For a catalog app that compose came out of the
//     verified store when it was installed; re-applying it passes no new
//     compose through the api, so no trust check is skipped.
//   - compose_catalog_version swaps with the compose. After re-applying a v2
//     app's v1 compose the row says v1, so ResolveUpgrade offers the v2 tile
//     again — the badge tells the truth about what is installed.
//   - ResolveUpgrade's downgrade refusal is not consulted, on purpose. That
//     refusal stops the api from OFFERING an older catalog's compose as an
//     upgrade when the catalog in effect goes backwards, which nobody asked
//     for. A re-apply is explicit, owner-initiated, and names one compose the
//     owner already ran. What the refusal guards against is still true here
//     — an older image cannot undo a data migration a newer one ran — and
//     the route cannot tell whether one ran. That warning is the UI's to give
//     (#414); consent stays in the UI (Bryce, 2026-09-12).
//
// Swapping rather than clearing means a re-apply can itself be re-applied:
// the compose it replaced is now the previous one. Like the upgrade, a failure
// after the pull is not reverted automatically.
func RevertWorkflow(store *Store, inv *inventory.Store, nc *nats.Conn, mint LeafMinter) jobs.Workflow {
	return jobs.Workflow{
		Kind: "app.revert",
		Steps: []jobs.WorkflowStep{
			{Name: "load", Timeout: 2 * time.Second, Do: revertLoad(store, inv)},
			// Backstops, as in UpgradeWorkflow; the real deadlines are the
			// previous compose's budget, applied inside each step.
			{Name: "pull", Timeout: proto.AppDeployRPCFor(int(proto.AppDeployWorkMax.Seconds())), Do: pullStep(store, inv, nc, "re-apply of the previous compose", revertPullSource)},
			{Name: "swap", Timeout: 2 * time.Second, Do: revertSwap(store, inv, nc)},
			{Name: "push", Timeout: proto.AppDeployRPCFor(int(proto.AppDeployWorkMax.Seconds())), Do: deployPush(store, inv, nc)},
			{Name: "leaf", Timeout: 15 * time.Second, Do: deployLeaf(store, inv, nc, mint)},
		},
	}
}

func revertLoad(store *Store, inv *inventory.Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		app, err := loadApp(sc, store, inv)
		if err != nil {
			return nil, err
		}
		if err := CanRevert(app); err != nil {
			return nil, err
		}
		sc.Log("info", fmt.Sprintf("re-applying the previous compose of %q on %s (%.12s → %.12s)",
			app.Name, app.TargetNode, app.ComposeSHA256, ComposeHash(app.PreviousComposeYAML)))
		return json.Marshal(map[string]string{"appId": app.ID, "targetNode": app.TargetNode})
	}
}

// revertPullSource is the compose a re-apply is about to write: the previous
// one, under the budget it ran with.
func revertPullSource(_ *jobs.StepCtx, app *App) (pullTarget, error) {
	if err := CanRevert(app); err != nil {
		return pullTarget{}, err
	}
	return pullTarget{ComposeYAML: app.PreviousComposeYAML, DeployBudgetSeconds: app.PreviousDeployBudgetSeconds}, nil
}

// revertSwap trades the installed record and the previous one. The previous
// compose must still be the one whose images were pulled, and the installed
// compose the one read — a change to either since means this job's view of the
// app is stale, and it stops with nothing changed.
func revertSwap(store *Store, inv *inventory.Store, nc *nats.Conn) jobs.DoFn {
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
			return abandon(fmt.Errorf("re-apply not done: %w", err))
		}
		if err := CanRevert(app); err != nil {
			return abandon(fmt.Errorf("re-apply not done: %w", err))
		}
		if ComposeHash(app.PreviousComposeYAML) != pulled.ComposeSHA256 {
			return abandon(fmt.Errorf("re-apply not done: the app's previous compose changed while its images were being pulled, and nothing on the node was changed — check the app and try again: %w", ErrComposeChanged))
		}
		fromHash := app.ComposeSHA256
		if err := store.RevertCompose(sc.Ctx, app.ID, fromHash, app.PreviousComposeYAML, time.Now().UTC()); err != nil {
			if errors.Is(err, ErrComposeChanged) {
				return abandon(fmt.Errorf("re-apply not done: the app's compose changed while this was starting, and nothing on the node was changed — check the app and try again: %w", err))
			}
			return abandon(fmt.Errorf("re-apply not done: swap compose: %w", err))
		}
		sc.Log("info", fmt.Sprintf("row now holds the previous compose (%.12s → %.12s); pushing it", fromHash, pulled.ComposeSHA256))
		return json.Marshal(map[string]any{
			"appId": app.ID, "fromComposeSha256": fromHash, "toComposeSha256": pulled.ComposeSHA256,
			"catalogVersion": app.PreviousComposeCatalogVersion,
		})
	}
}
