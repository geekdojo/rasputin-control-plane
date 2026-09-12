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

// CanRevert decides whether app has a previous compose to re-apply. It is the
// revertAvailable flag's answer; which compose that is, the client names by
// hash (previousComposeSha256) and ResolveReapply checks.
func CanRevert(app *App) error {
	if app.PreviousComposeYAML == "" {
		return ErrNoPreviousCompose
	}
	return nil
}

// ErrUnknownComposeHash is a re-apply naming a compose this app cannot go to:
// neither the one installed nor the one retained as previous. The HTTP layer
// answers it with a 409, so the text is written for the owner.
var ErrUnknownComposeHash = errors.New("this app has no compose with that sha256 to re-apply: it is neither the installed compose nor the retained previous one")

// ValidComposeHash reports whether s is spelled as ComposeHash spells a hash:
// 64 lower-case hex digits.
func ValidComposeHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ResolveReapply decides what re-applying the compose whose hash is sha does
// to app. current is true when that compose is already installed — the no-op
// an idempotent PUT must be. Otherwise a nil error means sha names the
// retained previous compose and there is something to do, and
// ErrUnknownComposeHash means it names nothing this app can go to.
//
// One answer for PUT /api/apps/{id}/compose with {"sha256":…} and for the
// app.revert saga, which asks again when it runs.
func ResolveReapply(app *App, sha string) (current bool, err error) {
	if sha == app.ComposeSHA256 {
		return true, nil
	}
	if app.PreviousComposeYAML != "" && ComposeHash(app.PreviousComposeYAML) == sha {
		return false, nil
	}
	return false, ErrUnknownComposeHash
}

// RevertSpec is the spec body of an app.revert job: the app, and the hash of
// the compose to re-apply. The hash is what makes a re-apply idempotent. A
// re-apply keyed only by appId meant "go to whichever compose is not
// installed", so the same request sent twice went there and back again. A
// hash names one compose, and once it is installed the same request is a
// no-op.
//
// A hash is safe in a spec where a compose is not: it names a compose the api
// already holds and reveals nothing of what the compose says.
type RevertSpec struct {
	AppID         string `json:"appId"`
	ComposeSHA256 string `json:"sha256"`
	// DeleteVolumes is ComposeChangeSpec's: the named volumes the owner asked
	// to delete because re-applying this compose drops them (#412).
	DeleteVolumes []string `json:"deleteVolumes,omitempty"`
}

// parseRevertSpec decodes an app.revert spec, strictly, like every app spec.
func parseRevertSpec(raw json.RawMessage) (*RevertSpec, error) {
	var spec RevertSpec
	if err := decodeStrict(raw, &spec); err != nil {
		return nil, err
	}
	if spec.AppID == "" {
		return nil, errors.New("appId is required")
	}
	if !ValidComposeHash(spec.ComposeSHA256) {
		return nil, errors.New("sha256 must be the 64 lower-case hex digits of a compose's sha256")
	}
	if err := ValidateDeleteVolumes(spec.AppID, spec.DeleteVolumes); err != nil {
		return nil, err
	}
	return &spec, nil
}

func revertSpecDeleteVolumes(raw json.RawMessage) ([]string, error) {
	spec, err := parseRevertSpec(raw)
	if err != nil {
		return nil, err
	}
	return spec.DeleteVolumes, nil
}

func revertSpecAppID(raw json.RawMessage) (string, error) {
	spec, err := parseRevertSpec(raw)
	if err != nil {
		return "", err
	}
	return spec.AppID, nil
}

// RevertWorkflow drives app.revert (geekdojo/geekdojo-brain#411, #410):
// re-apply, in place, the compose an app ran before its compose was last
// replaced, named by its hash. It is the owner's way back after a change whose
// pull succeeded and whose `up` did not — the one failure the other compose
// sagas deliberately do not undo on their own.
//
//  1. load  — the app and its node, checked as a deploy checks them; a hash
//     that is already installed ends the job here, successfully, changing
//     nothing
//  2. pull  — the named compose's images; nothing else on the node or the
//     row changes, and a failure ends the job with the status put back
//  3. apply — Store.RevertCompose installs the named previous record,
//     conditional on the installed and previous composes being the ones read
//     and pulled
//  4. push  — the deploy saga's push, unchanged
//  5. leaf  — the deploy saga's leaf step: the previous record carries its
//     own port and scheme, and the route is built from the row
//  6. drop_volumes — delete the volumes the re-applied compose drops that
//     the owner named in deleteVolumes, now that `up` has succeeded (#412)
//
// The pull step applies the dropped-volume gate to a re-apply exactly as to
// any other change: a previous compose is not exempt, because the volumes the
// compose being left created are on disk, and going back to a compose that
// does not declare them orphans their data just the same.
//
// The target is named, not implied. The compose being left is retained as the
// previous one, as every compose change retains what it replaced, so the owner
// can name it to go forward again. But a request naming a hash can only ever
// arrive at that hash: repeating it finds the compose installed and does
// nothing. The route this replaced took no target, went to "whichever one is
// not installed", and so bounced between two composes when it was repeated.
//
// It is a re-deploy of a compose that already ran on this node, not a catalog
// operation, and it asks the catalog nothing:
//
//   - The compose comes from the row, where UpgradeCompose or EditCompose put
//     it. For a catalog app that compose came out of the verified store when
//     it was installed; re-applying it passes no new compose through the api,
//     so no trust check is skipped.
//   - compose_catalog_version moves with the compose. After re-applying a v2
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
// Like the other compose sagas, a failure after the pull is not reverted
// automatically.
func RevertWorkflow(store *Store, inv *inventory.Store, nc *nats.Conn, mint LeafMinter) jobs.Workflow {
	return jobs.Workflow{
		Kind: "app.revert",
		Steps: []jobs.WorkflowStep{
			{Name: "load", Timeout: 2 * time.Second, Do: revertLoad(store, inv)},
			// Backstops, as in UpgradeWorkflow; the real deadlines are the
			// named compose's budget, applied inside each step.
			{Name: "pull", Timeout: proto.AppDeployRPCFor(int(proto.AppDeployWorkMax.Seconds())), Do: pullStep(store, inv, nc, "re-apply of the previous compose", revertSpecAppID, revertSpecDeleteVolumes, revertPullSource)},
			{Name: "apply", Timeout: 2 * time.Second, Do: revertApply(store, inv, nc)},
			{Name: "push", Timeout: proto.AppDeployRPCFor(int(proto.AppDeployWorkMax.Seconds())), Do: pushStep(store, inv, nc, revertSpecAppID)},
			{Name: "leaf", Timeout: 15 * time.Second, Do: leafStep(store, inv, nc, mint, revertSpecAppID)},
			{Name: "drop_volumes", Timeout: 90 * time.Second, Do: dropVolumesStep(store, inv, nc, revertSpecAppID)},
		},
	}
}

func revertLoad(store *Store, inv *inventory.Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parseRevertSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		app, err := loadAppByID(sc, store, inv, spec.AppID)
		if err != nil {
			return nil, err
		}
		current, err := ResolveReapply(app, spec.ComposeSHA256)
		if err != nil {
			return nil, err
		}
		result, _ := json.Marshal(map[string]any{"appId": app.ID, "targetNode": app.TargetNode, "composeSha256": spec.ComposeSHA256, "alreadyInstalled": current})
		if current {
			// The handler answers this with a no-op and starts no job, so
			// something else installed the compose between the request and
			// now. There is nothing to pull, write or push.
			sc.Log("info", fmt.Sprintf("compose %.12s is already installed on %q; nothing to do", spec.ComposeSHA256, app.Name))
			return result, jobs.ErrStopWorkflow
		}
		sc.Log("info", fmt.Sprintf("re-applying compose %.12s to %q on %s (installed: %.12s)",
			spec.ComposeSHA256, app.Name, app.TargetNode, app.ComposeSHA256))
		return result, nil
	}
}

// revertPullSource is the compose a re-apply is about to install: the one the
// spec names, under the budget it ran with.
func revertPullSource(sc *jobs.StepCtx, app *App) (pullTarget, error) {
	spec, err := parseRevertSpec(sc.Spec)
	if err != nil {
		return pullTarget{}, err
	}
	current, err := ResolveReapply(app, spec.ComposeSHA256)
	switch {
	case err != nil:
		return pullTarget{}, err
	case current:
		// Installed since load looked. apply will deploy what the row holds,
		// so that is what gets pulled.
		return pullTarget{ComposeYAML: app.ComposeYAML, DeployBudgetSeconds: app.DeployBudgetSeconds}, nil
	}
	return pullTarget{ComposeYAML: app.PreviousComposeYAML, DeployBudgetSeconds: app.PreviousDeployBudgetSeconds}, nil
}

// revertApply installs the named previous record. The compose it installs must
// be the one whose images were pulled, and the installed compose the one read
// — a change to either since means this job's view of the app is stale, and
// it stops with nothing changed.
func revertApply(store *Store, inv *inventory.Store, nc *nats.Conn) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		pulled, err := pulledCompose(sc)
		if err != nil {
			return nil, err
		}
		abandon := func(err error) (json.RawMessage, error) {
			abandonAfterPull(sc, store, nc, pulled, err.Error())
			return nil, err
		}
		spec, err := parseRevertSpec(sc.Spec)
		if err != nil {
			return abandon(fmt.Errorf("re-apply not done: %w", err))
		}
		if pulled.ComposeSHA256 != spec.ComposeSHA256 {
			return abandon(fmt.Errorf("re-apply not done: the compose pulled (%.12s) is not the one named (%.12s), and nothing on the node was changed — check the app and try again: %w",
				pulled.ComposeSHA256, spec.ComposeSHA256, ErrComposeChanged))
		}
		app, err := loadAppByID(sc, store, inv, spec.AppID)
		if err != nil {
			return abandon(fmt.Errorf("re-apply not done: %w", err))
		}
		current, err := ResolveReapply(app, spec.ComposeSHA256)
		switch {
		case errors.Is(err, ErrUnknownComposeHash):
			return abandon(fmt.Errorf("re-apply not done: the app's previous compose changed while its images were being pulled, and nothing on the node was changed — check the app and try again: %w", ErrComposeChanged))
		case err != nil:
			return abandon(fmt.Errorf("re-apply not done: %w", err))
		case current:
			// Another job installed the named compose during the pull. The row
			// already says what this job was asked to bring about; pushing it
			// is still that, and `up -d` on an unchanged compose changes
			// nothing.
			sc.Log("info", "the row already holds the named compose; deploying it")
			return json.Marshal(map[string]any{"appId": app.ID, "persisted": false, "composeSha256": app.ComposeSHA256})
		}
		fromHash := app.ComposeSHA256
		if err := store.RevertCompose(sc.Ctx, app.ID, fromHash, app.PreviousComposeYAML, time.Now().UTC()); err != nil {
			if errors.Is(err, ErrComposeChanged) {
				return abandon(fmt.Errorf("re-apply not done: the app's compose changed while this was starting, and nothing on the node was changed — check the app and try again: %w", err))
			}
			return abandon(fmt.Errorf("re-apply not done: install the previous compose: %w", err))
		}
		sc.Log("info", fmt.Sprintf("row now holds compose %.12s (was %.12s, kept as the previous); pushing it", pulled.ComposeSHA256, fromHash))
		return json.Marshal(map[string]any{
			"appId": app.ID, "persisted": true, "fromComposeSha256": fromHash, "toComposeSha256": pulled.ComposeSHA256,
			"catalogVersion": app.PreviousComposeCatalogVersion,
		})
	}
}
