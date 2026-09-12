package apps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Pull, then up (geekdojo/geekdojo-brain#411).
//
// A saga that changes an app's compose pulls the new compose's images as a
// step of its own, BEFORE it writes the row and before it pushes. The agent
// stages the compose for the pull and never writes the app's live compose file
// (agent/internal/docker ComposeBackend.Pull), and `pull` creates no
// container. So a pull that fails has changed nothing — not the node, not the
// row — and the saga ends there, with the app's status put back and the
// registry's error recorded as the reason. Measured case 7 (app-catalog.md
// §8a.2) is the fact this rests on: with a bad digest the old container keeps
// running untouched.
//
// Why the pull goes before the row write rather than after it. A pull placed
// after the write would need the write undone when it failed, and undoing it
// exactly is not possible from the row: UpgradeCompose shifts the installed
// compose into previous_compose_yaml, which overwrites the previous compose
// the app already had. Restoring "the row as it was" would then need that
// older compose from somewhere — a job step result, which is persisted and
// rendered on the Tasks page, and for a custom app (#410) holds whatever
// secrets its compose inlines. Pulling first never writes, so there is nothing
// to undo. The ordering #409 settled — row before PUSH — is unchanged: the
// push is still the first thing that touches the node, and the row names the
// new compose before it does.
//
// A failure AFTER a successful pull — the push, `up` — is not reverted. New
// containers may have started and migrated the app's data forward, and
// putting the old compose back over migrated data is the direction that
// cannot be recovered. The row keeps the new compose, previous_compose_yaml
// keeps the old, the status is failed with the agent's reason, and going back
// is the owner's explicit call (RevertWorkflow).
//
// The step is built from a pullSource so every saga that changes a compose puts
// it in front of its write: the catalog upgrade, the re-apply of the previous
// compose, and the custom compose edit (#410, which reads the submitted compose
// from the ComposeStash rather than from the row or the spec).

// pullTarget is the compose a pull step fetches images for, and the budget the
// pull runs under — the budget the deploy of that compose will get, since
// almost all of a deploy's time is its pull.
type pullTarget struct {
	ComposeYAML         string
	DeployBudgetSeconds int
}

// pullSource says what compose a saga is about to write onto app's row. It
// runs at the start of the pull step, before anything is touched, so an error
// from it is a refusal that changes nothing. The step after the pull must then
// write exactly this compose — pulledCompose gives it the hash to check.
type pullSource func(sc *jobs.StepCtx, app *App) (pullTarget, error)

// pullResult is the pull step's recorded result. It carries no compose text:
// step results are persisted and rendered, and a compose can hold secrets.
type pullResult struct {
	AppID string `json:"appId"`
	// ComposeSHA256 is the hash of the compose whose images were pulled. The
	// write after the pull refuses to install any other.
	ComposeSHA256 string `json:"composeSha256"`
	// PriorStatus is the status the step displaced when it marked the app
	// deploying, and MarkedAtMs the last_status_at it wrote; abandonAfterPull
	// uses both to put the status back.
	PriorStatus proto.AppStatus `json:"priorStatus"`
	MarkedAtMs  int64           `json:"markedAtMs"`
	// DeleteVolumes is the owner's deleteVolumes as the volume gate accepted
	// it: exactly the named volumes the pulled compose drops (#412). The drop
	// step removes these and nothing else, once `up` has succeeded.
	DeleteVolumes []string `json:"deleteVolumes,omitempty"`
}

// pullStep is a saga step that pulls source's compose on the app's node and
// changes nothing else. change names the saga's change in the reason an owner
// reads when it does not go ahead ("upgrade", "re-apply of the previous
// compose").
//
// It marks the app deploying for the length of the pull, as the push does, so
// the UI shows the operation the moment it starts rather than after a pull
// that can take the app's whole budget. When the pull fails the status goes
// back (Store.RestoreStatus), because nothing on the node changed.
//
// Before it pulls, it applies the dropped-volume gate (#412, volumegate.go):
// the node says which of the app's named volumes on disk the compose does not
// declare, and unless deleteVolumes names exactly those, the change ends here
// the way a failed pull does — nothing pulled, nothing written, status put
// back, and the volumes named in the reason. This is the authoritative check;
// the one PUT /api/apps/{id}/compose makes first is advisory. It runs before
// the pull, not after, so a refused change does not spend the app's budget
// fetching images it will not use.
func pullStep(store *Store, inv *inventory.Store, nc *nats.Conn, change string, appID specAppID, deleteVolumes specDeleteVolumes, source pullSource) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		app, err := loadAppFor(sc, store, inv, appID)
		if err != nil {
			return nil, err
		}
		named, err := deleteVolumes(sc.Spec)
		if err != nil {
			return nil, err
		}
		target, err := source(sc, app)
		if err != nil {
			return nil, err
		}

		markedAt := time.Now().UTC()
		_ = store.RecordStatus(sc.Ctx, app.ID, proto.AppStatusDeploying, "", markedAt)
		emitChange(nc, app.ID, proto.AppDeploying, proto.AppStatusDeploying, "", markedAt)
		pulled := pullResult{
			AppID:         app.ID,
			ComposeSHA256: ComposeHash(target.ComposeYAML),
			PriorStatus:   app.LastStatus,
			MarkedAtMs:    ms(markedAt),
		}

		dropped, err := DroppedVolumesOnNode(sc.Ctx, inv, nc, app, target.ComposeYAML)
		if err != nil {
			reason := fmt.Sprintf("%s not applied: which of the app's volumes the new compose would drop could not be checked, so nothing on the node was changed — %s", change, err)
			abandonAfterPull(sc, store, nc, pulled, reason)
			return nil, errors.New(reason)
		}
		if err := GateDroppedVolumes(dropped, named); err != nil {
			reason := fmt.Sprintf("%s not applied, and nothing on the node was changed: %s", change, err)
			abandonAfterPull(sc, store, nc, pulled, reason)
			return nil, fmt.Errorf("%s not applied, and nothing on the node was changed: %w", change, err)
		}
		if len(dropped) > 0 {
			names := make([]string, 0, len(dropped))
			for _, v := range dropped {
				names = append(names, v.Name)
			}
			pulled.DeleteVolumes = names
			sc.Log("info", "the new compose drops volume(s) the owner named for deletion; they are deleted once it is up: "+strings.Join(names, ", "))
		}

		sc.Log("info", fmt.Sprintf("pulling images for %q on %s (compose %.12s)", app.Name, app.TargetNode, pulled.ComposeSHA256))
		reason := pullOnNode(sc.Ctx, inv, nc, app, target)
		if reason != "" {
			reason = fmt.Sprintf("%s not applied: pulling its images failed, so nothing on the node was changed — %s", change, reason)
			abandonAfterPull(sc, store, nc, pulled, reason)
			return nil, errors.New(reason)
		}
		sc.Log("info", "images pulled; nothing on the node has changed yet")
		return json.Marshal(pulled)
	}
}

// pullOnNode sends docker.pull and returns "" on success, or why it did not
// succeed, in words for the owner.
func pullOnNode(ctx context.Context, inv *inventory.Store, nc *nats.Conn, app *App, target pullTarget) string {
	payload, err := json.Marshal(proto.AppPullCmd{
		AppID:             app.ID,
		ComposeYAML:       target.ComposeYAML,
		WorkBudgetSeconds: target.DeployBudgetSeconds,
	})
	if err != nil {
		return "encode pull command: " + err.Error()
	}
	// The app's own budget plus the slack, exactly as the push waits, so the
	// agent answers with the registry's error before this gives up.
	rctx, cancel := context.WithTimeout(ctx, proto.AppDeployRPCFor(target.DeployBudgetSeconds))
	defer cancel()
	subject := proto.AppPullSubject(app.TargetNode)
	msg, err := nc.RequestWithContext(rctx, subject, payload)
	switch {
	case errors.Is(err, nats.ErrNoResponders):
		// Offline, or online with an agent that predates docker.pull — which
		// one, and what to do about it, is inventory's to say. Either way the
		// pull did not run, so the node is untouched and going back is safe.
		ictx, icancel := detachCtx(ctx)
		defer icancel()
		return inv.ExplainNoResponder(ictx, subject).String()
	case err != nil:
		return "pull rpc: " + err.Error()
	}
	var ack proto.AppPullAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		return "decode pull ack: " + err.Error()
	}
	if !ack.OK {
		if ack.Detail == "" {
			return "agent reported the pull failed"
		}
		return ack.Detail
	}
	return ""
}

// pulledCompose is the pull step's result, for the step after it.
func pulledCompose(sc *jobs.StepCtx) (pullResult, error) {
	raw, ok := sc.PriorResults["pull"]
	if !ok {
		return pullResult{}, errors.New("no pull step ran before this one; refusing to write a compose whose images were not pulled")
	}
	var pr pullResult
	if err := json.Unmarshal(raw, &pr); err != nil {
		return pullResult{}, fmt.Errorf("read pull step result: %w", err)
	}
	return pr, nil
}

// abandonAfterPull ends a compose change that has not reached the node: the
// pull failed, or the write after a successful pull was refused. It puts back
// the status the pull step displaced, with reason as the detail, and emits the
// change so the UI refreshes. The caller returns the error that fails the job.
//
// The write uses a detached context: a pull that timed out has usually spent
// the step's own context, and a status write on a spent context silently
// writes nothing — leaving the app DEPLOYING, the very thing this undoes.
func abandonAfterPull(sc *jobs.StepCtx, store *Store, nc *nats.Conn, pulled pullResult, reason string) {
	ctx, cancel := detachCtx(sc.Ctx)
	defer cancel()
	now := time.Now().UTC()
	restored, err := store.RestoreStatus(ctx, pulled.AppID, fromMs(pulled.MarkedAtMs), pulled.PriorStatus, reason, now)
	switch {
	case err != nil:
		log.Printf("apps: restore status of %s after an abandoned compose change: %v", pulled.AppID, err)
		sc.Log("warn", "could not put the app's status back: "+err.Error())
	case !restored:
		// Something recorded a newer status after the pull marked the app
		// deploying; that is later news than the one being restored.
		sc.Log("info", "the app's status changed while this ran; leaving the newer status in place")
	default:
		emitChange(nc, pulled.AppID, changeFor(pulled.PriorStatus), pulled.PriorStatus, reason, now)
		sc.Log("info", fmt.Sprintf("status put back to %s", pulled.PriorStatus))
	}
}

// changeFor is the change event that announces an app settling at status —
// the same mapping the reconcile sweep uses for drift.
func changeFor(status proto.AppStatus) proto.AppChangeType {
	switch status {
	case proto.AppStatusStopped:
		return proto.AppStopped
	case proto.AppStatusFailed:
		return proto.AppFailed
	}
	return proto.AppDeployed
}
