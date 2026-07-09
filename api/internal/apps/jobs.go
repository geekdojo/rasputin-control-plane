package apps

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// DeploySpec is the spec body of an app.deploy job (and, by alias, app.stop /
// app.delete — all three are keyed only by appId).
type DeploySpec struct {
	AppID string `json:"appId"`
}

// DeleteSpec is the spec body of an app.delete job. Same shape as DeploySpec.
type DeleteSpec = DeploySpec

// DeployWorkflow drives the deploy saga:
//
//  1. load     — look up the app, validate target node is online
//  2. push     — RPC the target agent's docker.deploy handler
//  3. confirm  — agent's ack persists; emit a change event
//
// The agent owns whether the deploy actually succeeded (container running,
// healthchecks passing). The api just records what the agent reported.
func DeployWorkflow(store *Store, inv *inventory.Store, nc *nats.Conn) jobs.Workflow {
	return jobs.Workflow{
		Kind: "app.deploy",
		Steps: []jobs.WorkflowStep{
			{Name: "load", Timeout: 2 * time.Second, Do: deployLoad(store, inv)},
			{Name: "push", Timeout: 60 * time.Second, Do: deployPush(store, inv, nc)},
		},
	}
}

// StopWorkflow drives the stop saga. Symmetrical with deploy but smaller.
func StopWorkflow(store *Store, inv *inventory.Store, nc *nats.Conn) jobs.Workflow {
	return jobs.Workflow{
		Kind: "app.stop",
		Steps: []jobs.WorkflowStep{
			{Name: "load", Timeout: 2 * time.Second, Do: stopLoad(store, inv)},
			{Name: "push", Timeout: 30 * time.Second, Do: stopPush(store, inv, nc)},
		},
	}
}

// DeleteWorkflow drives the delete saga: stop the running deployment on the
// target node (docker compose down), THEN remove the api's ledger row. This is
// what makes "delete" actually tear down containers instead of orphaning them.
//
//  1. stop   — if the node is online, RPC docker.stop (compose down); this must
//     succeed, else the saga fails and the row stays (no silent orphan
//     on a reachable node — the user can retry). If the node is offline
//     or de-registered, we can't reach it: log a warning and proceed to
//     remove the record (delete should still work on a dead node), with
//     the caveat that a container may reappear if that node returns.
//  2. remove — delete the ledger row + emit the `deleted` change event.
func DeleteWorkflow(store *Store, inv *inventory.Store, nc *nats.Conn) jobs.Workflow {
	return jobs.Workflow{
		Kind: "app.delete",
		Steps: []jobs.WorkflowStep{
			{Name: "stop", Timeout: 40 * time.Second, Do: deleteStop(store, inv, nc)},
			{Name: "remove", Timeout: 2 * time.Second, Do: deleteRemove(store, nc)},
		},
	}
}

// ReconcileWorkflow sweeps every app's actual status from its target node
// and reconciles the api's stored lastStatus. Fired by the scheduler on a
// 5-minute (default) interval; also manually invokable.
//
// Two steps:
//
//  1. list  — pull every app from the store; the result is just metadata
//     for the next step (kept for observability + step result).
//  2. sweep — for each app, if its target node is online, NATS-RPC
//     docker.status; if the derived status differs from the
//     stored lastStatus, update + emit a change event. Apps on
//     offline nodes are recorded but not failed.
//
// The saga never fails as a whole — individual app failures are logged
// and counted but don't abort the sweep. This is "honest drift
// reporting", not "apply intent".
func ReconcileWorkflow(store *Store, inv *inventory.Store, nc *nats.Conn) jobs.Workflow {
	return jobs.Workflow{
		Kind: "apps.reconcile",
		Steps: []jobs.WorkflowStep{
			{Name: "list", Timeout: 2 * time.Second, Do: reconcileList(store)},
			{Name: "sweep", Timeout: 90 * time.Second, Do: reconcileSweep(store, inv, nc)},
		},
	}
}

func reconcileList(store *Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		all, err := store.List(sc.Ctx)
		if err != nil {
			return nil, fmt.Errorf("list apps: %w", err)
		}
		sc.Log("info", fmt.Sprintf("reconciling %d app(s)", len(all)))
		return json.Marshal(map[string]int{"count": len(all)})
	}
}

func reconcileSweep(store *Store, inv *inventory.Store, nc *nats.Conn) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		all, err := store.List(sc.Ctx)
		if err != nil {
			return nil, fmt.Errorf("list apps: %w", err)
		}

		var (
			checked int
			drifted int
			skipped int
			failed  int
		)

		for _, app := range all {
			node, err := inv.Get(sc.Ctx, app.TargetNode)
			if err != nil || node == nil {
				skipped++
				continue
			}
			// Skip if not online — the agent won't answer. We don't change
			// lastStatus to "unknown" here because the heartbeat-driven
			// status tracking already conveys that the node is offline.
			if computeNodeStatus(node.LastSeen) != proto.StatusOnline {
				skipped++
				continue
			}

			cmd, _ := json.Marshal(proto.AppStatusCmd{AppID: app.ID})
			// Short timeout per app — the sweep step's own deadline is the
			// hard ceiling; a single hung agent shouldn't block the rest.
			ctx, cancel := context.WithTimeout(sc.Ctx, 5*time.Second)
			msg, err := nc.RequestWithContext(ctx, proto.AppStatusSubject(app.TargetNode), cmd)
			cancel()
			if err != nil {
				failed++
				sc.Log("warn", fmt.Sprintf("%s: status rpc on %s: %v", app.Name, app.TargetNode, err))
				continue
			}
			var ack proto.AppStatusAck
			if err := json.Unmarshal(msg.Data, &ack); err != nil {
				failed++
				continue
			}
			checked++
			if ack.Status == app.LastStatus {
				continue
			}
			// Drift detected — update store + publish.
			now := time.Now().UTC()
			detail := fmt.Sprintf("reconcile: was %s, observed %s", app.LastStatus, ack.Status)
			_ = store.RecordStatus(sc.Ctx, app.ID, ack.Status, detail, now)
			change := proto.AppDeployed
			if ack.Status == proto.AppStatusStopped {
				change = proto.AppStopped
			} else if ack.Status == proto.AppStatusFailed {
				change = proto.AppFailed
			}
			emitChange(nc, app.ID, change, ack.Status, detail, now)
			drifted++
			sc.Log("warn", fmt.Sprintf("%s drifted: %s → %s", app.Name, app.LastStatus, ack.Status))
		}

		sc.Log("info", fmt.Sprintf("checked=%d drifted=%d skipped=%d failed=%d",
			checked, drifted, skipped, failed))
		return json.Marshal(map[string]int{
			"checked": checked, "drifted": drifted,
			"skipped": skipped, "failed": failed,
		})
	}
}

// computeNodeStatus mirrors the api package's helper — duplicated here to
// avoid an import cycle. 30s/2m thresholds match.
func computeNodeStatus(lastSeen time.Time) proto.NodeStatus {
	gap := time.Since(lastSeen)
	switch {
	case gap < 30*time.Second:
		return proto.StatusOnline
	case gap < 2*time.Minute:
		return proto.StatusStale
	default:
		return proto.StatusOffline
	}
}

func parseSpec(raw json.RawMessage) (*DeploySpec, error) {
	var spec DeploySpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return nil, fmt.Errorf("invalid spec: %w", err)
	}
	if spec.AppID == "" {
		return nil, errors.New("appId is required")
	}
	return &spec, nil
}

func loadApp(sc *jobs.StepCtx, store *Store, inv *inventory.Store) (*App, error) {
	spec, err := parseSpec(sc.Spec)
	if err != nil {
		return nil, err
	}
	app, err := store.Get(sc.Ctx, spec.AppID)
	if err != nil {
		return nil, fmt.Errorf("get app: %w", err)
	}
	if app == nil {
		return nil, fmt.Errorf("app %q not found", spec.AppID)
	}
	node, err := inv.Get(sc.Ctx, app.TargetNode)
	if err != nil {
		return nil, fmt.Errorf("get node: %w", err)
	}
	if node == nil {
		return nil, fmt.Errorf("target node %q not registered", app.TargetNode)
	}
	if node.Role != proto.RoleCompute && node.Role != proto.RoleControlPlane {
		return nil, fmt.Errorf("target node %q has role %q; expected compute or controlplane",
			app.TargetNode, node.Role)
	}
	return app, nil
}

func deployLoad(store *Store, inv *inventory.Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		app, err := loadApp(sc, store, inv)
		if err != nil {
			return nil, err
		}
		sc.Log("info", fmt.Sprintf("deploying %q to %s", app.Name, app.TargetNode))
		return json.Marshal(map[string]string{"appId": app.ID, "targetNode": app.TargetNode})
	}
}

func deployPush(store *Store, inv *inventory.Store, nc *nats.Conn) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		app, err := loadApp(sc, store, inv)
		if err != nil {
			return nil, err
		}

		// Mark deploying before we send the rpc so the UI shows the
		// transition immediately (event → WS refresh → yellow DEPLOYING badge),
		// rather than looking unresponsive while the image pull / up runs.
		now := time.Now().UTC()
		_ = store.RecordStatus(sc.Ctx, app.ID, proto.AppStatusDeploying, "", now)
		emitChange(nc, app.ID, proto.AppDeploying, proto.AppStatusDeploying, "", now)

		cmd, _ := json.Marshal(proto.AppDeployCmd{
			AppID:       app.ID,
			Name:        app.Name,
			ComposeYAML: app.ComposeYAML,
		})
		msg, err := nc.RequestWithContext(sc.Ctx, proto.AppDeploySubject(app.TargetNode), cmd)
		if err != nil {
			now := time.Now().UTC()
			_ = store.RecordStatus(sc.Ctx, app.ID, proto.AppStatusFailed, "deploy rpc: "+err.Error(), now)
			emitChange(nc, app.ID, proto.AppFailed, proto.AppStatusFailed, "deploy rpc failed", now)
			return nil, fmt.Errorf("deploy rpc: %w", err)
		}
		var ack proto.AppDeployAck
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			return nil, fmt.Errorf("decode ack: %w", err)
		}

		now = time.Now().UTC()
		_ = store.RecordStatus(sc.Ctx, app.ID, ack.Status, ack.Detail, now)
		change := proto.AppDeployed
		if !ack.OK || ack.Status == proto.AppStatusFailed {
			change = proto.AppFailed
		}
		emitChange(nc, app.ID, change, ack.Status, ack.Detail, now)

		if !ack.OK {
			detail := ack.Detail
			if detail == "" {
				detail = "agent reported deploy failed"
			}
			return nil, errors.New(detail)
		}

		sc.Log("info", fmt.Sprintf("status=%s", ack.Status))
		return json.Marshal(ack)
	}
}

func stopLoad(store *Store, inv *inventory.Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		app, err := loadApp(sc, store, inv)
		if err != nil {
			return nil, err
		}
		sc.Log("info", fmt.Sprintf("stopping %q on %s", app.Name, app.TargetNode))
		return json.Marshal(map[string]string{"appId": app.ID, "targetNode": app.TargetNode})
	}
}

func stopPush(store *Store, inv *inventory.Store, nc *nats.Conn) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		app, err := loadApp(sc, store, inv)
		if err != nil {
			return nil, err
		}

		// Show STOPPING immediately — docker compose down can take a few
		// seconds and the button otherwise looks like it did nothing.
		now := time.Now().UTC()
		_ = store.RecordStatus(sc.Ctx, app.ID, proto.AppStatusStopping, "", now)
		emitChange(nc, app.ID, proto.AppStopping, proto.AppStatusStopping, "", now)

		cmd, _ := json.Marshal(proto.AppStopCmd{AppID: app.ID})
		msg, err := nc.RequestWithContext(sc.Ctx, proto.AppStopSubject(app.TargetNode), cmd)
		if err != nil {
			now := time.Now().UTC()
			_ = store.RecordStatus(sc.Ctx, app.ID, proto.AppStatusFailed, "stop rpc: "+err.Error(), now)
			emitChange(nc, app.ID, proto.AppFailed, proto.AppStatusFailed, "stop rpc failed", now)
			return nil, fmt.Errorf("stop rpc: %w", err)
		}
		var ack proto.AppStopAck
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			return nil, fmt.Errorf("decode ack: %w", err)
		}

		now = time.Now().UTC()
		_ = store.RecordStatus(sc.Ctx, app.ID, ack.Status, ack.Detail, now)
		emitChange(nc, app.ID, proto.AppStopped, ack.Status, ack.Detail, now)

		if !ack.OK {
			detail := ack.Detail
			if detail == "" {
				detail = "agent reported stop failed"
			}
			return nil, errors.New(detail)
		}

		sc.Log("info", fmt.Sprintf("status=%s", ack.Status))
		return json.Marshal(ack)
	}
}

// deleteStop stops the deployment before its record is removed. It reuses the
// same docker.stop RPC as app.stop. On a reachable node the stop must succeed;
// on an unreachable one it warns and lets the delete proceed (best-effort).
func deleteStop(store *Store, inv *inventory.Store, nc *nats.Conn) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parseSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		app, err := store.Get(sc.Ctx, spec.AppID)
		if err != nil {
			return nil, fmt.Errorf("get app: %w", err)
		}
		if app == nil {
			// Already gone — idempotent success (the saga may have retried
			// after remove already ran).
			sc.Log("info", "app already removed")
			return json.Marshal(map[string]string{"appId": spec.AppID, "stop": "already-gone"})
		}

		node, _ := inv.Get(sc.Ctx, app.TargetNode)
		online := node != nil && computeNodeStatus(node.LastSeen) == proto.StatusOnline
		if !online {
			// Can't reach the node to stop it. Delete should still work (a user
			// expects "delete" to remove the record), but warn loudly: if that
			// node returns, its container may reappear until reconciled.
			sc.Log("warn", fmt.Sprintf("node %q is unreachable — removing the record WITHOUT stopping; its container may reappear if the node returns", app.TargetNode))
			return json.Marshal(map[string]string{"appId": app.ID, "stop": "skipped-unreachable"})
		}

		sc.Log("info", fmt.Sprintf("stopping %q on %s before delete", app.Name, app.TargetNode))
		now := time.Now().UTC()
		_ = store.RecordStatus(sc.Ctx, app.ID, proto.AppStatusStopping, "", now)
		emitChange(nc, app.ID, proto.AppStopping, proto.AppStatusStopping, "", now)

		cmd, _ := json.Marshal(proto.AppStopCmd{AppID: app.ID})
		msg, err := nc.RequestWithContext(sc.Ctx, proto.AppStopSubject(app.TargetNode), cmd)
		if err != nil {
			now := time.Now().UTC()
			_ = store.RecordStatus(sc.Ctx, app.ID, proto.AppStatusFailed, "stop rpc: "+err.Error(), now)
			emitChange(nc, app.ID, proto.AppFailed, proto.AppStatusFailed, "stop rpc failed", now)
			return nil, fmt.Errorf("stop rpc: %w", err)
		}
		var ack proto.AppStopAck
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			return nil, fmt.Errorf("decode stop ack: %w", err)
		}
		if !ack.OK {
			detail := ack.Detail
			if detail == "" {
				detail = "agent reported stop failed"
			}
			now := time.Now().UTC()
			_ = store.RecordStatus(sc.Ctx, app.ID, proto.AppStatusFailed, detail, now)
			return nil, errors.New(detail)
		}
		sc.Log("info", "stopped")
		return json.Marshal(map[string]string{"appId": app.ID, "stop": "ok"})
	}
}

// deleteRemove drops the ledger row and emits the deleted event. Idempotent:
// a missing row is treated as already-removed.
func deleteRemove(store *Store, nc *nats.Conn) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := parseSpec(sc.Spec)
		if err != nil {
			return nil, err
		}
		if err := store.Delete(sc.Ctx, spec.AppID); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("delete app: %w", err)
		}
		emitChange(nc, spec.AppID, proto.AppDeleted, proto.AppStatusStopped, "deleted", time.Now().UTC())
		sc.Log("info", "removed from the app list")
		return json.Marshal(map[string]string{"appId": spec.AppID, "deleted": "true"})
	}
}

func emitChange(nc *nats.Conn, appID string, change proto.AppChangeType, status proto.AppStatus, detail string, ts time.Time) {
	ev := proto.AppChangeEvt{
		AppID:  appID,
		Change: change,
		Status: status,
		Detail: detail,
		Ts:     ts,
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return
	}
	if err := nc.Publish(proto.AppChangeSubject(appID, change), payload); err != nil {
		log.Printf("apps: publish change %s: %v", appID, err)
	}
}
