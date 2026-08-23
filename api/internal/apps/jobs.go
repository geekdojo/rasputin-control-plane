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
// LeafMinter mints an app's per-app TLS leaf and returns the delivery command
// (cert/key + proxy route info) the deploy saga ships to the target node
// (ADR-0004 §6). main backs it with the Mesh CA + cluster id; nil disables leaf
// delivery (e.g. dev without a CA).
type LeafMinter func(app *App) (proto.AppLeafCmd, error)

func DeployWorkflow(store *Store, inv *inventory.Store, nc *nats.Conn, mint LeafMinter) jobs.Workflow {
	return jobs.Workflow{
		Kind: "app.deploy",
		Steps: []jobs.WorkflowStep{
			{Name: "load", Timeout: 2 * time.Second, Do: deployLoad(store, inv)},
			// Longer than the agent's own work budget on purpose, so the agent
			// answers with the real failure instead of this step timing out on
			// top of it — see proto.AppDeployWork.
			{Name: "push", Timeout: proto.AppDeployRPC, Do: deployPush(store, inv, nc)},
			{Name: "leaf", Timeout: 15 * time.Second, Do: deployLeaf(store, inv, nc, mint)},
		},
	}
}

// deployLeaf mints the app's TLS leaf and delivers it (+ proxy route info) to
// the target node, where the node-local Caddy fronts the app at its real HTTPS
// URL (ADR-0004 §6/§9). Best-effort: a successful container deploy is not undone
// by a leaf hiccup — the failure is logged, and a redeploy (or the node's
// startup reconcile) retries. Skipped for a headless app (no published port) or
// when leaf delivery is disabled (nil minter).
func deployLeaf(store *Store, inv *inventory.Store, nc *nats.Conn, mint LeafMinter) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		if mint == nil {
			return nil, nil
		}
		app, err := loadApp(sc, store, inv)
		if err != nil {
			return nil, err
		}
		if app.PublishedPort == 0 {
			sc.Log("info", "no published port — skipping proxy leaf")
			return nil, nil
		}
		cmd, err := mint(app)
		if err != nil {
			sc.Log("warn", "mint leaf failed (app is deployed; proxy unavailable): "+err.Error())
			return nil, nil
		}
		ok, detail, err := deliverLeaf(sc.Ctx, nc, app.TargetNode, cmd)
		if err != nil {
			sc.Log("warn", "deliver leaf failed (app is deployed; proxy unavailable): "+err.Error())
			return nil, nil
		}
		if !ok {
			sc.Log("warn", "node rejected leaf: "+detail)
			return nil, nil
		}
		sc.Log("info", "delivered TLS leaf + proxy route")
		return nil, nil
	}
}

// deliverLeaf ships an AppLeafCmd to nodeID over the bus and reports whether the
// node accepted it (ack.OK) plus any rejection detail. Shared by the deploy saga
// and the rotation sweep so mint-and-ship lives in one place.
func deliverLeaf(ctx context.Context, nc *nats.Conn, nodeID string, cmd proto.AppLeafCmd) (ok bool, detail string, err error) {
	payload, err := json.Marshal(cmd)
	if err != nil {
		return false, "", err
	}
	msg, err := nc.RequestWithContext(ctx, proto.AppLeafSubject(nodeID), payload)
	if err != nil {
		return false, "", err
	}
	var ack proto.AppLeafAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		return false, "", err
	}
	return ack.OK, ack.Detail, nil
}

// LeafRemover deletes an app's on-disk leaf material on the control plane
// (keyed by AppID). main backs it with an os.RemoveAll of the app's leaf dir;
// nil is a no-op (dev without a CA — no leaves were ever persisted).
type LeafRemover func(appID string) error

// deleteLeaf tears down the app's leaf + proxy route on the target node, and
// removes the CP-side leaf material, before the ledger row is removed
// (ADR-0004 §6). Best-effort — an offline node must not block delete (its files
// go when it's reflashed / the app never returns).
func deleteLeaf(store *Store, inv *inventory.Store, nc *nats.Conn, removeLeaf LeafRemover) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		app, err := loadApp(sc, store, inv)
		if err != nil {
			// Node gone/de-registered: nothing to tear down on it. Let delete
			// proceed, but still clean the CP-side leaf dir if we can name the app.
			sc.Log("warn", "skip leaf teardown: "+err.Error())
			if spec, perr := parseSpec(sc.Spec); perr == nil && removeLeaf != nil {
				_ = removeLeaf(spec.AppID)
			}
			return nil, nil
		}
		cmd, _ := json.Marshal(proto.AppLeafCmd{AppID: app.ID, Remove: true})
		if _, err := nc.RequestWithContext(sc.Ctx, proto.AppLeafSubject(app.TargetNode), cmd); err != nil {
			sc.Log("warn", "leaf teardown rpc failed: "+err.Error())
		}
		if removeLeaf != nil {
			if err := removeLeaf(app.ID); err != nil {
				sc.Log("warn", "remove CP leaf dir failed: "+err.Error())
			}
		}
		return nil, nil
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
func DeleteWorkflow(store *Store, inv *inventory.Store, nc *nats.Conn, removeLeaf LeafRemover) jobs.Workflow {
	return jobs.Workflow{
		Kind: "app.delete",
		Steps: []jobs.WorkflowStep{
			{Name: "stop", Timeout: 40 * time.Second, Do: deleteStop(store, inv, nc)},
			{Name: "teardown_leaf", Timeout: 10 * time.Second, Do: deleteLeaf(store, inv, nc, removeLeaf)},
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

// LeafRotator re-mints an app's per-app TLS leaf against its on-disk copy. It
// returns the delivery command, whether a fresh leaf was minted this sweep
// (renewed==true → the leaf entered its renew window or its SANs drifted and
// must be re-shipped), and a commit closure the caller invokes ONLY after the
// node accepts the fresh leaf — so an offline node retries on the next sweep
// instead of the on-disk leaf silently advancing past what the node holds. nil
// disables rotation (no CA / dev).
type LeafRotator func(app *App) (cmd proto.AppLeafCmd, renewed bool, commit func() error, err error)

// RotateLeavesWorkflow is the timer half of the per-app leaf lifecycle
// (ADR-0004 §6): it periodically re-mints per-app TLS leaves before they expire
// and re-ships the fresh leaf to the app's node, which hot-reloads its proxy.
// Mint-on-deploy and teardown-on-delete are the saga's job; this closes the
// "leaves must not expire" gap. Like the reconcile sweep it never fails as a
// whole — per-app errors are logged and counted, not fatal.
func RotateLeavesWorkflow(store *Store, inv *inventory.Store, nc *nats.Conn, rotate LeafRotator) jobs.Workflow {
	return jobs.Workflow{
		Kind: "apps.leaf_rotate",
		Steps: []jobs.WorkflowStep{
			{Name: "rotate", Timeout: 90 * time.Second, Do: rotateLeavesSweep(store, inv, nc, rotate)},
		},
	}
}

func rotateLeavesSweep(store *Store, inv *inventory.Store, nc *nats.Conn, rotate LeafRotator) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		if rotate == nil {
			return nil, nil
		}
		all, err := store.List(sc.Ctx)
		if err != nil {
			return nil, fmt.Errorf("list apps: %w", err)
		}

		var checked, rotated, shipped, skipped, failed int
		for _, app := range all {
			if app.PublishedPort == 0 {
				continue // headless app: no proxy, no leaf
			}
			checked++
			out := RotateAppLeaf(sc.Ctx, inv, nc, rotate, app)
			for _, m := range out.Log {
				sc.Log(m.Level, m.Text)
			}
			switch out.Outcome {
			case LeafUnchanged:
			case LeafShipped:
				rotated++
				shipped++
			case LeafNodeOffline:
				rotated++
				skipped++
			case LeafFailed:
				if out.Renewed {
					rotated++
				}
				failed++
			}
		}

		sc.Log("info", fmt.Sprintf("checked=%d rotated=%d shipped=%d skipped=%d failed=%d",
			checked, rotated, shipped, skipped, failed))
		return json.Marshal(map[string]int{
			"checked": checked, "rotated": rotated, "shipped": shipped,
			"skipped": skipped, "failed": failed,
		})
	}
}

// --- one app's leaf, shared by the sweep and the exposure toggle ------------

// LeafOutcome is what happened to one app's leaf.
type LeafOutcome string

const (
	LeafUnchanged   LeafOutcome = "unchanged"    // still has life and its SANs match
	LeafShipped     LeafOutcome = "shipped"      // re-minted, delivered, persisted
	LeafNodeOffline LeafOutcome = "node-offline" // re-minted but not delivered; retried next sweep
	LeafFailed      LeafOutcome = "failed"
)

// LeafLog is one line the caller decides how to surface: the sweep writes it to
// its job log, the PATCH handler discards all but the error.
type LeafLog struct {
	Level string
	Text  string
}

// LeafResult is the outcome of RotateAppLeaf.
type LeafResult struct {
	Outcome LeafOutcome
	Renewed bool
	Err     error
	Log     []LeafLog
}

// RotateAppLeaf re-mints ONE app's TLS leaf if it needs it and ships it to the
// app's node.
//
// Extracted from the rotation sweep for #197. Changing an app's LAN exposure
// changes its leaf's SAN set, and PrepareAppLeaf already treats a SAN drift as
// a reason to re-mint — so the toggle needs no new machinery, only the ability
// to run one app's rotation NOW rather than waiting up to a sweep interval for
// the .lan name to start or stop resolving. Sharing the body rather than
// copying it is the point: two rotation paths would differ in exactly the
// place that matters, which is what happens when the node is offline.
//
// Never returns an error for an offline node. The fresh leaf is deliberately
// NOT committed in that case, so the sweep re-mints and retries — an app's leaf
// cannot quietly expire on a node that was down, and an exposure change made
// while a node is offline lands when it comes back.
func RotateAppLeaf(ctx context.Context, inv *inventory.Store, nc *nats.Conn, rotate LeafRotator, app *App) LeafResult {
	if rotate == nil || app.PublishedPort == 0 {
		return LeafResult{Outcome: LeafUnchanged}
	}
	cmd, renewed, commit, err := rotate(app)
	if err != nil {
		return LeafResult{Outcome: LeafFailed, Err: fmt.Errorf("re-mint leaf: %w", err),
			Log: []LeafLog{{"warn", fmt.Sprintf("%s: re-mint leaf: %v", app.Name, err)}}}
	}
	if !renewed {
		return LeafResult{Outcome: LeafUnchanged}
	}

	node, err := inv.Get(ctx, app.TargetNode)
	if err != nil || node == nil || computeNodeStatus(node.LastSeen) != proto.StatusOnline {
		return LeafResult{Outcome: LeafNodeOffline, Renewed: true,
			Log: []LeafLog{{"info", fmt.Sprintf("%s: leaf due for rotation but node %s offline — retrying next sweep", app.Name, app.TargetNode)}}}
	}

	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	ok, detail, derr := deliverLeaf(dctx, nc, app.TargetNode, cmd)
	cancel()
	if derr != nil {
		return LeafResult{Outcome: LeafFailed, Renewed: true, Err: fmt.Errorf("deliver leaf: %w", derr),
			Log: []LeafLog{{"warn", fmt.Sprintf("%s: deliver rotated leaf: %v", app.Name, derr)}}}
	}
	if !ok {
		return LeafResult{Outcome: LeafFailed, Renewed: true, Err: fmt.Errorf("node rejected leaf: %s", detail),
			Log: []LeafLog{{"warn", fmt.Sprintf("%s: node rejected rotated leaf: %s", app.Name, detail)}}}
	}

	res := LeafResult{Outcome: LeafShipped, Renewed: true,
		Log: []LeafLog{{"info", fmt.Sprintf("%s: rotated + delivered fresh TLS leaf", app.Name)}}}
	if err := commit(); err != nil {
		// Delivered but not persisted: harmless (the next sweep re-mints and
		// re-ships an equivalent leaf), but worth surfacing.
		res.Log = append(res.Log, LeafLog{"warn", fmt.Sprintf("%s: persist rotated leaf: %v", app.Name, err)})
	}
	return res
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

// isRealDrift decides whether an observed container state is news worth
// overwriting the stored status with.
//
// The sweep exists for one symptom — "the api says running but it isn't" — and
// it used to treat ANY difference as drift. That is wrong twice over, because
// not every stored status is a belief about containers that an observation can
// simply correct.
//
//	IN FLIGHT (deploying, stopping). An operation owns the record while it
//	runs. Mid-deploy the containers legitimately do not exist yet, so the agent
//	answers "stopped" and the old code helpfully reset the row — clobbering a
//	deploy that was still pulling. This was survivable while a deploy was
//	capped at 60s; with proto.AppDeployWork at 300s and this sweep on a 5-minute
//	timer, a long first pull and a sweep now overlap by design.
//
//	A VERDICT (failed). "failed" records what an operation concluded, not what
//	is running. A failed deploy leaves no containers, so the agent reports
//	"stopped" — which CONFIRMS the failure rather than contradicting it. The old
//	code overwrote the verdict and its error detail with a bare "stopped", so
//	the row read as merely un-deployed and the reason was gone. Observed on
//	e3bench 2026-08-23: rows flipped to "reconcile: was failed, observed
//	stopped" about a minute after failing, and the operator was left with no
//	trace of why. Only "running" is genuine news — the app recovered.
//
// Anything else is ordinary drift and is recorded as before.
func isRealDrift(app *App, observed proto.AppStatus, now time.Time) bool {
	if observed == app.LastStatus {
		return false
	}
	switch app.LastStatus {
	case proto.AppStatusDeploying, proto.AppStatusStopping:
		// Leave it alone only while the operation could plausibly still be
		// running. Past that the row is stale, not busy, and refusing to
		// correct it would strand the app in a transitional state forever.
		return now.Sub(app.UpdatedAt) > proto.AppDeployRPC
	case proto.AppStatusFailed:
		return observed == proto.AppStatusRunning
	}
	return true
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
			if !isRealDrift(app, ack.Status, time.Now().UTC()) {
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
			fctx, cancel := detachCtx(sc.Ctx)
			now := time.Now().UTC()
			_ = store.RecordStatus(fctx, app.ID, proto.AppStatusFailed, "deploy rpc: "+err.Error(), now)
			cancel()
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
			fctx, cancel := detachCtx(sc.Ctx)
			now := time.Now().UTC()
			_ = store.RecordStatus(fctx, app.ID, proto.AppStatusFailed, "stop rpc: "+err.Error(), now)
			cancel()
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
			fctx, cancel := detachCtx(sc.Ctx)
			now := time.Now().UTC()
			_ = store.RecordStatus(fctx, app.ID, proto.AppStatusFailed, "stop rpc: "+err.Error(), now)
			cancel()
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

// detachCtx returns a context that survives the cancellation/deadline of the
// request context — which is often the very reason an RPC failed — so a
// terminal-status write still lands. Without this, recording "failed" on an
// already-expired sc.Ctx is a silent no-op (ExecContext returns
// context.DeadlineExceeded and writes nothing), leaving the app stuck showing a
// transitional state (deploying/stopping) forever. Values from sc.Ctx are
// preserved; only the cancellation is dropped, then bounded by a fresh timeout.
func detachCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
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
