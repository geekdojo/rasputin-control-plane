package apps

import (
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

// DeploySpec is the spec body of an app.deploy job.
type DeploySpec struct {
	AppID string `json:"appId"`
}

// DeployWorkflow drives the deploy saga:
//
//   1. load     — look up the app, validate target node is online
//   2. push     — RPC the target agent's docker.deploy handler
//   3. confirm  — agent's ack persists; emit a change event
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
		// transition immediately.
		now := time.Now().UTC()
		_ = store.RecordStatus(sc.Ctx, app.ID, proto.AppStatusDeploying, "", now)

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

		now := time.Now().UTC()
		_ = store.RecordStatus(sc.Ctx, app.ID, proto.AppStatusStopping, "", now)

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
