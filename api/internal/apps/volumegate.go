package apps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Volumes a compose change would drop (geekdojo/geekdojo-brain#412).
//
// A compose that renames a volume key, or drops the service that mounted it,
// makes `up` exit 0 and mount a new, empty volume. The data stays in the old
// one with nothing mounting it (measured case 3, app-catalog.md §8a.2). Bryce,
// 2026-09-12: "We shouldn't be orphaning anything." So no compose change —
// upgrade, custom edit or re-apply — is applied while it would leave a named
// volume the app has ON DISK undeclared, unless the owner names exactly those
// volumes in deleteVolumes, and then they are removed after `up` succeeds.
//
// What a compose declares is Compose's to say, on the node: the api holds no
// YAML parser (ADR-0006 D4). The agent stages the compose and runs `docker
// compose config --volumes`, and compares that with the app's named volumes
// on disk (docker.volumes.check). Anonymous volumes are not in this gate: they
// have no key to compare, and #413 records every one the app's containers
// mount and removes them when the app is deleted with its data.
//
// Two layers, as a backup run's one-at-a-time rule has (handleStartBackupRun):
//
//   - PUT /api/apps/{id}/compose asks first, so an owner is answered 409 with
//     the list at once. That check is advisory: it can pass and the node
//     change before the job runs, and when it cannot get an answer at all it
//     lets the job run.
//   - The saga's pull step asks again, before it pulls or writes anything,
//     and that answer is the gate. A refusal there changes nothing on the
//     node or the row, exactly as a failed pull does.
//
// Deletion is the last step, after `up` succeeded and the route is in place.
// Before that the change can still fail, and going back re-applies the
// previous compose, which needs those very volumes.

// ComposeChangeSpec is the spec body of app.upgrade and app.edit: the app,
// and the volumes the owner named for deletion with the change. (app.revert
// names its target compose too; see RevertSpec.) Volume names are safe in a
// spec — they say which volume, not what is in it — and a spec is the durable
// record of what the owner asked to have deleted. Decoded strictly, like every
// app spec.
type ComposeChangeSpec struct {
	AppID string `json:"appId"`
	// DeleteVolumes is every named volume, rasp_<appid>_<volume>, the owner
	// asked to delete because this change drops it. Absent means none.
	DeleteVolumes []string `json:"deleteVolumes,omitempty"`
}

func parseComposeChangeSpec(raw json.RawMessage) (*ComposeChangeSpec, error) {
	var spec ComposeChangeSpec
	if err := decodeStrict(raw, &spec); err != nil {
		return nil, err
	}
	if err := checkSpecAppID(spec.AppID); err != nil {
		return nil, err
	}
	if err := ValidateDeleteVolumes(spec.AppID, spec.DeleteVolumes); err != nil {
		return nil, err
	}
	return &spec, nil
}

func composeChangeSpecAppID(raw json.RawMessage) (string, error) {
	spec, err := parseComposeChangeSpec(raw)
	if err != nil {
		return "", err
	}
	return spec.AppID, nil
}

func composeChangeSpecDeleteVolumes(raw json.RawMessage) ([]string, error) {
	spec, err := parseComposeChangeSpec(raw)
	if err != nil {
		return nil, err
	}
	return spec.DeleteVolumes, nil
}

// specDeleteVolumes reads the volumes a compose change's spec names for
// deletion, in the one shape its kind declares.
type specDeleteVolumes func(raw json.RawMessage) ([]string, error)

// ValidateDeleteVolumes applies the rules a deleteVolumes list must pass
// without asking the node: every name is a named volume of appID's own
// project, and none appears twice. The HTTP layer answers a failure with a
// 400, since no state of the node could make it acceptable.
func ValidateDeleteVolumes(appID string, names []string) error {
	seen := make(map[string]bool, len(names))
	var bad []string
	for _, name := range names {
		if seen[name] {
			bad = append(bad, fmt.Sprintf("%s: named twice", name))
			continue
		}
		seen[name] = true
		if reason := proto.RefuseAppDeleteVolumeName(appID, name); reason != "" {
			bad = append(bad, name+": "+reason)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("deleteVolumes refused: %s", strings.Join(bad, "; "))
	}
	return nil
}

// VolumeGateError is a compose change refused because the volumes it drops
// and the volumes the owner named for deletion are not the same set.
type VolumeGateError struct {
	// Dropped is every named volume the app has on disk that the new compose
	// does not declare — what the change would orphan, all of it, whether or
	// not it was named.
	Dropped []proto.AppDroppedVolume
	// Unnamed is the part of Dropped the owner did not name for deletion.
	Unnamed []proto.AppDroppedVolume
	// NotDropped is every name in deleteVolumes the change does not drop:
	// a volume the new compose still declares, or one not on the node.
	NotDropped []string
}

func (e *VolumeGateError) Error() string {
	var parts []string
	if len(e.Unnamed) > 0 {
		vols := make([]string, 0, len(e.Unnamed))
		for _, v := range e.Unnamed {
			vols = append(vols, fmt.Sprintf("%s (volume %q)", v.Name, v.Volume))
		}
		parts = append(parts, fmt.Sprintf("the new compose no longer declares %d volume(s) this app has on disk, so applying it would leave their data orphaned: %s — keep them declared, or name each in deleteVolumes to delete it once the new compose is up",
			len(e.Unnamed), strings.Join(vols, ", ")))
	}
	if len(e.NotDropped) > 0 {
		parts = append(parts, fmt.Sprintf("deleteVolumes names volume(s) this change does not drop — the new compose still declares them, or they are not on the node — and only a volume the change drops is deleted with it: %s",
			strings.Join(e.NotDropped, ", ")))
	}
	return strings.Join(parts, "; ")
}

// GateDroppedVolumes decides a compose change against the volumes it drops.
// It proceeds only when named — the owner's deleteVolumes — is exactly the
// dropped set: every dropped volume named, so nothing is orphaned, and nothing
// named that is not dropped, so a volume the new compose still declares is
// never deleted. nil, or a *VolumeGateError.
func GateDroppedVolumes(dropped []proto.AppDroppedVolume, named []string) error {
	want := make(map[string]bool, len(named))
	for _, n := range named {
		want[n] = true
	}
	e := &VolumeGateError{Dropped: sortedDropped(dropped)}
	drops := make(map[string]bool, len(dropped))
	for _, v := range e.Dropped {
		drops[v.Name] = true
		if !want[v.Name] {
			e.Unnamed = append(e.Unnamed, v)
		}
	}
	for _, n := range named {
		if !drops[n] {
			e.NotDropped = append(e.NotDropped, n)
		}
	}
	sort.Strings(e.NotDropped)
	if len(e.Unnamed) == 0 && len(e.NotDropped) == 0 {
		return nil
	}
	return e
}

func sortedDropped(d []proto.AppDroppedVolume) []proto.AppDroppedVolume {
	out := append([]proto.AppDroppedVolume(nil), d...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// DroppedByDeclared is the dropped set computed in the api from two lists it
// already has: the app's named volumes as a node's docker.volumes.list
// reported them, and the volume keys a compose declares. The catalog upgrade's
// advisory check uses it with its tile's tile.json declarations, which the
// catalog lint requires to classify every named volume of the tile's compose
// (rasputin-app-catalog internal/compose/volumes.go), so no compose is parsed
// here. The saga does not use it: its answer comes from Compose on the node.
func DroppedByDeclared(appID string, onNode []proto.AppVolumeInfo, declared []string) []proto.AppDroppedVolume {
	keys := make(map[string]bool, len(declared))
	for _, k := range declared {
		keys[k] = true
	}
	var dropped []proto.AppDroppedVolume
	for _, v := range onNode {
		if v.Anonymous || !strings.EqualFold(v.AppID, appID) {
			continue
		}
		owner, key, ok := proto.ParseAppVolumeName(v.Name)
		if !ok || !strings.EqualFold(owner, appID) || keys[key] {
			continue
		}
		dropped = append(dropped, proto.AppDroppedVolume{Name: v.Name, Volume: key})
	}
	return sortedDropped(dropped)
}

// DroppedVolumesOnNode asks app's node which of the app's named volumes on
// disk compose does not declare (docker.volumes.check). An error means there
// is no answer — the node is offline, its agent predates the verb (inventory
// says which), or Compose could not read the compose — never that nothing is
// dropped.
func DroppedVolumesOnNode(ctx context.Context, inv *inventory.Store, nc *nats.Conn, app *App, compose string) ([]proto.AppDroppedVolume, error) {
	payload, err := json.Marshal(proto.AppVolumesCheckCmd{AppID: app.ID, ComposeYAML: compose})
	if err != nil {
		return nil, fmt.Errorf("encode volumes check: %w", err)
	}
	rctx, cancel := context.WithTimeout(ctx, proto.AppVolumesCheckRPC)
	defer cancel()
	subject := proto.AppVolumesCheckSubject(app.TargetNode)
	msg, err := nc.RequestWithContext(rctx, subject, payload)
	switch {
	case errors.Is(err, nats.ErrNoResponders):
		ictx, icancel := detachCtx(ctx)
		defer icancel()
		return nil, errors.New(inv.ExplainNoResponder(ictx, subject).String())
	case err != nil:
		return nil, fmt.Errorf("volumes check rpc: %w", err)
	}
	var ack proto.AppVolumesCheckAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		return nil, fmt.Errorf("decode volumes check ack: %w", err)
	}
	if !ack.OK {
		if ack.Detail == "" {
			ack.Detail = "agent reported the volumes check failed"
		}
		return nil, errors.New(ack.Detail)
	}
	return sortedDropped(ack.Dropped), nil
}

// dropVolumesResult is the drop step's recorded result: names only.
type dropVolumesResult struct {
	AppID   string                   `json:"appId"`
	Removed []string                 `json:"removed"`
	Refused []proto.AppVolumeRefusal `json:"refused"`
	Detail  string                   `json:"detail,omitempty"`
}

// dropVolumesStep is the last step of every compose change: remove the
// volumes the pull step's gate confirmed the change drops and the owner named.
//
// It runs only when every step before it succeeded, so only after `up` did —
// the push step fails the job on a failed `up`, and the saga stops there. The
// volumes are removed by the agent's docker.volumes.drop, which refuses any
// volume the app's compose on the node still declares and then goes through
// the removal gates the orphan reaper and the delete-with-data sweep share.
//
// A refusal fails the job naming each volume and why, and changes nothing
// else: the new compose is already up and stays up, and a volume that was not
// removed is still on the node, still the app's, and removed with its data if
// the app is deleted (#413).
func dropVolumesStep(store *Store, inv *inventory.Store, nc *nats.Conn, appID specAppID) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		pulled, err := pulledCompose(sc)
		if err != nil {
			return nil, err
		}
		if len(pulled.DeleteVolumes) == 0 {
			sc.Log("info", "no volumes were named for deletion")
			return nil, nil
		}
		app, err := loadAppFor(sc, store, inv, appID)
		if err != nil {
			return nil, fmt.Errorf("the new compose is up, but the volumes named for deletion were not removed: %w", err)
		}
		payload, err := json.Marshal(proto.AppVolumesDropCmd{AppID: app.ID, Names: pulled.DeleteVolumes})
		if err != nil {
			return nil, err
		}
		rctx, cancel := context.WithTimeout(sc.Ctx, 70*time.Second)
		defer cancel()
		subject := proto.AppVolumesDropSubject(app.TargetNode)
		msg, err := nc.RequestWithContext(rctx, subject, payload)
		if err != nil {
			reason := err.Error()
			if errors.Is(err, nats.ErrNoResponders) {
				ictx, icancel := detachCtx(sc.Ctx)
				reason = inv.ExplainNoResponder(ictx, subject).String()
				icancel()
			}
			return nil, fmt.Errorf("the new compose is up, but the volumes named for deletion were not removed (%s): %s",
				strings.Join(pulled.DeleteVolumes, ", "), reason)
		}
		var ack proto.AppVolumesRemoveAck
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			return nil, fmt.Errorf("the new compose is up; decode the volume removal ack: %w", err)
		}
		res := dropVolumesResult{AppID: app.ID, Removed: ack.Removed, Refused: ack.Refused, Detail: ack.Detail}
		if res.Removed == nil {
			res.Removed = []string{}
		}
		if res.Refused == nil {
			res.Refused = []proto.AppVolumeRefusal{}
		}
		if len(res.Removed) > 0 {
			sc.Log("info", "deleted the volume(s) the change dropped: "+strings.Join(res.Removed, ", "))
		}
		if ack.Detail != "" {
			sc.Log("info", ack.Detail)
		}
		out, _ := json.Marshal(res)
		if len(res.Refused) > 0 || !ack.OK {
			reasons := make([]string, 0, len(res.Refused))
			for _, r := range res.Refused {
				reasons = append(reasons, r.Name+": "+r.Reason)
			}
			return out, fmt.Errorf("the new compose is up, but %d volume(s) named for deletion were not removed, and are still on the node: %s",
				len(res.Refused), strings.Join(reasons, "; "))
		}
		return out, nil
	}
}
