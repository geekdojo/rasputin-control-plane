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
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Deleting an app WITH its data names the data.
//
// app.delete's deleteVolumes is the exact list of volume names the operator
// confirmed, never a flag. The node's agent removes every volume the app has
// when it is told to delete data (#413: `compose down -v`, then by exact name
// what that cannot see), so the list the operator confirmed has to be that
// whole set: a name the app does not have is refused, and a volume the app has
// that the list leaves out is refused too, because it would be deleted without
// anyone having been shown its name.
//
// The set is re-derived at commit, not trusted from the request. The HTTP
// handler checks it against the node before it queues the job, and the saga
// checks it again after the app's containers are down — the point from which
// no container of the app exists to create a volume, and the agent has
// recorded every anonymous volume one of them mounted (appvolumes.go in the
// agent). Only then is the stop that deletes data sent.

// appVolumesListRPC bounds one docker.volumes.list round trip with sizes
// skipped: a `docker volume ls`, the inspects and the agent's per-app records,
// none of which walks a volume's files.
const appVolumesListRPC = 20 * time.Second

// ValidateAppDeleteVolumeNames applies the rules an app.delete deleteVolumes
// list must pass without asking the node: every name is one of appID's named
// volumes (rasp_<appid>_<volume>) or an anonymous volume's 64-hex name, and
// none appears twice. Which anonymous volumes are the app's is the node's to
// say; CompareDeleteVolumes checks that.
func ValidateAppDeleteVolumeNames(appID string, names []string) error {
	seen := make(map[string]bool, len(names))
	var bad []string
	for _, name := range names {
		if seen[name] {
			bad = append(bad, fmt.Sprintf("%s: named twice", name))
			continue
		}
		seen[name] = true
		if proto.IsAnonymousVolumeName(name) {
			continue
		}
		owner, _, ok := proto.ParseAppVolumeName(name)
		switch {
		case !ok:
			bad = append(bad, fmt.Sprintf("%s: not a volume of this app: the name is neither of the form %s_<volume> nor an anonymous volume's 64-hex name", name, proto.AppProjectName(appID)))
		case !strings.EqualFold(owner, appID):
			bad = append(bad, fmt.Sprintf("%s: a volume of app %s, not of this app (%s)", name, owner, strings.ToUpper(appID)))
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("deleteVolumes refused: %s", strings.Join(bad, "; "))
	}
	return nil
}

// DeleteVolumesMismatch is a deleteVolumes list that is not exactly the
// volumes the app has on its node.
type DeleteVolumesMismatch struct {
	// NotOfApp is every named entry the node does not list as the app's.
	NotOfApp []string
	// Unconfirmed is every volume the app has on the node that the list does
	// not name — each would be deleted without its name having been shown.
	Unconfirmed []proto.AppVolumeInfo
	// OnNode is every volume the app has on the node: the list a client
	// resubmitting must send.
	OnNode []proto.AppVolumeInfo
}

func (m *DeleteVolumesMismatch) Error() string {
	var parts []string
	if len(m.NotOfApp) > 0 {
		parts = append(parts, "deleteVolumes names volume(s) this app does not have on its node: "+strings.Join(m.NotOfApp, ", "))
	}
	if len(m.Unconfirmed) > 0 {
		names := make([]string, 0, len(m.Unconfirmed))
		for _, v := range m.Unconfirmed {
			names = append(names, v.Name)
		}
		parts = append(parts, fmt.Sprintf("deleting this app's data removes every volume it has on its node, and deleteVolumes does not name %d of them: %s — name each one to delete them, or send no deleteVolumes to keep them all",
			len(names), strings.Join(names, ", ")))
	}
	return strings.Join(parts, "; ")
}

// CompareDeleteVolumes checks named against the volumes the node lists for
// appID. It returns nil when they are the same set, and a
// *DeleteVolumesMismatch otherwise. onNode may hold other apps' volumes; only
// appID's count.
func CompareDeleteVolumes(appID string, named []string, onNode []proto.AppVolumeInfo) error {
	mine := OwnVolumes(appID, onNode)
	have := make(map[string]bool, len(mine))
	for _, v := range mine {
		have[v.Name] = true
	}
	want := make(map[string]bool, len(named))
	m := &DeleteVolumesMismatch{OnNode: mine}
	for _, n := range named {
		want[n] = true
		if !have[n] {
			m.NotOfApp = append(m.NotOfApp, n)
		}
	}
	for _, v := range mine {
		if !want[v.Name] {
			m.Unconfirmed = append(m.Unconfirmed, v)
		}
	}
	if len(m.NotOfApp) == 0 && len(m.Unconfirmed) == 0 {
		return nil
	}
	sort.Strings(m.NotOfApp)
	return m
}

// OwnVolumes is the subset of a node listing that belongs to appID, sorted by
// name.
func OwnVolumes(appID string, vols []proto.AppVolumeInfo) []proto.AppVolumeInfo {
	out := []proto.AppVolumeInfo{}
	for _, v := range vols {
		if strings.EqualFold(v.AppID, appID) {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// AppVolumesOnNode asks nodeID's agent for the Rasputin-managed volumes on it,
// sizes skipped, and returns appID's. Silence is explained against the node's
// inventory row, as every other volumes verb explains it.
func AppVolumesOnNode(ctx context.Context, inv *inventory.Store, nc *nats.Conn, nodeID, appID string) ([]proto.AppVolumeInfo, error) {
	payload, err := json.Marshal(proto.AppVolumesListCmd{SkipSizes: true})
	if err != nil {
		return nil, fmt.Errorf("encode volumes list: %w", err)
	}
	rctx, cancel := context.WithTimeout(ctx, appVolumesListRPC)
	defer cancel()
	subject := proto.AppVolumesListSubject(nodeID)
	msg, err := nc.RequestWithContext(rctx, subject, payload)
	switch {
	case errors.Is(err, nats.ErrNoResponders):
		ictx, icancel := detachCtx(ctx)
		defer icancel()
		return nil, errors.New(inv.ExplainNoResponder(ictx, subject).String())
	case err != nil:
		return nil, fmt.Errorf("volumes list rpc: %w", err)
	}
	var ack proto.AppVolumesListAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		return nil, fmt.Errorf("decode volumes list ack: %w", err)
	}
	if !ack.OK {
		if ack.Detail == "" {
			ack.Detail = "agent reported the volumes list failed"
		}
		return nil, errors.New(ack.Detail)
	}
	return OwnVolumes(appID, ack.Volumes), nil
}
