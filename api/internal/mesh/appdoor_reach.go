package mesh

import (
	"context"
	"fmt"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// appDoorReachAlertID is the warning raised while app sign-in has no
// private-network record because the control plane has not joined.
const appDoorReachAlertID = "app-signin-unjoined"

// AppDoorReachAlerts is the app-signin-unjoined warning, computed when the
// alerts list is read (geekdojo/geekdojo-brain#984). It is up while the doors
// are on and the control plane has no single bound device with a tailnet IP
// (selfDevice): unbound, no device, no tailnet IP, or bound to two devices.
// In each of those states the door's record is absent. The bind (enrollRecord's
// BindDevice) clears it on the next read; an unbind or a deleted device raises
// it again. It does not cover a bound device that is offline on the tailnet.
func (s *Service) AppDoorReachAlerts(ctx context.Context, now time.Time) []proto.Alert {
	if s.cfg.AppDoorHost == "" || s.cfg.SelfNodeID == "" {
		return nil
	}
	devices, err := s.store.ListDevices(ctx)
	if err != nil {
		// Saying "not joined" without having looked would be untrue, and
		// failing the whole alerts list would hide every other alert, so the
		// check is skipped and the reason logged.
		s.cfg.Log.WarnContext(ctx, "app sign-in reach not checked: mesh devices unreadable",
			"node_id", s.cfg.SelfNodeID, "err", err)
		return nil
	}
	bound, _ := BoundDevices(devices)
	if s.selfDevice(bound) != nil {
		return nil
	}
	return []proto.Alert{{
		ID:          appDoorReachAlertID,
		Severity:    proto.AlertWarn,
		Source:      proto.AlertSourceNode,
		Title:       "App sign-in is not reachable over your private network yet: the control plane has not joined it.",
		Detail:      fmt.Sprintf("The control plane joins its private network on its own. If this warning stays, the newest mesh.enroll_node task for %s says why.", s.cfg.SelfNodeID),
		Since:       now,
		RelatedKind: "node",
		RelatedID:   s.cfg.SelfNodeID,
	}}
}

// AppDoorOnline reports whether the app sign-in door is reachable over the
// private network now (geekdojo/geekdojo-brain#986, the app door's
// rasputin_signin_door_up fact): the doors are on, the control plane has its
// one bound device with a tailnet IP (selfDevice, as the door's record needs),
// and that device was online at a reconcile younger than MembershipMaxAge
// (membershipAt, the one place "on the mesh" is decided). With no current
// observation it reads false. A devices read error is returned.
func (s *Service) AppDoorOnline(ctx context.Context) (bool, error) {
	return s.appDoorOnlineAt(ctx, time.Now().UTC())
}

// appDoorOnlineAt is AppDoorOnline with the clock injected; see the tests.
func (s *Service) appDoorOnlineAt(ctx context.Context, now time.Time) (bool, error) {
	if s.cfg.AppDoorHost == "" || s.cfg.SelfNodeID == "" {
		return false, nil
	}
	devices, err := s.store.ListDevices(ctx)
	if err != nil {
		return false, fmt.Errorf("mesh devices: %w", err)
	}
	bound, _ := BoundDevices(devices)
	if s.selfDevice(bound) == nil {
		return false, nil
	}
	m := s.membershipAt(ctx, now)[s.cfg.SelfNodeID]
	return m != nil && m.Online, nil
}
