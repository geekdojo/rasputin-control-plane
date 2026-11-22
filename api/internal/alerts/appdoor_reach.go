package alerts

import (
	"context"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// SetAppDoorReachAlerts wires the app-signin-unjoined warning
// (mesh.Service.AppDoorReachAlerts, geekdojo/geekdojo-brain#984). Set before
// List. A func, like SetDiskAlerts, so this package does not depend on mesh;
// it takes List's ctx because it reads the mesh device table.
func (s *Service) SetAppDoorReachAlerts(fn func(ctx context.Context, now time.Time) []proto.Alert) {
	s.appDoorReachAlerts = fn
}
