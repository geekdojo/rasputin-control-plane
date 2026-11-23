package alerts

import (
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// SetSigninNameAlerts wires the home sign-in name's alerts
// (signinname.Responder.Alerts, geekdojo/geekdojo-brain#995): the conflict,
// unpublished and refused alerts, computed on read. Set before List. A func,
// like SetDiskAlerts, so this package does not depend on signinname.
func (s *Service) SetSigninNameAlerts(fn func(now time.Time) []proto.Alert) {
	s.signinNameAlerts = fn
}
