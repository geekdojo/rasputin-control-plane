package apps

import (
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

func TestIsRealDrift(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-10 * time.Second)                 // an operation still plausibly running
	stale := now.Add(-proto.AppDeployRPC - time.Minute) // long past any deploy window

	cases := []struct {
		name     string
		last     proto.AppStatus
		updated  time.Time
		observed proto.AppStatus
		want     bool
		why      string
	}{
		// The bug this file exists for. A failed deploy leaves no containers,
		// so the agent says "stopped" — which agrees with the verdict rather
		// than contradicting it. Recording it destroyed the error detail and
		// left the row looking merely un-deployed.
		{"failed stays failed when observed stopped", proto.AppStatusFailed, fresh, proto.AppStatusStopped, false,
			"observing stopped CONFIRMS a failed deploy; overwriting it erases why it failed"},
		{"failed stays failed when observed unknown", proto.AppStatusFailed, fresh, proto.AppStatusUnknown, false,
			"unknown is not evidence the failure was wrong"},
		{"failed yields to a genuine recovery", proto.AppStatusFailed, fresh, proto.AppStatusRunning, true,
			"running IS news — the containers came up after all"},

		// In-flight operations own the record. Newly load-bearing: a 300s deploy
		// budget and a 5-minute sweep overlap by design.
		{"deploying is left alone mid-flight", proto.AppStatusDeploying, fresh, proto.AppStatusStopped, false,
			"containers legitimately do not exist yet while the image is still pulling"},
		{"stopping is left alone mid-flight", proto.AppStatusStopping, fresh, proto.AppStatusRunning, false,
			"the stop is still in progress"},
		{"a stale deploying row is corrected", proto.AppStatusDeploying, stale, proto.AppStatusStopped, true,
			"past the deploy window it is stuck, not busy — never correcting it strands the app"},

		// The symptom the sweep was built for (the api says running but it isn't).
		{"running to stopped is real drift", proto.AppStatusRunning, fresh, proto.AppStatusStopped, true, ""},
		{"running to failed is real drift", proto.AppStatusRunning, fresh, proto.AppStatusFailed, true, ""},
		{"stopped to running is real drift", proto.AppStatusStopped, fresh, proto.AppStatusRunning, true, ""},

		{"no change is not drift", proto.AppStatusRunning, fresh, proto.AppStatusRunning, false, ""},
		{"failed observed failed is not drift", proto.AppStatusFailed, fresh, proto.AppStatusFailed, false, ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			app := &App{LastStatus: c.last, UpdatedAt: c.updated}
			if got := isRealDrift(app, c.observed, now); got != c.want {
				t.Errorf("isRealDrift(last=%s, observed=%s) = %v, want %v\n%s",
					c.last, c.observed, got, c.want, c.why)
			}
		})
	}
}
