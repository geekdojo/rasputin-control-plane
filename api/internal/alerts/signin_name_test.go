package alerts

import (
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/signinname"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-995-17 (alerts half): with no sign-in name source, List carries none of
// its alerts; with one set, its alert is in the snapshot, source security,
// and the source gets the injected clock's now.
func TestList_SigninNameAlertsHook(t *testing.T) {
	f := newFixture(t)
	f.markSetupComplete(t)
	fixed := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	f.svc.SetNow(func() time.Time { return fixed })

	quiet, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got := alertIDs(quiet); len(got) != 0 {
		t.Fatalf("List ids with no source = %v, want none", got)
	}

	// A real responder's source: a refused one, which needs no socket.
	r := signinname.NewRefused("sso-bench", proto.ErrClusterIDReservedPrefix, signinname.SystemClock{})
	var gotNow time.Time
	f.svc.SetSigninNameAlerts(func(now time.Time) []proto.Alert {
		gotNow = now
		return r.Alerts(now)
	})
	loud, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(loud) != 1 || loud[0].ID != signinname.AlertRefused || loud[0].Source != proto.AlertSourceSecurity || loud[0].Severity != proto.AlertCrit {
		t.Fatalf("List = %+v, want the sign-in name alert", loud)
	}
	if !gotNow.Equal(fixed) {
		t.Fatalf("the source got now %v, want %v", gotNow, fixed)
	}
}
