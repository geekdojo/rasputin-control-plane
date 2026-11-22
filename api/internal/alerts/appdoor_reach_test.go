package alerts

import (
	"context"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-984-09: with no app-door source set, List succeeds without its alert;
// with one set, its alert is in the snapshot in the severity/Since order, and
// the source gets List's ctx and the injected clock's now.
func TestList_AppDoorReachAlertsHook(t *testing.T) {
	f := newFixture(t)
	f.markSetupComplete(t)
	f.insertFailedJob(t, "j1", "apps.deploy", "The deploy failed.", 2*time.Hour)
	// After the job failure (the fixture stamps it two hours before the wall clock).
	fixed := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	f.svc.SetNow(func() time.Time { return fixed })

	quiet, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got := alertIDs(quiet); len(got) != 1 || got[0] != "job-failed:j1" {
		t.Fatalf("List ids with no source = %v, want only job-failed:j1", got)
	}

	type ctxKey struct{}
	ctx := context.WithValue(f.ctx, ctxKey{}, "list")
	var gotCtx context.Context
	var gotNow time.Time
	f.svc.SetAppDoorReachAlerts(func(c context.Context, now time.Time) []proto.Alert {
		gotCtx, gotNow = c, now
		return []proto.Alert{{ID: "app-signin-unjoined", Severity: proto.AlertWarn, Source: proto.AlertSourceNode,
			Title: "App sign-in is not reachable over your private network yet: the control plane has not joined it.", Since: now}}
	})
	loud, err := f.svc.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	// Both warn: the older job failure sorts first.
	if got := alertIDs(loud); len(got) != 2 || got[0] != "job-failed:j1" || got[1] != "app-signin-unjoined" {
		t.Fatalf("List ids = %v, want job-failed:j1 then app-signin-unjoined", got)
	}
	if gotCtx != ctx || !gotNow.Equal(fixed) {
		t.Fatalf("the source got ctx %v and now %v, want List's ctx and %v", gotCtx, gotNow, fixed)
	}
}
