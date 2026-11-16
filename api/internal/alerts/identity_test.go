package alerts

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-979-22: with no identity source set, List succeeds with no identity
// alert; with one set, its alert is in the sorted snapshot, and the source
// gets List's ctx and now.
func TestList_IdentityAlertsHook(t *testing.T) {
	f := newFixture(t)
	f.markSetupComplete(t)
	f.insertFailedJob(t, "j1", "apps.deploy", "The deploy failed.", 2*time.Hour)
	fixed := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	f.svc.SetNow(func() time.Time { return fixed })

	quiet, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, a := range quiet {
		if strings.HasPrefix(a.ID, "identity:") {
			t.Fatalf("an unwired identity source added %+v", a)
		}
	}

	type ctxKey struct{}
	ctx := context.WithValue(f.ctx, ctxKey{}, "list")
	var gotCtx context.Context
	var gotNow time.Time
	f.svc.SetIdentityAlerts(func(c context.Context, now time.Time) []proto.Alert {
		gotCtx, gotNow = c, now
		return []proto.Alert{{ID: "identity:database-down", Severity: proto.AlertCrit, Source: proto.AlertSourceSecurity,
			Title: "Sign-in is unavailable because its database is not running.", Since: now}}
	})
	loud, err := f.svc.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got := alertIDs(loud); len(got) != 2 || got[0] != "identity:database-down" || got[1] != "job-failed:j1" {
		t.Fatalf("List ids = %v, want the identity crit before the job-failed warn", got)
	}
	if gotCtx != ctx || !gotNow.Equal(fixed) {
		t.Fatalf("the source got ctx %v and now %v, want List's ctx and %v", gotCtx, gotNow, fixed)
	}
}
