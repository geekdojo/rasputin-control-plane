package alerts

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// #398's alert path against a scripted target-health source: one crit alert
// per unhealthy claimed target, raised once with a stable id, the same alert
// on the next read, gone on the next healthy poll, nothing for unknown.

type fakeBackupTargets struct {
	reports []proto.BackupTargetHealthReport
	err     error
}

func (f *fakeBackupTargets) ClaimedTargetHealth(context.Context) ([]proto.BackupTargetHealthReport, error) {
	return f.reports, f.err
}

func targetReport(state proto.BackupTargetHealthState, sinceAgo time.Duration, detail string) proto.BackupTargetHealthReport {
	now := time.Now().UTC()
	return proto.BackupTargetHealthReport{
		PartUUID: "part-uuid-1", Label: "e3bench-backup", NodeID: "cp-1",
		Health: proto.BackupTargetHealth{State: state, CheckedAt: now.Add(-time.Minute), Since: now.Add(-sinceAgo), Detail: detail},
	}
}

func targetAlertsOf(alerts []proto.Alert) []proto.Alert {
	var out []proto.Alert
	for _, a := range alerts {
		if strings.HasPrefix(a.ID, "backup-target:") {
			out = append(out, a)
		}
	}
	return out
}

func TestBackupTargetAlerts_RaiseOnceResolveOnOK(t *testing.T) {
	f := newFixture(t)
	f.markSetupComplete(t)
	src := &fakeBackupTargets{reports: []proto.BackupTargetHealthReport{
		targetReport(proto.BackupTargetHealthMissing, 3*time.Hour, "nothing attached to cp-1 carries partition UUID part-uuid-1; a DIFFERENT disk is at /dev/sda now"),
	}}
	f.svc.SetBackupTargets(src)

	first, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := targetAlertsOf(first)
	if len(got) != 1 {
		t.Fatalf("target alerts = %+v, want exactly one", got)
	}
	a := got[0]
	if a.ID != "backup-target:part-uuid-1" || a.Severity != proto.AlertCrit {
		t.Errorf("alert = %+v; want id keyed by partition UUID and crit — every backup will fail", a)
	}
	for _, want := range []string{"e3bench-backup", "MISSING", "3h", "every backup will fail"} {
		if !strings.Contains(a.Title, want) {
			t.Errorf("title %q does not say %q", a.Title, want)
		}
	}
	if !strings.Contains(a.Detail, "DIFFERENT disk") {
		t.Errorf("detail %q is not the probe's finding", a.Detail)
	}
	if a.RelatedKind != "node" || a.RelatedID != "cp-1" {
		t.Errorf("related = %s/%s, want the node holding the disk", a.RelatedKind, a.RelatedID)
	}
	if time.Since(a.Since) < 2*time.Hour {
		t.Errorf("since = %s, want when the state was first observed", a.Since)
	}

	// Same read again: the same alert, not a second one.
	second, _ := f.svc.List(f.ctx)
	if got2 := targetAlertsOf(second); len(got2) != 1 || got2[0].ID != a.ID {
		t.Errorf("second read = %+v, want the same single alert", got2)
	}

	// The next poll finds it healthy: gone, no operator action.
	src.reports = []proto.BackupTargetHealthReport{targetReport(proto.BackupTargetHealthOK, time.Minute, "wrote, read back, deleted")}
	third, _ := f.svc.List(f.ctx)
	if got3 := targetAlertsOf(third); len(got3) != 0 {
		t.Errorf("alert still present after a healthy poll: %+v", got3)
	}
}

func TestBackupTargetAlerts_EveryFailingStateIsCritAndUnknownIsNothing(t *testing.T) {
	f := newFixture(t)
	f.markSetupComplete(t)
	src := &fakeBackupTargets{}
	f.svc.SetBackupTargets(src)
	for _, st := range []proto.BackupTargetHealthState{
		proto.BackupTargetHealthMissing, proto.BackupTargetHealthUnmounted,
		proto.BackupTargetHealthUnwritable, proto.BackupTargetHealthUnreachable,
	} {
		src.reports = []proto.BackupTargetHealthReport{targetReport(st, time.Hour, "d")}
		got := targetAlertsOf(mustList(t, f))
		if len(got) != 1 || got[0].Severity != proto.AlertCrit || !strings.Contains(got[0].Title, strings.ToUpper(string(st))) {
			t.Errorf("%s: alerts = %+v, want one crit naming the state", st, got)
		}
	}
	src.reports = []proto.BackupTargetHealthReport{{PartUUID: "p", Label: "x", NodeID: "n", Health: proto.BackupTargetHealth{State: proto.BackupTargetHealthUnknown}}}
	if got := targetAlertsOf(mustList(t, f)); len(got) != 0 {
		t.Errorf("an unpolled target raised %+v; nothing was found yet", got)
	}
}

func TestBackupTargetAlerts_NoSourceOrErrorSource(t *testing.T) {
	f := newFixture(t)
	f.markSetupComplete(t)
	if got := targetAlertsOf(mustList(t, f)); len(got) != 0 {
		t.Errorf("alerts with no source wired: %+v", got)
	}
	f.svc.SetBackupTargets(&fakeBackupTargets{err: errors.New("ledger closed")})
	if _, err := f.svc.List(f.ctx); err == nil || !strings.Contains(err.Error(), "backup targets") {
		t.Errorf("a failing source should fail the read loudly, got %v", err)
	}
}

func mustList(t *testing.T, f *fixture) []proto.Alert {
	t.Helper()
	out, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
