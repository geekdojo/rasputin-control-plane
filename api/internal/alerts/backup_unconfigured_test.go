package alerts

import (
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// design/storage.md §4.4's persistent nag (#299), executed against a
// scripted per-app derivation: raised once with a stable id for a critical
// app while backups are unconfigured, unchanged on the next read, gone the
// moment the app's state says a target exists, warn and never crit, never
// beside an OVERDUE alert for the same app, and silent for an app with only
// `state` volumes.

func unconfiguredApp(id, name, class string) proto.AppBackupStatus {
	st := proto.AppBackupStatus{AppID: id, AppName: name}
	st.State = proto.AppBackupUnconfigured
	st.Class = class
	st.Reason = "no backup target is claimed, so nothing on this cluster is backed up anywhere. Claim a disk under Storage → Backups"
	return st
}

func unconfiguredAlertsOf(alerts []proto.Alert) []proto.Alert {
	var out []proto.Alert
	for _, a := range alerts {
		if strings.HasPrefix(a.ID, backupUnconfiguredID) {
			out = append(out, a)
		}
	}
	return out
}

func TestBackupUnconfigured_RaiseOnceResolveWhenConfigured(t *testing.T) {
	f := newFixture(t)
	f.markSetupComplete(t)
	src := &fakeBackupStates{states: []proto.AppBackupStatus{unconfiguredApp("app-vw", "vaultwarden", "critical")}}
	f.svc.SetBackupStates(src)

	first, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := unconfiguredAlertsOf(first)
	if len(got) != 1 {
		t.Fatalf("unconfigured alerts = %+v, want exactly one", got)
	}
	a := got[0]
	if a.ID != "backup-unconfigured:app-vw" || a.Severity != proto.AlertWarn || a.Source != proto.AlertSourceApp {
		t.Errorf("alert = %+v; want warn, source app, id keyed by app", a)
	}
	if !strings.Contains(a.Title, "vaultwarden has no backup target") || !strings.Contains(a.Title, "not protected") {
		t.Errorf("title %q must say the app has no backup target and is not protected", a.Title)
	}
	if !strings.Contains(a.Detail, "/storage") || !strings.Contains(a.Detail, "Claim a disk") {
		t.Errorf("detail %q must carry the derivation's reason and the way through (/storage)", a.Detail)
	}
	if a.RelatedKind != "app" || a.RelatedID != "app-vw" {
		t.Errorf("drill-through = %s/%s, want app/app-vw", a.RelatedKind, a.RelatedID)
	}
	if len(backupAlertsOf(first)) != 0 {
		t.Errorf("an unconfigured app must never also carry OVERDUE: %+v", backupAlertsOf(first))
	}

	// The second tick is the same alert, not a second one.
	second, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again := unconfiguredAlertsOf(second); len(again) != 1 || again[0].ID != a.ID {
		t.Errorf("second read = %+v; must be the same single alert", again)
	}

	// A target is claimed and the schedule is on: the derivation moves the
	// app to `never` (first run still ahead) and the nag is gone on its own.
	src.states[0].State = proto.AppBackupNever
	src.states[0].Reason = "not backed up yet"
	third, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if left := unconfiguredAlertsOf(third); len(left) != 0 {
		t.Errorf("once configured the alert must be gone; got %+v", left)
	}
	if src.calls != 3 {
		t.Errorf("derivation called %d times, want once per read — the nag must ride the same read as OVERDUE", src.calls)
	}
}

func TestBackupUnconfigured_WarnOnlyAndCriticalOnly(t *testing.T) {
	f := newFixture(t)
	f.markSetupComplete(t)
	f.svc.SetBackupStates(&fakeBackupStates{states: []proto.AppBackupStatus{
		unconfiguredApp("app-vw", "vaultwarden", "critical"),
		unconfiguredApp("app-im", "immich", "state"),
		unconfiguredApp("app-none", "custom", ""),
	}})
	all, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := unconfiguredAlertsOf(all)
	if len(got) != 1 {
		t.Fatalf("unconfigured alerts = %+v, want one — only the critical app raises", got)
	}
	if got[0].ID != "backup-unconfigured:app-vw" {
		t.Errorf("alert = %+v, want the critical app's", got[0])
	}
	if got[0].Severity != proto.AlertWarn {
		t.Errorf("severity = %s, want warn: nothing was due, so this is not #298's crit", got[0].Severity)
	}
	for _, a := range all {
		if a.Severity == proto.AlertCrit && strings.HasPrefix(a.ID, "backup-") {
			t.Errorf("no backup alert may be crit while nothing is overdue: %+v", a)
		}
	}
}

func TestBackupUnconfigured_OtherStatesRaiseNothing(t *testing.T) {
	f := newFixture(t)
	f.markSetupComplete(t)
	mk := func(id string, state proto.AppBackupStateKind) proto.AppBackupStatus {
		st := proto.AppBackupStatus{AppID: id, AppName: id}
		st.State = state
		st.Class = "critical"
		return st
	}
	f.svc.SetBackupStates(&fakeBackupStates{states: []proto.AppBackupStatus{
		mk("ok", proto.AppBackupOK),
		mk("never", proto.AppBackupNever),
		mk("none", proto.AppBackupNone),
	}})
	all, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := unconfiguredAlertsOf(all); len(got) != 0 {
		t.Errorf("non-unconfigured states raised %+v", got)
	}
	_ = time.Now
}
