package alerts

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// design/storage.md §4.4's alert path (#298), executed against a scripted
// per-app derivation: raised once with a stable id, unchanged on the next
// read, gone the moment the app's state is no longer overdue, and crit or
// warn by the app's §4.2 class.

type fakeBackupStates struct {
	states []proto.AppBackupStatus
	err    error
	calls  int
}

func (f *fakeBackupStates) AppBackupStates(context.Context) ([]proto.AppBackupStatus, error) {
	f.calls++
	return f.states, f.err
}

func overdueApp(id, name, class string, lastSuccessAgo time.Duration, reason string) proto.AppBackupStatus {
	now := time.Now().UTC()
	st := proto.AppBackupStatus{AppID: id, AppName: name}
	st.State = proto.AppBackupOverdue
	st.Class = class
	st.Reason = reason
	since := now.Add(-2 * time.Hour)
	st.OverdueSince = &since
	if lastSuccessAgo > 0 {
		t := now.Add(-lastSuccessAgo)
		st.LastSuccessAt = &t
	}
	return st
}

func backupAlertsOf(alerts []proto.Alert) []proto.Alert {
	var out []proto.Alert
	for _, a := range alerts {
		if strings.HasPrefix(a.ID, "backup-overdue:") {
			out = append(out, a)
		}
	}
	return out
}

func TestBackupAlerts_RaiseOnceResolveOnSuccess(t *testing.T) {
	f := newFixture(t)
	f.markSetupComplete(t)
	src := &fakeBackupStates{states: []proto.AppBackupStatus{
		overdueApp("app-im", "immich", "state", 9*24*time.Hour, "the most recent backup attempt FAILED for this app — immich-upload: node n-compute is OFFLINE"),
	}}
	f.svc.SetBackupStates(src)

	first, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := backupAlertsOf(first)
	if len(got) != 1 {
		t.Fatalf("backup alerts = %+v, want exactly one", got)
	}
	a := got[0]
	if a.ID != "backup-overdue:app-im" || a.Severity != proto.AlertWarn || a.Source != proto.AlertSourceApp {
		t.Errorf("alert = %+v; a `state` app is warn, source app, id keyed by app", a)
	}
	for _, want := range []string{"immich", "OVERDUE", "9d"} {
		if !strings.Contains(a.Title, want) {
			t.Errorf("title %q does not say %q", a.Title, want)
		}
	}
	if !strings.Contains(a.Detail, "OFFLINE") {
		t.Errorf("detail %q does not carry the fan-out's reason", a.Detail)
	}
	if a.RelatedKind != "app" || a.RelatedID != "app-im" {
		t.Errorf("drill-through = %s/%s, want app/app-im", a.RelatedKind, a.RelatedID)
	}
	if a.Since.IsZero() || time.Since(a.Since) < time.Hour {
		t.Errorf("since = %s, want the moment the state became overdue", a.Since)
	}

	// The second tick is the same alert, not a second one.
	second, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	again := backupAlertsOf(second)
	if len(again) != 1 || again[0].ID != a.ID || !again[0].Since.Equal(a.Since) {
		t.Errorf("second read = %+v; must be the same single alert", again)
	}

	// The next generation captured it: the alert resolves on its own.
	src.states[0].State = proto.AppBackupOK
	src.states[0].OverdueSince = nil
	third, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if left := backupAlertsOf(third); len(left) != 0 {
		t.Errorf("after a successful capture the alert must be gone; got %+v", left)
	}
	if src.calls != 3 {
		t.Errorf("derivation called %d times, want once per read", src.calls)
	}
}

func TestBackupAlerts_SeverityByClass(t *testing.T) {
	f := newFixture(t)
	f.markSetupComplete(t)
	f.svc.SetBackupStates(&fakeBackupStates{states: []proto.AppBackupStatus{
		overdueApp("app-vw", "vaultwarden", "critical", 0, "never backed up: installed 12d ago"),
		overdueApp("app-im", "immich", "state", 9*24*time.Hour, "node n-compute is OFFLINE"),
	}})
	all, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := backupAlertsOf(all)
	if len(got) != 2 {
		t.Fatalf("backup alerts = %+v, want two", got)
	}
	// Crit sorts first.
	if got[0].ID != "backup-overdue:app-vw" || got[0].Severity != proto.AlertCrit {
		t.Errorf("first = %+v; the critical app is crit and first", got[0])
	}
	if !strings.Contains(got[0].Title, "never backed up") {
		t.Errorf("title %q must say the app was never backed up", got[0].Title)
	}
	if got[1].ID != "backup-overdue:app-im" || got[1].Severity != proto.AlertWarn {
		t.Errorf("second = %+v; a state app is warn", got[1])
	}
}

func TestBackupAlerts_OnlyOverdueRaises(t *testing.T) {
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
		// #299's state: nothing was due, so nothing is overdue — even for a
		// critical app. The nag is that issue's, not this alert's.
		mk("unconfigured", proto.AppBackupUnconfigured),
		mk("none", proto.AppBackupNone),
	}})
	all, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := backupAlertsOf(all); len(got) != 0 {
		t.Errorf("non-overdue states raised %+v", got)
	}
}

func TestBackupAlerts_NoSourceOrErrorSurfaces(t *testing.T) {
	f := newFixture(t)
	f.markSetupComplete(t)
	// Not wired: nothing, and no error.
	all, err := f.svc.List(f.ctx)
	if err != nil || len(backupAlertsOf(all)) != 0 {
		t.Fatalf("unwired source: alerts=%+v err=%v", backupAlertsOf(all), err)
	}
	// A derivation that fails fails the read, loudly, rather than reading
	// as "no backup is overdue".
	f.svc.SetBackupStates(&fakeBackupStates{err: errors.New("ledger unreadable")})
	if _, err := f.svc.List(f.ctx); err == nil || !strings.Contains(err.Error(), "ledger unreadable") {
		t.Errorf("a failed derivation must surface, got err=%v", err)
	}
}
