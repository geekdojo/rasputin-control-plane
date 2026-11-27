package alerts

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-321-22 (the alerts' half): the issue alert is a persisted warning and
// the redemption alert a persisted critical, one row per event, under the
// security source with their titles; a second raise of one event adds
// nothing; with no store both are no-ops.
func TestBreakGlassAlerts_TC321_22(t *testing.T) {
	ctx := context.Background()
	svc, store := nodeKeyService(t)
	for _, raise := range []func() error{
		func() error { return svc.RaiseBreakGlassIssued(ctx, "ev-1") },
		func() error { return svc.RaiseBreakGlassIssued(ctx, "ev-1") },
		func() error { return svc.RaiseBreakGlassRedeemed(ctx, "ev-2") },
	} {
		if err := raise(); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("%d rows, want 2: %+v", len(rows), rows)
	}
	want := map[string]struct {
		sev   proto.AlertSeverity
		title string
	}{
		"BreakGlassCodeIssued":    {proto.AlertWarn, "A break-glass code was issued on the control plane."},
		"BreakGlassSessionOpened": {proto.AlertCrit, "A break-glass code was used to open a repair session."},
	}
	for _, r := range rows {
		w, ok := want[r.Labels["alertname"]]
		if !ok || r.Severity != w.sev || r.Title != w.title || r.Status != "firing" || r.Detail == "" {
			t.Errorf("row %+v", r)
		}
		if a := toAlert(r); a.Source != proto.AlertSourceSecurity {
			t.Errorf("source %q", a.Source)
		}
	}
	none := &Service{}
	if err := none.RaiseBreakGlassIssued(ctx, "x"); err != nil {
		t.Error(err)
	}
	if err := none.RaiseBreakGlassRedeemed(ctx, "x"); err != nil {
		t.Error(err)
	}
}

// TC-321-23: the no-last-resort warning shows with no console password and
// an authorized_keys that is absent, empty, or holds only comments and
// invalid lines; not with a password, nor with one valid key line; and not
// when a read fails. It reaches List through SetLastResortAlerts.
func TestLastResortWarning_TC321_23(t *testing.T) {
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	lines := func(l ...string) func() ([]string, error) { return func() ([]string, error) { return l, nil } }
	hash := func(id string, err error) func(context.Context) (string, error) {
		return func(context.Context) (string, error) { return id, err }
	}
	for name, c := range map[string]struct {
		lr   LastResort
		want bool
	}{
		"no password, no keys (absent, empty or only comments and invalid lines)": {LastResort{hash("", nil), lines()}, true},
		"a console password":        {LastResort{hash("h1", nil), lines()}, false},
		"one valid key line":        {LastResort{hash("", nil), lines("ssh-ed25519 AAAA")}, false},
		"the hash couldn't be read": {LastResort{hash("", errors.New("db")), lines()}, false},
		"the keys couldn't be read": {LastResort{hash("", nil), func() ([]string, error) { return nil, errors.New("eperm") }}, false},
		"unwired":                   {LastResort{}, false},
	} {
		got := c.lr.Alerts(context.Background(), now)
		if (len(got) == 1) != c.want {
			t.Errorf("%s: %+v", name, got)
			continue
		}
		if c.want && (got[0].Title != "There is no last-resort way in: set a console password in Settings → Node access." ||
			got[0].Severity != proto.AlertWarn || got[0].ID != LastResortAlertID || !got[0].Since.Equal(now)) {
			t.Errorf("%s: %+v", name, got[0])
		}
	}
}

// TC-321-50 (F-321-28, F-321-29): the reset alert is a persisted critical
// row per event, labelled with the event and the account's opaque id; a
// second raise of one event adds nothing. The redemption alert's detail
// names the reset and the move re-run and no longer says "and nothing
// else".
func TestBreakGlassResetAlert_TC321_50(t *testing.T) {
	ctx := context.Background()
	svc, store := nodeKeyService(t)
	for _, ev := range []string{"ev-1", "ev-1", "ev-2"} {
		if err := svc.RaiseBreakGlassReset(ctx, ev, "sub-"+ev); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("%d rows, want 2: %+v", len(rows), rows)
	}
	for _, r := range rows {
		if r.Severity != proto.AlertCrit || r.Title != "A break-glass repair reset an administrator's sign-in." ||
			r.Labels["alertname"] != "BreakGlassSignInReset" || r.Labels["accountId"] != "sub-"+r.Labels["eventId"] ||
			r.Status != "firing" || r.Detail == "" {
			t.Errorf("row %+v", r)
		}
		if a := toAlert(r); a.Source != proto.AlertSourceSecurity {
			t.Errorf("source %q", a.Source)
		}
	}
	if err := (&Service{}).RaiseBreakGlassReset(ctx, "x", "y"); err != nil {
		t.Error(err)
	}
	for _, want := range []string{"reset one administrator's or designated account's sign-in once", "bring those back"} {
		if !strings.Contains(breakGlassRedeemedDetail, want) {
			t.Errorf("the redemption detail lacks %q", want)
		}
	}
	if strings.Contains(breakGlassRedeemedDetail, "and nothing else") {
		t.Error("the redemption detail still says the session can do nothing else")
	}
}

// TC-321-49: C9's alert is listed exactly while the state holds; not when
// it doesn't, when the read fails, or unwired. It reaches List through
// SetLostAccountsAlerts.
func TestLostAccountsAlert_TC321_49(t *testing.T) {
	now := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	repair := func(holds bool, err error) func(context.Context) (bool, error) {
		return func(context.Context) (bool, error) { return holds, err }
	}
	for name, c := range map[string]struct {
		la   LostAccounts
		want bool
	}{
		"holds":       {LostAccounts{Repair: repair(true, nil)}, true},
		"not holding": {LostAccounts{Repair: repair(false, nil)}, false},
		"read fails":  {LostAccounts{Repair: repair(true, errors.New("db"))}, false},
		"unwired":     {LostAccounts{}, false},
	} {
		got := c.la.Alerts(context.Background(), now)
		if (len(got) == 1) != c.want {
			t.Errorf("%s: %+v", name, got)
			continue
		}
		if c.want && (got[0].ID != "identity:blank" || got[0].Severity != proto.AlertCrit || got[0].Title !=
			"Sign-in has lost its accounts, but this cluster still has its accounts from before the sign-in update. Open a repair session with a repair code to bring them back.") {
			t.Errorf("%s: %+v", name, got[0])
		}
	}
	f := newFixture(t)
	f.svc.SetLostAccountsAlerts(LostAccounts{Repair: repair(true, nil)}.Alerts)
	list, err := f.svc.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, a := range list {
		if a.ID == LostAccountsAlertID {
			found++
		}
	}
	if found != 1 {
		t.Errorf("List carries %d identity:blank alerts, want 1", found)
	}
}
