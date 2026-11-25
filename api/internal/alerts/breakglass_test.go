package alerts

import (
	"context"
	"errors"
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
