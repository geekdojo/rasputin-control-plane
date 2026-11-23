package signinname

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-995-10: the guard's three states, and each alert's title and Detail.
func TestClassify(t *testing.T) {
	since := t0.Add(-time.Minute)
	live := ownerRecord{addr: other, src: other, ttl: 120 * time.Second, heard: t0.Add(-10 * time.Second), since: since}
	gone := live
	gone.heard = t0.Add(-121 * time.Second)
	for name, c := range map[string]struct {
		f    facts
		want Status
	}{
		"ok":                {facts{answering: true, since: since}, Status{State: StateOK, Since: since}},
		"conflict":          {facts{owner: live, since: t0}, Status{State: StateConflict, Owner: other, Since: since}},
		"conflict outranks": {facts{answering: true, owner: live}, Status{State: StateConflict, Owner: other, Since: since}},
		"no LAN address":    {facts{fault: CauseNoAddress, since: since}, Status{State: StateUnpublished, Cause: CauseNoAddress, Since: since}},
		"open failed":       {facts{fault: CauseOpenFailed, since: since}, Status{State: StateUnpublished, Cause: CauseOpenFailed, Since: since}},
		"stopped":           {facts{fault: CauseStopped, owner: live, since: since}, Status{State: StateUnpublished, Cause: CauseStopped, Since: since}},
		"refused":           {facts{fault: CauseRefused, since: since}, Status{State: StateUnpublished, Cause: CauseRefused, Since: since}},
		"probing":           {facts{since: since}, Status{State: StateUnpublished, Cause: CauseProbing, Since: since}},
		"owner expired":     {facts{owner: gone, since: since}, Status{State: StateUnpublished, Cause: CauseProbing, Since: gone.expires()}},
	} {
		if got := classify(c.f, t0); got != c.want {
			t.Errorf("%s: classify = %+v, want %+v", name, got, c.want)
		}
	}
}

// TC-995-10: no unpublished alert while probing or announcing; the exact
// alert for every other cause.
func TestAlertsPerCause(t *testing.T) {
	r := &Responder{host: testHost}
	title := "Sign-in isn't reachable: this system's sign-in address, sso-bench.local, is not being published."
	for _, f := range []facts{{since: t0}, {answering: true, since: t0}} {
		r.f = f
		if a := r.Alerts(t0); len(a) != 0 {
			t.Errorf("facts %+v raised %+v", f, a)
		}
	}
	for cause, detail := range map[Cause]string{
		CauseNoAddress:  "The control plane has no LAN address.",
		CauseOpenFailed: "The sign-in name responder could not open its network socket.",
		CauseStopped:    "The sign-in name responder stopped after an internal error. Restart the control plane to publish the name again.",
	} {
		r.f = facts{fault: cause, since: t0}
		want := proto.Alert{ID: AlertUnpublished, Severity: proto.AlertCrit, Source: proto.AlertSourceSecurity, Title: title, Detail: detail, Since: t0}
		if a := r.Alerts(t0); len(a) != 1 || a[0] != want {
			t.Errorf("%s: %+v, want %+v", cause, a, want)
		}
	}
}

// TC-995-15: a refused responder opens nothing (it has no opener at all), is
// unpublished "refused", and raises only the refused alert, titled for the
// rule the id broke (F-995-06).
func TestRefused(t *testing.T) {
	clk := newRunClock()
	const lenTitle = "This cluster's name can't carry a sign-in address. Re-provision it with a cluster id that does not start with sso- and has at most 59 characters."
	long := strings.Repeat("a", 60)
	for _, c := range []struct {
		id, title, detail string
		reason            error
	}{
		{"sso-bench", lenTitle, `The cluster id "sso-bench" starts with sso-, which is reserved for sign-in addresses.`, proto.ErrClusterIDReservedPrefix},
		{long, lenTitle, fmt.Sprintf("The cluster id %q is 60 characters, and a cluster id may have at most 59 so that its sign-in address fits in one DNS label.", long), proto.ErrClusterIDTooLong},
		{"Bench", "This cluster's name can't carry a sign-in address. Re-provision it with a cluster id made only of lowercase letters, digits and hyphens.",
			`The cluster id "Bench" is not a lowercase DNS label.`, doors.ErrNotLabel},
	} {
		r := NewRefused(c.id, c.reason, clk)
		if r.open != nil || r.conn != nil {
			t.Errorf("%s: a refused responder holds an opener or socket", c.id)
		}
		r.Run(t.Context()) // returns at once
		r.Wait()
		if st := r.State(t0); st.State != StateUnpublished || st.Cause != CauseRefused {
			t.Errorf("%s: state %+v", c.id, st)
		}
		want := proto.Alert{ID: AlertRefused, Severity: proto.AlertCrit, Source: proto.AlertSourceSecurity, Title: c.title, Detail: c.detail, Since: t0}
		if a := r.Alerts(t0.Add(time.Hour)); len(a) != 1 || a[0] != want {
			t.Errorf("%s: alerts %+v\nwant %+v", c.id, a, want)
		}
		if s, ok := r.MetricState(t0); !ok || s != "unpublished" {
			t.Errorf("%s: metric %q %v", c.id, s, ok)
		}
	}
	var nilR *Responder
	nilR.Wait()
	if _, ok := nilR.MetricState(t0); ok {
		t.Error("a nil responder reported a metric state")
	}
}
