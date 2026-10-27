package storestate

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-765-28: an otherwise-ready store with a blank verdict reads Blank. It
// raises the crit secret-store:blank alert whose detail names restoring a
// backup, a secret-bearing deploy is refused with secret_store_not_ready, and
// a token-free deploy goes through. A verdict that cannot be read is Blank
// too, with one WARN however often it is read.
func TestMonitor_BlankVerdictRefusesStoreDependentWork(t *testing.T) {
	f := newFixture(t, readyHealth, nil)
	f.blank = true
	if st := f.state(t); st != Blank {
		t.Fatalf("state = %s, want %s", st, Blank)
	}
	alerts := f.m.Alerts(context.Background(), time.Now())
	if len(alerts) != 1 {
		t.Fatalf("alerts = %+v, want one", alerts)
	}
	a := alerts[0]
	if a.ID != "secret-store:blank" || a.Severity != proto.AlertCrit || a.Source != proto.AlertSourceSecurity {
		t.Errorf("alert = %+v, want secret-store:blank, crit, security", a)
	}
	if !strings.Contains(a.Detail, "Restore this cluster from a backup") {
		t.Errorf("detail %q does not name restoring a backup as the recovery", a.Detail)
	}
	assertSentence(t, "blank title", a.Title)
	assertNoVendor(t, "blank alert", a.Title+a.Detail)

	inner := &innerSource{value: "resolved"}
	g := newGate(t, f, inner)
	_, _, err := g.ResolveCompose(context.Background(), "a", tokened)
	var nre *NotReadyError
	if !errors.As(err, &nre) || nre.State != Blank || nre.Code() != Code {
		t.Fatalf("secret-bearing deploy = %v, want a NotReadyError for blank with %s", err, Code)
	}
	if v, _, err := g.ResolveCompose(context.Background(), "a", tokenFree); err != nil || string(v.Reveal()) != "resolved" {
		t.Fatalf("token-free deploy = (%q, %v), want it to go through", v.Reveal(), err)
	}

	f.blank, f.blankErr = false, errors.New("settings table locked")
	for range 3 {
		if st := f.state(t); st != Blank {
			t.Fatalf("unreadable verdict: state = %s, want %s", st, Blank)
		}
	}
	if n := len(f.rec.Matching(slog.LevelWarn, "blank verdict unreadable")); n != 1 {
		t.Errorf("%d WARN records for the unreadable verdict over three readings, want 1", n)
	}

	f.blankErr = nil
	if st := f.state(t); st != Ready {
		t.Fatalf("verdict clear again: state = %s, want %s", st, Ready)
	}
}

// A store that is not ready reads its own state, not Blank: the verdict is
// asked only of an otherwise-ready store.
func TestMonitor_BlankOnlyOverAReadyStore(t *testing.T) {
	f := newFixture(t, readyHealth, nil)
	f.blank = true
	f.store.set(secretstore.Health{}, healthErr(secretstore.ErrSealed))
	if st := f.state(t); st == Blank {
		t.Fatalf("a sealed store read %s", st)
	}
}
