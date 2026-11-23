package identitystate

import (
	"context"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// TC-985-32: BecameReady fires on the transition to ready, once per
// transition, and never while the state holds or blocks.
func TestBecameReady_FiresOnTheTransition(t *testing.T) {
	x := newFixture(t)
	fired := 0
	log, _ := logkittest.New()
	d := x.deps(log, x.ledger)
	d.BecameReady = func() { fired++ }
	m, err := New(d)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	read := func() State {
		t.Helper()
		st, err := m.State(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	if st := read(); st != Ready || fired != 1 {
		t.Fatalf("first ready reading: state %s, BecameReady fired %d times, want ready and 1", st, fired)
	}
	if read(); fired != 1 {
		t.Fatalf("a second ready reading fired BecameReady again: %d", fired)
	}
	x.w.set(func(w *world) { w.units.KC = kcStartPost })
	if st := read(); st != Starting || fired != 1 {
		t.Fatalf("a starting reading: state %s, fired %d, want starting and still 1", st, fired)
	}
	x.w.set(func(w *world) { w.units.KC = kcActive })
	if st := read(); st != Ready || fired != 2 {
		t.Fatalf("ready again: state %s, fired %d, want ready and 2", st, fired)
	}
}

// A Monitor without BecameReady, as every mode but keycloak builds it, reads
// ready without calling anything.
func TestBecameReady_NilCallsNothing(t *testing.T) {
	x := newFixture(t)
	if st, err := x.m.State(context.Background()); err != nil || st != Ready {
		t.Fatalf("state %s, %v; want ready", st, err)
	}
}
