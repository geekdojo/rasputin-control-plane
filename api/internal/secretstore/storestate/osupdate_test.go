package storestate

import (
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-800-12: a not-ready store held by a running job for an OS update's copy
// raises the quiesced warn alert with copy naming the OS update; Clause and
// String name it too. The backup and rotation copy are TC-830-11's and stay
// as they were.
func TestMonitor_QuiesceOSUpdateCopy(t *testing.T) {
	f := newFixture(t, secretstore.Health{}, healthErr(secretstore.ErrUnreachable))
	f.running["upd"] = true
	release := f.m.Quiesce("upd", QuiesceOSUpdate)
	defer release()
	a := f.m.Alerts(context.Background(), f.clock.now())
	if len(a) != 1 || a[0].ID != "secret-store:quiesced" || a[0].Severity != proto.AlertWarn {
		t.Fatalf("alerts = %+v", a)
	}
	if a[0].Title != "The secret store is paused for an OS update." {
		t.Errorf("Title = %q", a[0].Title)
	}
	if !strings.Contains(a[0].Detail, "a copy of its data is taken before an OS update") ||
		strings.Contains(a[0].Detail, "backup") || strings.Contains(a[0].Detail, "seal key") {
		t.Errorf("Detail = %q", a[0].Detail)
	}
	assertSentence(t, "Detail", a[0].Detail)
	if got := QuiesceOSUpdate.String(); got != "os-update" {
		t.Errorf("String() = %q, want os-update", got)
	}
	if c := Clause(Quiesced); !strings.Contains(c, "or an OS update") {
		t.Errorf("Clause(Quiesced) = %q, want it to name an OS update", c)
	}
	recs := f.rec.Matching(slog.LevelInfo, "secret store quiesced for an OS update")
	if len(recs) != 1 {
		t.Fatal("no quiesce record naming the OS update")
	}
	if got, _ := logkittest.Attr(recs[0], "reason"); got != "os-update" {
		t.Errorf("reason field = %q, want os-update", got)
	}
}

// OnFirstReady (geekdojo/geekdojo-brain#800, F-800-03): no reading that is
// not Ready runs the callback; the first Ready reading runs it once with the
// registered ctx; later Ready readings, after the store went down and came
// back, never run it again; and a callback registered after the store was
// already read Ready runs at once.
func TestMonitor_OnFirstReady(t *testing.T) {
	f := newFixture(t, secretstore.Health{Initialized: true, Sealed: true}, nil)
	type key struct{}
	ctx := context.WithValue(context.Background(), key{}, "root")
	var calls atomic.Int32
	got := make(chan any, 4)
	f.m.OnFirstReady(ctx, func(c context.Context) {
		calls.Add(1)
		got <- c.Value(key{})
	})
	if st := f.state(t); st != Sealed {
		t.Fatalf("state = %s", st)
	}
	f.store.set(secretstore.Health{}, healthErr(secretstore.ErrUnreachable))
	f.state(t)
	select {
	case <-got:
		t.Fatal("a reading that was not Ready ran the callback")
	case <-time.After(50 * time.Millisecond):
	}

	f.store.set(secretstore.Health{Initialized: true, Version: "2.7.1"}, nil)
	if st := f.state(t); st != Ready {
		t.Fatalf("state = %s", st)
	}
	if v := <-got; v != "root" {
		t.Errorf("callback ctx carried %v, want the registered ctx", v)
	}
	// Down and back: a second Ready transition runs nothing.
	f.store.set(secretstore.Health{}, healthErr(secretstore.ErrUnreachable))
	f.state(t)
	f.store.set(secretstore.Health{Initialized: true}, nil)
	f.state(t)
	f.state(t)

	late := make(chan struct{})
	f.m.OnFirstReady(ctx, func(context.Context) { close(late) })
	<-late
	select {
	case <-got:
		t.Fatal("the first callback ran twice")
	case <-time.After(50 * time.Millisecond):
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("callback ran %d time(s), want 1", n)
	}
}
