package policy

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
)

var t0 = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

func table(t *testing.T) doors.Table {
	t.Helper()
	tb, err := doors.New("ci")
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

// clock is a settable now.
type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func newThrottle(t *testing.T) (*Throttle, *clock) {
	t.Helper()
	c := &clock{now: t0}
	th, err := NewThrottle(ThrottleDeps{Table: table(t), Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	return th, c
}

var seq int

// fail feeds one counted failure from addr for client at at.
func fail(th *Throttle, client, addr string, at time.Time) {
	seq++
	th.UserEvent(context.Background(), events.UserEvent{
		ID: fmt.Sprintf("e%d", seq), Time: at, Type: "LOGIN_ERROR", ClientID: client,
		Error: "invalid_user_credentials", IP: netip.MustParseAddr(addr),
	})
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// TC-985-25: keys are per IPv4 address, per IPv6 /64, IPv4-mapped read as
// IPv4, and per door.
func TestThrottle_Keys(t *testing.T) {
	th, c := newThrottle(t)
	for range 4 {
		fail(th, ConsoleClient, "192.0.2.1", c.now)
		fail(th, ConsoleClient, "2001:db8:1:1::a", c.now)
	}
	for a, want := range map[string]bool{
		"192.0.2.1": true, "192.0.2.2": false, "2001:db8:1:1::a": true, "2001:db8:1:1::b": true,
		"2001:db8:1:2::a": false, "::ffff:192.0.2.1": true,
	} {
		if got := th.Wait(Home, addr(a), c.now) > 0; got != want {
			t.Errorf("home door, %s waits = %v, want %v", a, got, want)
		}
	}
	if th.Wait(App, addr("192.0.2.1"), c.now) != 0 {
		t.Error("a home-door source waits at the app door too; the doors are separate keys")
	}
}

// TC-985-26: the first three failures set no wait, then 60, 120, 240, 480
// and 900 s; a source that keeps failing after each wait ends stays at 900 s
// and never returns to a free count (the 12-hour window, F-985-02).
func TestThrottle_RisingWaitStaysAtTheCap(t *testing.T) {
	th, c := newThrottle(t)
	const a = "198.51.100.7"
	at := c.now
	for i := range 3 {
		fail(th, ConsoleClient, a, at)
		if w := th.Wait(Home, addr(a), at); w != 0 {
			t.Fatalf("failure %d set a wait of %v, want none", i+1, w)
		}
	}
	for i, want := range []time.Duration{60, 120, 240, 480, 900, 900, 900} {
		fail(th, ConsoleClient, a, at)
		if w := th.Wait(Home, addr(a), at); w != want*time.Second {
			t.Fatalf("failure %d set a wait of %v, want %v", i+4, w, want*time.Second)
		}
		// The next guess comes just after this wait ends.
		at = at.Add(want*time.Second + time.Second)
		c.now = at
	}
	// An hour later still: within the window, so the very next failure waits
	// 900 s again, never a free count.
	at = at.Add(time.Hour)
	c.now = at
	fail(th, ConsoleClient, a, at)
	if w := th.Wait(Home, addr(a), at); w != 900*time.Second {
		t.Fatalf("a failure an hour after the last waits %v, want 900s", w)
	}
	// Only a gap longer than the window restarts the count.
	at = at.Add(sourceFailureWindowLifetime + time.Minute)
	c.now = at
	fail(th, ConsoleClient, a, at)
	if w := th.Wait(Home, addr(a), at); w != 0 {
		t.Fatalf("a failure after more than %v set a wait of %v, want a free count", sourceFailureWindowLifetime, w)
	}
	if th.Wait(Home, addr("198.51.100.8"), at) != 0 {
		t.Error("another address waits")
	}
}

// TC-985-27: a sign-in that succeeds, from the same address, changes neither
// the wait nor the count; the throttle has no method that clears a source.
func TestThrottle_NoEarlyEnd(t *testing.T) {
	th, c := newThrottle(t)
	const a = "203.0.113.5"
	for range 5 {
		fail(th, ConsoleClient, a, c.now)
	}
	before := th.Wait(Home, addr(a), c.now)
	th.UserEvent(context.Background(), events.UserEvent{ID: "ok", Time: c.now, Type: "LOGIN", ClientID: ConsoleClient, IP: addr(a)})
	th.UserEvent(context.Background(), events.UserEvent{ID: "x", Time: c.now, Type: "LOGIN_ERROR", ClientID: ConsoleClient,
		Error: "user_disabled", IP: addr(a)})
	if after := th.Wait(Home, addr(a), c.now); after != before || before != 120*time.Second {
		t.Fatalf("wait %v before and %v after a LOGIN, want 120s both", before, after)
	}
	k, _ := keyOf(Home, addr(a))
	if n := th.sources[k].failures; n != 5 {
		t.Fatalf("count %d after a LOGIN, want 5", n)
	}
	// The API surface: nothing that names a clear, reset, unlock or delete.
	tt := reflect.TypeOf(th)
	for i := range tt.NumMethod() {
		name := strings.ToLower(tt.Method(i).Name)
		for _, bad := range []string{"clear", "reset", "unlock", "delete", "forget", "remove"} {
			if strings.Contains(name, bad) {
				t.Errorf("the throttle has a method %s", tt.Method(i).Name)
			}
		}
	}
}

// TC-985-28: one credential post in flight per source; the next is admitted
// only after a drain pass that started after the answer has ended, never
// before, and a pass that started earlier does not release it.
func TestThrottle_BurstBound(t *testing.T) {
	th, c := newThrottle(t)
	ctx := context.Background()
	a := addr("192.0.2.9")
	first := th.Admit(Home, a, c.now)
	if !first.OK {
		t.Fatalf("the first post was refused: %+v", first)
	}
	for range 19 {
		if adm := th.Admit(Home, a, c.now); adm.OK || !adm.Busy {
			t.Fatalf("a concurrent post was admitted or not busy: %+v", adm)
		}
	}
	if other := th.Admit(Home, addr("192.0.2.10"), c.now); !other.OK {
		t.Fatal("another address was held by this one's post")
	}
	th.PassStarted(ctx, 1) // a pass already running when the answer came
	th.Answered(first.Key)
	th.PassEnded(ctx, 1)
	if adm := th.Admit(Home, a, c.now); adm.OK {
		t.Fatal("a pass that started before the answer released the slot")
	}
	th.PassStarted(ctx, 2)
	if adm := th.Admit(Home, a, c.now); adm.OK {
		t.Fatal("the slot was released before the pass ended")
	}
	th.PassEnded(ctx, 2)
	if adm := th.Admit(Home, a, c.now); !adm.OK {
		t.Fatalf("the slot was not released by a pass that started after the answer: %+v", adm)
	}
}

// TC-985-28: an unanswered post is never released by a pass.
func TestThrottle_UnansweredHolds(t *testing.T) {
	th, c := newThrottle(t)
	ctx := context.Background()
	a := addr("192.0.2.11")
	th.Admit(Home, a, c.now)
	th.PassStarted(ctx, 5)
	th.PassEnded(ctx, 5)
	if adm := th.Admit(Home, a, c.now); adm.OK {
		t.Fatal("a pass released a post that was never answered")
	}
}

// TC-985-26: a waiting source's post is refused with Retry-After and the
// sentence, in whole minutes, "1 minute" when singular.
func TestThrottle_WaitRefusal(t *testing.T) {
	th, c := newThrottle(t)
	a := "192.0.2.12"
	for range 4 {
		fail(th, ConsoleClient, a, c.now)
	}
	adm := th.Admit(Home, addr(a), c.now)
	if adm.OK || adm.Busy || adm.RetryAfter != time.Minute {
		t.Fatalf("admission %+v, want a 60 s wait", adm)
	}
	want := "Too many sign-in attempts came from this device. Try again in 1 minute, or sign in from another device."
	if adm.Sentence != want {
		t.Errorf("sentence %q, want %q", adm.Sentence, want)
	}
	if got := waitSentence(61 * time.Second); !strings.Contains(got, "in 2 minutes,") {
		t.Errorf("61 s reads %q, want 2 minutes", got)
	}
	if adm := th.Admit(Home, netip.Addr{}, c.now); adm.OK || adm.Sentence == "" {
		t.Errorf("an unparsable peer was admitted: %+v", adm)
	}
}

// TC-985-29: what counts. Only LOGIN_ERROR with invalid_user_credentials or
// user_not_found; a missing or unparsable address is skipped; a re-delivered
// id counts once; an app client's failure counts at the app door; an event
// older than the window is ignored.
func TestThrottle_Classification(t *testing.T) {
	th, c := newThrottle(t)
	ctx := context.Background()
	count := func(door Kind, a string) int {
		k, _ := keyOf(door, addr(a))
		if s := th.sources[k]; s != nil {
			return s.failures
		}
		return 0
	}
	send := func(e events.UserEvent) { th.UserEvent(ctx, e) }
	send(events.UserEvent{ID: "1", Time: c.now, Type: "LOGIN_ERROR", ClientID: ConsoleClient, Error: "invalid_user_credentials", IP: addr("10.0.0.1")})
	send(events.UserEvent{ID: "2", Time: c.now, Type: "LOGIN_ERROR", ClientID: ConsoleClient, Error: "user_not_found", IP: addr("10.0.0.1")})
	send(events.UserEvent{ID: "2", Time: c.now, Type: "LOGIN_ERROR", ClientID: ConsoleClient, Error: "user_not_found", IP: addr("10.0.0.1")})
	send(events.UserEvent{ID: "3", Time: c.now, Type: "LOGIN_ERROR", ClientID: ConsoleClient, Error: "expired_code", IP: addr("10.0.0.1")})
	send(events.UserEvent{ID: "4", Time: c.now, Type: "CODE_TO_TOKEN_ERROR", ClientID: ConsoleClient, Error: "invalid_user_credentials", IP: addr("10.0.0.1")})
	send(events.UserEvent{ID: "5", Time: c.now, Type: "LOGIN_ERROR", ClientID: ConsoleClient, Error: "invalid_user_credentials"})
	send(events.UserEvent{ID: "6", Time: c.now.Add(-sourceFailureWindowLifetime - time.Minute), Type: "LOGIN_ERROR", ClientID: ConsoleClient, Error: "invalid_user_credentials", IP: addr("10.0.0.1")})
	if n := count(Home, "10.0.0.1"); n != 2 {
		t.Fatalf("home count %d, want 2", n)
	}
	send(events.UserEvent{ID: "7", Time: c.now, Type: "LOGIN_ERROR", ClientID: "immich", Error: "invalid_user_credentials", IP: addr("10.0.0.1")})
	send(events.UserEvent{ID: "8", Time: c.now, Type: "LOGIN_ERROR", ClientID: "rasputin-account", Error: "invalid_user_credentials", IP: addr("10.0.0.1")})
	if n := count(App, "10.0.0.1"); n != 2 {
		t.Fatalf("app count %d, want 2 (an app client and rasputin-account)", n)
	}
	if n := count(Home, "10.0.0.1"); n != 2 {
		t.Fatalf("an app client's failure counted at the home door: %d", n)
	}
}

// TC-985-30: the map stays at its cap, expired records are evicted first,
// and the bounds are the ratified values.
func TestThrottle_Bounds(t *testing.T) {
	if sourceWaitMinLifetime != 60*time.Second || sourceWaitMaxLifetime != 900*time.Second ||
		sourceFailureWindowLifetime != 12*time.Hour || guessFreeFailures != 3 {
		t.Fatal("the guessing bounds differ from D22's ratified values")
	}
	th, c := newThrottle(t)
	// Fill the map: half recent and waiting, half expired long ago.
	old := c.now.Add(-13 * time.Hour)
	for i := range maxSources {
		a := netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)})
		k, _ := keyOf(Home, a)
		s := &source{failures: 5, last: old}
		if i%2 == 0 {
			s.last, s.waitUntil = c.now, c.now.Add(time.Hour)
		}
		th.sources[k] = s
	}
	fail(th, ConsoleClient, "10.200.0.1", c.now)
	if n := len(th.sources); n > maxSources {
		t.Fatalf("%d records, over the cap %d", n, maxSources)
	}
	waiting := 0
	for _, s := range th.sources {
		if s.waitUntil.After(c.now) {
			waiting++
		}
	}
	if waiting != maxSources/2 {
		t.Fatalf("%d waiting records left, want all %d kept: the expired ones go first", waiting, maxSources/2)
	}
	// With no expired record left, the idle record with the oldest failure
	// goes, never a held slot.
	for len(th.sources) < maxSources {
		fail(th, ConsoleClient, fmt.Sprintf("10.201.%d.%d", len(th.sources)>>8&0xff, len(th.sources)&0xff), c.now)
	}
	if adm := th.Admit(Home, addr("10.202.0.1"), c.now); !adm.OK || len(th.sources) > maxSources {
		t.Fatalf("an admit at the cap: %+v with %d records", adm, len(th.sources))
	}
	if th.Waiting(Home, c.now) == 0 || th.Waiting(App, c.now) != 0 {
		t.Errorf("Waiting: home %d, app %d", th.Waiting(Home, c.now), th.Waiting(App, c.now))
	}
}

func TestNewThrottle_Refuses(t *testing.T) {
	if _, err := NewThrottle(ThrottleDeps{Now: time.Now}); err == nil {
		t.Error("no table accepted")
	}
	if _, err := NewThrottle(ThrottleDeps{Table: table(t)}); err == nil {
		t.Error("no clock accepted")
	}
}
