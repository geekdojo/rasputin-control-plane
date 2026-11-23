package door

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
)

var eventSeq atomic.Int64

// failFrom feeds the throttle one counted home-door failure from remote.
func failFrom(f *fixture, remote string) {
	ap := netip.MustParseAddrPort(remote)
	f.th.UserEvent(context.Background(), events.UserEvent{
		ID: "ev" + strconv.FormatInt(eventSeq.Add(1), 10), Time: f.now, Type: "LOGIN_ERROR",
		ClientID: policy.ConsoleClient, Error: "invalid_user_credentials", IP: ap.Addr(),
	})
}

func credentialPost(field string) req {
	return req{method: http.MethodPost, target: actions("authenticate") + "?client_id=" + policy.ConsoleClient,
		form: url.Values{"username": {"someone"}, field: {"guess"}}}
}

// drained runs one drain pass through the throttle, as the drainer would.
func drained(f *fixture, n uint64) {
	f.th.PassStarted(context.Background(), n)
	f.th.PassEnded(context.Background(), n)
}

// TC-985-26: during a wait, credential posts answer 429 with Retry-After and
// the sentence; a passkey post, a reset post and GETs pass; other addresses
// are unaffected.
func TestDoor_ThrottleWait(t *testing.T) {
	f := newFixture(t)
	for range 4 {
		failFrom(f, peer)
	}
	for _, field := range []string{"password", "otp", "recoveryCodeInput"} {
		before := f.up.count()
		w := f.do(Home, credentialPost(field))
		f.wantRefused(w, http.StatusTooManyRequests, before, "a "+field+" post during a wait")
		if w.Header().Get("Retry-After") != "60" {
			t.Errorf("%s: Retry-After %q, want 60", field, w.Header().Get("Retry-After"))
		}
		want := "Too many sign-in attempts came from this device. Try again in 1 minute, or sign in from another device."
		if got := sentenceIn(t, w.Body.String()); got != want {
			t.Errorf("%s: %q, want %q", field, got, want)
		}
	}
	f.wantPass(Home, req{method: http.MethodPost, target: actions("authenticate") + "?client_id=" + policy.ConsoleClient,
		form: url.Values{"credentialId": {"abc"}, "authenticatorData": {"d"}, "clientDataJSON": {"c"}, "signature": {"s"}, "userHandle": {"u"}}},
		"a passkey post during a wait")
	f.wantPass(Home, req{method: http.MethodPost, target: actions("reset-credentials") + "?client_id=" + policy.ResetHomeClient,
		form: url.Values{"username": {"someone"}}}, "a reset post during a wait")
	f.wantPass(Home, req{target: actions("authenticate") + "?client_id=" + policy.ConsoleClient}, "a GET during a wait")
	other := credentialPost("password")
	other.remote = "192.0.2.2:1"
	f.wantPass(Home, other, "another address's post")
	f.now = f.now.Add(61 * time.Second)
	drained(f, 1)
	f.wantPass(Home, credentialPost("password"), "a post once the wait has ended")
}

// TC-985-28: twenty concurrent credential posts from one address: at most
// one is forwarded at a time, the rest are refused with the throttle page,
// and the next is admitted only after a drain pass that started after the
// answer.
func TestDoor_BurstBound(t *testing.T) {
	f := newFixture(t)
	var inFlight, peak atomic.Int64
	entered := make(chan struct{}, 32)
	release := make(chan struct{})
	f.up.setHandler(func(w http.ResponseWriter, _ *http.Request) {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		entered <- struct{}{}
		<-release
		inFlight.Add(-1)
		w.WriteHeader(200)
	})
	var wg sync.WaitGroup
	codes := make([]int, 20)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = f.do(Home, credentialPost("password")).Code
		}()
	}
	<-entered // one post reached the identity service and is held there
	close(release)
	wg.Wait()
	ok := 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
		default:
			t.Errorf("a post answered %d", c)
		}
	}
	if ok != 1 || peak.Load() != 1 {
		t.Fatalf("%d posts forwarded, peak %d in flight; want 1 and 1", ok, peak.Load())
	}
	// Answered, but no pass has run since: still held.
	before := f.up.count()
	f.wantRefused(f.do(Home, credentialPost("password")), http.StatusTooManyRequests, before, "a post before the drain ran")
	if f.dirty.n.Load() == 0 {
		t.Fatal("the answered post did not mark the drain dirty")
	}
	drained(f, 1)
	f.wantPass(Home, credentialPost("password"), "the next post once the drain has taken the event")
}

// TC-985-32: forwarding an event-producing pattern marks the drain dirty;
// a theme file, discovery and the door's own files do not.
func TestDoor_DirtyFacts(t *testing.T) {
	f := newFixture(t)
	for _, target := range []string{themeLoginPath + "css/signin.css", realmPrefix + ".well-known/openid-configuration", signinPrefix + "css/tokens.css", "/nothing"} {
		f.do(Home, req{target: target})
	}
	if n := f.dirty.n.Load(); n != 0 {
		t.Fatalf("%d marks from requests that store no event", n)
	}
	f.do(Home, req{target: oidc("auth") + "?" + authQuery(policy.ConsoleClient, nil)})
	f.do(App, req{method: http.MethodPost, target: oidc("token"), form: url.Values{"client_id": {"rasputin-account"}, "grant_type": {"refresh_token"}}})
	if n := f.dirty.n.Load(); n != 2 {
		t.Fatalf("%d marks after two forwarded event-producing requests, want 2", n)
	}
	f.do(Home, req{target: oidc("auth") + "?" + authQuery(policy.ConsoleClient, map[string]string{"prompt": "none"})})
	if n := f.dirty.n.Load(); n != 2 {
		t.Fatalf("a refused request marked the drain dirty")
	}
}
