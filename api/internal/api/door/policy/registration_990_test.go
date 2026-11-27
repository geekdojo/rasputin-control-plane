package policy

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The home door's sign-up (geekdojo/geekdojo-brain#990).

const (
	sentenceSourceWant  = "Create your account from a device on your home network."
	sentenceFullWant    = "Too many people are waiting for access. Ask an administrator."
	sentenceUnknownWant = "Creating an account isn't available right now. Ask whoever runs this cluster to add you."
)

// fixedNetwork is the facts as given.
type fixedNetwork struct{ f NetworkFacts }

func (n fixedNetwork) Facts(context.Context) (NetworkFacts, error) { return n.f, nil }

// countingWaiting counts Full calls and answers full or err; gate, when
// set, holds each call until it is closed.
type countingWaiting struct {
	calls atomic.Int32
	full  atomic.Bool
	err   error
	gate  chan struct{}
}

func (w *countingWaiting) Full(context.Context) (bool, error) {
	w.calls.Add(1)
	if w.gate != nil {
		<-w.gate
	}
	return w.full.Load(), w.err
}

// emailBook answers EmailInUse from a set, counting calls.
type emailBook struct {
	mu    sync.Mutex
	inUse map[string]bool
	err   error
	calls int
}

func (b *emailBook) EmailInUse(_ context.Context, e string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	return b.inUse[e], b.err
}

// listedNames answers Removed from a set of emails, counting calls.
type listedNames struct {
	mu     sync.Mutex
	emails map[string]bool
	err    error
	calls  int
}

func (l *listedNames) Removed(_ context.Context, _, email string) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	return l.emails[email], l.err
}

func regPolicy(t *testing.T, network Network, waiting Waiting, removed RemovedNames, emails Emails) *Service {
	t.Helper()
	th, _ := newThrottle(t)
	svc, err := New(Deps{Table: table(t), Readiness: okReady{}, Throttle: th, AppClients: NoAppClients{},
		Actions: NoActionsIssued{}, Network: network, Waiting: waiting, Removed: removed, Emails: emails, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// createFrom is prompt=create from peer.
func createFrom(peer netip.Addr) Request {
	return Request{Door: Home, Route: RouteAuth, Method: http.MethodGet, ClientIDs: []string{ConsoleClient},
		Params: map[string][]string{"response_type": {"code"}, "prompt": {"create"}}, Peer: peer}
}

// TC-990-14: the source rule. Only a home address that is neither tailnet
// nor a node's is admitted; every other is refused with the sentence and
// the back link.
func TestRegistration_TC990_14_SourceRule(t *testing.T) {
	facts := NetworkFacts{
		HomeSubnets: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		Tailnet:     []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		Nodes:       []netip.Addr{netip.MustParseAddr("192.0.2.10")},
	}
	svc := regPolicy(t, fixedNetwork{facts}, notFull{}, noneRemoved{}, noEmails{})
	for _, c := range []struct {
		peer  netip.Addr
		admit bool
	}{
		{netip.MustParseAddr("100.64.1.2"), false},
		{netip.MustParseAddr("192.0.2.10"), false},
		{netip.MustParseAddr("::ffff:192.0.2.10"), false},
		{netip.MustParseAddr("192.0.2.50"), true},
		{netip.MustParseAddr("198.51.100.7"), false},
		{netip.Addr{}, false},
	} {
		d := svc.Check(t.Context(), createFrom(c.peer))
		if c.admit {
			if !d.Allow {
				t.Errorf("%v refused: %+v", c.peer, d)
			}
			continue
		}
		if d.Allow || d.Status != http.StatusForbidden || d.Sentence != sentenceSourceWant || !d.BackLink || d.Reason != "registration_source" {
			t.Errorf("%v: %+v", c.peer, d)
		}
	}
}

// TC-990-18: F-991-12 at the policy. A removed email and an in-use email
// give equal Decisions but for the reason; both checks run on every post
// that carries an email, whichever matches; an EmailInUse error refuses
// with the unavailable sentence, a removed-list error with the paused one.
func TestRegistration_TC990_18_EmailOneAnswer(t *testing.T) {
	list := &listedNames{emails: map[string]bool{"gone@x.invalid": true}}
	book := &emailBook{inUse: map[string]bool{"taken@x.invalid": true}}
	svc := regPolicy(t, homeNetwork{}, notFull{}, list, book)
	removed := checked(t.Context(), svc, post(url.Values{"username": {"n1"}, "email": {"gone@x.invalid"}}))
	inUse := checked(t.Context(), svc, post(url.Values{"username": {"n2"}, "email": {"taken@x.invalid"}}))
	if removed.Reason != "registration_removed_email" || inUse.Reason != "registration_email_in_use" {
		t.Errorf("reasons %q, %q", removed.Reason, inUse.Reason)
	}
	removed.Reason, inUse.Reason = "", ""
	if removed != inUse {
		t.Errorf("the decisions differ:\n%+v\n%+v", removed, inUse)
	}
	if removed.Allow || removed.Status != http.StatusForbidden || !removed.BackLink || removed.Sentence != sentenceEmailWant {
		t.Errorf("the decision %+v", removed)
	}
	// Both checks ran on each post: one name check and one email check on
	// the list, one lookup in the book, per post.
	if list.calls != 4 || book.calls != 2 {
		t.Errorf("list calls %d, book calls %d; want 4 and 2", list.calls, book.calls)
	}
	book.err = errors.New("down")
	d := checked(t.Context(), svc, post(url.Values{"username": {"n3"}, "email": {"new@x.invalid"}}))
	if d.Allow || d.Reason != ReasonRegistrationUnknown || d.Sentence != sentenceUnknownWant {
		t.Errorf("an EmailInUse error: %+v", d)
	}
	book.err, list.err = nil, errors.New("down")
	d = checked(t.Context(), svc, post(url.Values{"username": {"n4"}, "email": {"new@x.invalid"}}))
	if d.Allow || d.Reason != ReasonRegistrationPaused {
		t.Errorf("a removed-list error: %+v", d)
	}
}

// TC-990-13 (unit part): a full waiting list refuses prompt=create and the
// post with the cap's sentence; an unreadable count refuses with the
// unavailable one.
func TestRegistration_TC990_13_Cap(t *testing.T) {
	w := &countingWaiting{}
	w.full.Store(true)
	svc := regPolicy(t, homeNetwork{}, w, noneRemoved{}, noEmails{})
	for what, req := range map[string]Request{"prompt=create": createFrom(homePeer), "post": post(url.Values{"username": {"z"}})} {
		d := checked(t.Context(), svc, req)
		if d.Allow || d.Reason != "registration_full" || d.Sentence != sentenceFullWant || !d.BackLink {
			t.Errorf("%s: %+v", what, d)
		}
	}
	w.full.Store(false)
	w.err = errors.New("down")
	if d := checked(t.Context(), svc, createFrom(homePeer)); d.Reason != ReasonRegistrationUnknown {
		t.Errorf("an unreadable count: %+v", d)
	}
}

// F-990-02: the cap is held across the relay. Two concurrent registration
// posts at 19 waiting: the second does not read the count until the first
// is released, and every refusal releases the slot.
func TestRegistration_F990_02_SlotHeldAcrossRelay(t *testing.T) {
	w := &countingWaiting{}
	svc := regPolicy(t, homeNetwork{}, w, noneRemoved{}, noEmails{})
	first := svc.Check(t.Context(), post(url.Values{"username": {"a"}}))
	if !first.Allow || !first.RegistrationHeld {
		t.Fatalf("the first post: %+v", first)
	}
	done := make(chan Decision, 1)
	go func() { done <- svc.Check(t.Context(), post(url.Values{"username": {"b"}})) }()
	select {
	case d := <-done:
		t.Fatalf("the second post was decided while the first held the slot: %+v", d)
	case <-time.After(50 * time.Millisecond):
	}
	if n := w.calls.Load(); n != 1 {
		t.Errorf("the count was read %d times before the first was released, want 1", n)
	}
	// The first post's account now exists: the second reads the cap reached.
	w.full.Store(true)
	svc.ReleaseRegistration()
	second := <-done
	if second.Allow || second.Reason != "registration_full" || second.RegistrationHeld {
		t.Errorf("the second post: %+v", second)
	}
	// Its refusal released the slot: a third post decides at once.
	w.full.Store(false)
	third := svc.Check(t.Context(), post(url.Values{"username": {"c"}}))
	if !third.Allow || !third.RegistrationHeld {
		t.Errorf("the third post: %+v", third)
	}
	// A post whose request ends while it waits is refused as unavailable.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if d := svc.Check(ctx, post(url.Values{"username": {"d"}})); d.Allow || d.Reason != ReasonRegistrationUnknown {
		t.Errorf("a post whose request ended: %+v", d)
	}
	svc.ReleaseRegistration()
	// Pages hold no slot.
	if d := svc.Check(t.Context(), createFrom(homePeer)); !d.Allow || d.RegistrationHeld {
		t.Errorf("prompt=create held the slot: %+v", d)
	}
	svc.ReleaseRegistration() // a release with nothing held is a no-op
	if d := checked(t.Context(), svc, post(url.Values{"username": {"e"}})); !d.Allow {
		t.Errorf("after a spare release: %+v", d)
	}
}

// fakeNodes answers the inventory's node addresses.
type fakeNodes struct {
	ips []string
	err error
}

func (n fakeNodes) list(context.Context) ([]string, error) { return n.ips, n.err }

// TC-990-15: NetworkSource's fail-closed table (security-resolvers R76).
func TestNetworkSource_TC990_15(t *testing.T) {
	home := func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")} }
	tailnet := func() []netip.Prefix {
		return []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd7a:115c:a1e0::/48")}
	}
	src := func(lan, tn func() []netip.Prefix, nodes fakeNodes) *NetworkSource {
		s, err := NewNetworkSource(NetworkSourceDeps{LAN: lan, Tailnet: tn, Nodes: nodes.list})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	ok := src(home, tailnet, fakeNodes{ips: []string{"192.0.2.10", ""}})
	f, err := ok.Facts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Nodes) != 1 || f.Nodes[0] != netip.MustParseAddr("192.0.2.10") || len(f.Tailnet) != 2 || len(f.HomeSubnets) != 1 {
		t.Errorf("facts %+v (an empty node address is skipped)", f)
	}

	// Absent or empty LAN snapshot: no home subnets, so every peer is refused.
	for name, lan := range map[string]func() []netip.Prefix{
		"absent": func() []netip.Prefix { return nil },
		"empty":  func() []netip.Prefix { return []netip.Prefix{} },
	} {
		s := src(lan, tailnet, fakeNodes{})
		f, err := s.Facts(t.Context())
		if err != nil || len(f.HomeSubnets) != 0 {
			t.Errorf("%s LAN: %+v %v", name, f, err)
		}
		svc := regPolicy(t, s, notFull{}, noneRemoved{}, noEmails{})
		if d := svc.Check(t.Context(), createFrom(homePeer)); d.Allow || d.Reason != "registration_source" {
			t.Errorf("%s LAN: %+v", name, d)
		}
	}
	// Each error: refused with the unavailable sentence, reason
	// registration_unknown (WARN at the door).
	for name, s := range map[string]*NetworkSource{
		"inventory read error": src(home, tailnet, fakeNodes{err: errors.New("down")}),
		"unparseable LANIP":    src(home, tailnet, fakeNodes{ips: []string{"not-an-ip"}}),
		"empty tailnet":        src(home, func() []netip.Prefix { return nil }, fakeNodes{}),
		"invalid tailnet":      src(home, func() []netip.Prefix { return []netip.Prefix{{}} }, fakeNodes{}),
	} {
		if _, err := s.Facts(t.Context()); err == nil {
			t.Errorf("%s: no error", name)
		}
		svc := regPolicy(t, s, notFull{}, noneRemoved{}, noEmails{})
		if d := svc.Check(t.Context(), createFrom(homePeer)); d.Allow || d.Reason != ReasonRegistrationUnknown || d.Sentence != sentenceUnknownWant {
			t.Errorf("%s: %+v", name, d)
		}
	}
	if _, err := NewNetworkSource(NetworkSourceDeps{}); err == nil {
		t.Error("NewNetworkSource with nothing succeeded")
	}
}
