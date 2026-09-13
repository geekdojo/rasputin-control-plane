package lanaddr

import (
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSource is an injectable Source: the test sets the address list and fires
// the change channel, standing in for the kernel.
type fakeSource struct {
	mu      sync.Mutex
	addrs   []Addr
	listErr error
	ch      chan struct{}
	subErr  error
	lists   chan error // one value per List call: the error it returned
}

func newFakeSource(addrs ...Addr) *fakeSource {
	return &fakeSource{addrs: addrs, ch: make(chan struct{}, 1), lists: make(chan error, 64)}
}

func (f *fakeSource) Subscribe(ctx context.Context) (<-chan struct{}, error) {
	if f.subErr != nil {
		return nil, f.subErr
	}
	return f.ch, nil
}

func (f *fakeSource) List() ([]Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lists <- f.listErr
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]Addr(nil), f.addrs...), nil
}

// set replaces the address list and announces it, as the kernel would.
func (f *fakeSource) set(addrs ...Addr) {
	f.mu.Lock()
	f.addrs = addrs
	f.mu.Unlock()
	f.ch <- struct{}{}
}

// recorder collects the transitions a subscriber sees.
type recorder struct {
	mu   sync.Mutex
	seen []string // next.String() per call
	cond chan struct{}
}

func newRecorder() *recorder { return &recorder{cond: make(chan struct{}, 16)} }

func (r *recorder) fn(_, next Snapshot) {
	r.mu.Lock()
	r.seen = append(r.seen, next.String())
	r.mu.Unlock()
	r.cond <- struct{}{}
}

// waitFor blocks until the subscriber has been called n times in total. The
// deadline only bounds a broken test; nothing in the Watcher waits on a clock.
func (r *recorder) waitFor(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		r.mu.Lock()
		if len(r.seen) >= n {
			out := append([]string(nil), r.seen...)
			r.mu.Unlock()
			return out
		}
		r.mu.Unlock()
		select {
		case <-r.cond:
		case <-deadline:
			r.mu.Lock()
			defer r.mu.Unlock()
			t.Fatalf("waited for %d subscriber calls, saw %v", n, r.seen)
		}
	}
}

// TestWatcher_Lifecycle walks the #431 bench sequence: boot with no DHCP (only
// the fallback and link-local), a late lease beside the fallback, the fallback
// released, the lease lost. Each change reaches the subscriber exactly once, in
// order, and the snapshot follows.
func TestWatcher_Lifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	src := newFakeSource(loopback) // API start: no usable address yet
	w := NewWatcher(src)
	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if ip := w.PrimaryIP(); ip != nil {
		t.Fatalf("primary at start = %v, want none", ip)
	}

	rec := newRecorder()
	w.Subscribe(rec.fn)
	if got := rec.waitFor(t, 1); got[0] != "none" {
		t.Fatalf("replay = %v, want [none]", got)
	}

	src.set(loopback, fallback, linkLocal)
	rec.waitFor(t, 2)
	if got := w.PrimaryIP().String(); got != "192.168.1.2" {
		t.Fatalf("after fallback: primary = %s", got)
	}

	src.set(loopback, fallback, lease)
	rec.waitFor(t, 3)
	if got := w.PrimaryIP().String(); got != "192.168.1.226" {
		t.Fatalf("after late lease: primary = %s", got)
	}

	src.set(loopback, lease)
	rec.waitFor(t, 4)

	src.set(loopback, linkLocal)
	got := rec.waitFor(t, 5)
	if w.PrimaryIP() != nil {
		t.Fatalf("after lease loss: primary = %v, want none", w.PrimaryIP())
	}

	want := []string{
		"none",
		"192.168.1.2 (end0, static)",
		"192.168.1.226 (end0, dhcp) + 192.168.1.2 (end0, static)",
		"192.168.1.226 (end0, dhcp)",
		"none",
	}
	if len(got) != len(want) {
		t.Fatalf("transitions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("transition %d = %q, want %q (all: %v)", i, got[i], want[i], got)
		}
	}
}

// An event that leaves the usable set unchanged — a tailnet or docker address
// coming and going — must not call subscribers: every call can rebind a
// listener or submit a job.
func TestWatcher_IgnoresIrrelevantChanges(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := newFakeSource(lease)
	w := NewWatcher(src)
	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	rec := newRecorder()
	w.Subscribe(rec.fn)
	rec.waitFor(t, 1)

	src.set(lease, tailnet, docker0)
	src.set(lease, tailnet)
	// A real change afterwards proves the irrelevant ones were processed first
	// and dropped, rather than still queued.
	src.set(fallback)
	got := rec.waitFor(t, 2)
	if len(got) != 2 || got[1] != "192.168.1.2 (end0, static)" {
		t.Fatalf("transitions = %v, want the replay and the one real change", got)
	}
}

// A failed list keeps the last good snapshot rather than dropping to "none",
// which would stop the nameserver over a transient read error.
func TestWatcher_ListErrorKeepsSnapshot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := newFakeSource(lease)
	w := NewWatcher(src)
	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	rec := newRecorder()
	w.Subscribe(rec.fn)
	rec.waitFor(t, 1)

	src.mu.Lock()
	src.listErr = errors.New("netlink: boom")
	src.mu.Unlock()
	drain(src.lists)
	src.ch <- struct{}{}
	// Wait until the Watcher has actually hit the failing List.
	if err := <-src.lists; err == nil {
		t.Fatal("expected the failing List to run")
	}

	// Recover and change; the error in between produced no transition.
	src.mu.Lock()
	src.listErr = nil
	src.mu.Unlock()
	src.set(fallback)
	got := rec.waitFor(t, 2)
	if len(got) != 2 || got[1] != "192.168.1.2 (end0, static)" {
		t.Fatalf("transitions = %v", got)
	}
}

func drain(ch chan error) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// With no event subscription the Watcher still reports the start-time address,
// and says why it will not follow changes.
func TestWatcher_SubscribeErrorStillScans(t *testing.T) {
	src := newFakeSource(fallback)
	src.subErr = errors.ErrUnsupported
	w := NewWatcher(src)
	if err := w.Start(context.Background()); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("Start err = %v, want ErrUnsupported", err)
	}
	if got := w.PrimaryIP(); got == nil || got.String() != "192.168.1.2" {
		t.Fatalf("primary = %v, want the start-time scan", got)
	}
}

// syncBuffer is a goroutine-safe log sink: the Watcher logs from its own
// goroutine while the test reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	b := &syncBuffer{}
	prev := log.Writer()
	log.SetOutput(b)
	t.Cleanup(func() { log.SetOutput(prev) })
	return b
}

const subscriptionEnded = "address subscription ended"

// TestWatcher_SubscriptionEndWarns: the kernel subscription breaking while the
// api is still running is the one case where changes silently stop being
// followed, so it must say so. The channel closing because ctx was cancelled is
// a shutdown, and must not.
func TestWatcher_SubscriptionEndWarns(t *testing.T) {
	waitLoop := func(t *testing.T, w *Watcher) {
		t.Helper()
		select {
		case <-w.loopDone:
		case <-time.After(5 * time.Second): // bounds a broken test only
			t.Fatal("watcher loop did not exit after its channel closed")
		}
	}

	t.Run("channel closes with ctx live: warns", func(t *testing.T) {
		out := captureLog(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		src := newFakeSource(lease)
		w := NewWatcher(src)
		if err := w.Start(ctx); err != nil {
			t.Fatal(err)
		}
		close(src.ch)
		waitLoop(t, w)
		if !strings.Contains(out.String(), subscriptionEnded) || !strings.Contains(out.String(), "192.168.1.226") {
			t.Fatalf("want a %q warning naming the address still in use; log:\n%s", subscriptionEnded, out.String())
		}
	})

	t.Run("ctx cancelled: silent", func(t *testing.T) {
		out := captureLog(t)
		ctx, cancel := context.WithCancel(context.Background())
		src := newFakeSource(lease)
		w := NewWatcher(src)
		if err := w.Start(ctx); err != nil {
			t.Fatal(err)
		}
		// A real Source closes its channel because ctx ended.
		cancel()
		close(src.ch)
		waitLoop(t, w)
		if strings.Contains(out.String(), subscriptionEnded) {
			t.Fatalf("warned on a normal shutdown; log:\n%s", out.String())
		}
	})
}
