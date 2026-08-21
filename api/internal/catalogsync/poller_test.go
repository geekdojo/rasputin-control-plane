package catalogsync

import (
	"context"
	"errors"
	"testing"
	"time"
)

var errBadSig = errors.New("wrong purpose")

func TestPoller_RefreshTriggersASync(t *testing.T) {
	h := newHub(t)
	h.release(4, true, mustBundle(t, 4), []byte("sig"))
	s, _ := newStore(t, &fakeVerifier{}, bundle(1, "floor"))

	p := NewPoller(h.fetcher("dev"), s)
	p.Interval = time.Hour // the ticker must not be what makes this pass
	p.StartupDelay = 0     // the delay exists for real hardware, not for tests

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)
	p.Refresh()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if s.Current().Version == 4 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("catalog never updated; still v%d", s.Current().Version)
}

// A second click while a fetch is in flight must not queue a second fetch.
// Buffered-by-one is the mechanism; this asserts the behaviour rather than
// the implementation.
func TestPoller_RefreshDoesNotQueueOrBlock(t *testing.T) {
	h := newHub(t)
	p := NewPoller(h.fetcher("dev"), nil)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			p.Refresh()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Refresh blocked; it must never block the caller")
	}
	if got := len(p.refresh); got != 1 {
		t.Errorf("queued %d refreshes; a burst must collapse to one", got)
	}
}

// Null-vs-zero matters: a cluster that has never reached the internet must not
// render the same as one that checked and found nothing.
func TestPoller_LastCheckedIsZeroUntilAPollCompletes(t *testing.T) {
	h := newHub(t)
	s, _ := newStore(t, &fakeVerifier{}, bundle(1, "floor"))
	p := NewPoller(h.fetcher("dev"), s)

	if at, err := p.LastChecked(); !at.IsZero() || err != nil {
		t.Fatalf("before any poll: got (%v, %v), want (zero, nil)", at, err)
	}

	p.once(context.Background())
	at, err := p.LastChecked()
	if at.IsZero() {
		t.Fatal("after a poll, LastChecked must be set")
	}
	if err != nil {
		t.Fatalf("poll against an empty channel should not error: %v", err)
	}
}

// A failed poll is a normal condition behind someone's home router. It must be
// recorded, not propagated, and it must not disturb the catalog.
func TestPoller_FailureIsRecordedAndTheCatalogSurvives(t *testing.T) {
	h := newHub(t)
	h.release(9, true, mustBundle(t, 9), []byte("sig"))
	s, _ := newStore(t, &fakeVerifier{err: errBadSig}, bundle(2, "floor"))
	p := NewPoller(h.fetcher("dev"), s)

	p.once(context.Background())

	at, err := p.LastChecked()
	if at.IsZero() || err == nil {
		t.Fatalf("a failure must be recorded: (%v, %v)", at, err)
	}
	if got := s.Current().Version; got != 2 {
		t.Fatalf("catalog changed to v%d on a failed poll; must stay v2", got)
	}
}

func TestPoller_StopsWhenTheContextIsCancelled(t *testing.T) {
	h := newHub(t)
	s, _ := newStore(t, &fakeVerifier{}, bundle(1, "floor"))
	p := NewPoller(h.fetcher("dev"), s)

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { p.Run(ctx); close(stopped) }()
	cancel()

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return on cancellation; it must not outlive the api")
	}
}
