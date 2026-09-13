package lanaddr

import (
	"context"
	"log"
	"net"
	"sync"
)

// Source is where the node's addresses come from. The production Source is the
// kernel ([SystemSource]); tests inject their own so no netlink socket is needed.
type Source interface {
	// Subscribe starts listening for address changes. The returned channel
	// receives a value after any address is added to or removed from the node.
	// Deliveries coalesce — one pending value stands for any number of changes —
	// because the receiver re-lists the whole set rather than applying deltas.
	// The channel is closed when ctx ends or the subscription breaks.
	//
	// It is called BEFORE the first List, so a change landing between the two is
	// delivered rather than lost.
	Subscribe(ctx context.Context) (<-chan struct{}, error)
	// List returns every IPv4 address the node holds right now, unfiltered.
	List() ([]Addr, error)
}

// Watcher holds the current [Snapshot] and calls subscribers when it changes.
type Watcher struct {
	src Source

	mu  sync.Mutex
	cur Snapshot

	// dispatchMu serializes every call into a subscriber — the change loop and a
	// new subscriber's replay alike — so each subscriber sees snapshots in the
	// order they happened and never two at once.
	dispatchMu sync.Mutex
	subs       []func(prev, next Snapshot)

	// loopDone is closed when the change loop exits (or at once, when there was
	// no subscription to loop over). Tests wait on it; nothing else needs to.
	loopDone chan struct{}
}

// NewWatcher builds a Watcher over src. Call Start to begin.
func NewWatcher(src Source) *Watcher {
	return &Watcher{src: src, loopDone: make(chan struct{})}
}

// Start subscribes to address changes, takes the initial snapshot, and follows
// changes until ctx ends. It returns once the initial snapshot is in place, so
// Snapshot and PrimaryIP are meaningful as soon as it returns.
//
// A subscription error is returned, but the Watcher still takes the initial
// snapshot: the caller gets the start-time address, and the error says it will
// not follow changes. That is strictly better than no address, and it is what a
// non-Linux dev box gets.
func (w *Watcher) Start(ctx context.Context) error {
	ch, subErr := w.src.Subscribe(ctx)
	w.refresh()
	if subErr != nil {
		close(w.loopDone)
		return subErr
	}
	go func() {
		defer close(w.loopDone)
		for range ch {
			w.refresh()
		}
		if ctx.Err() == nil {
			// Nothing will tell us about a change from here on. Say so loudly
			// rather than re-subscribing on a timer; the next api start
			// subscribes again.
			log.Printf("lanaddr: address subscription ended; LAN address changes are no longer followed (current: %s)", w.Snapshot())
		}
	}()
	return nil
}

// refresh re-lists the addresses and, when the usable set changed, dispatches
// the change. A List error keeps the previous snapshot: the kernel's next
// address event lists again.
func (w *Watcher) refresh() {
	addrs, err := w.src.List()
	if err != nil {
		log.Printf("lanaddr: list addresses: %v (keeping %s)", err, w.Snapshot())
		return
	}
	next := Select(addrs)

	w.dispatchMu.Lock()
	defer w.dispatchMu.Unlock()
	w.mu.Lock()
	prev := w.cur
	if prev.Equal(next) {
		w.mu.Unlock()
		return
	}
	w.cur = next
	subs := append([]func(prev, next Snapshot){}, w.subs...)
	w.mu.Unlock()

	log.Printf("lanaddr: LAN IPv4 %s -> %s", prev, next)
	for _, fn := range subs {
		fn(prev, next)
	}
}

// Subscribe registers fn and immediately calls it once with a zero prev and the
// current snapshot, so a subscriber added after Start misses nothing and needs
// no separate "initial value" path. After that fn is called on every change.
//
// fn runs serialized with every other subscriber call and must not call
// Subscribe itself.
func (w *Watcher) Subscribe(fn func(prev, next Snapshot)) {
	w.dispatchMu.Lock()
	defer w.dispatchMu.Unlock()
	w.mu.Lock()
	w.subs = append(w.subs, fn)
	cur := w.cur
	w.mu.Unlock()
	fn(Snapshot{}, cur)
}

// Snapshot returns the current snapshot.
func (w *Watcher) Snapshot() Snapshot {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cur
}

// PrimaryIP returns the current primary LAN IPv4, or nil when the node has none.
// It reads the watcher's state and does no I/O, so it is cheap enough to call
// per DNS query.
func (w *Watcher) PrimaryIP() net.IP {
	return w.Snapshot().PrimaryIP()
}
