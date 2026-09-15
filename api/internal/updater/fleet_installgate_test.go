package updater

import (
	"fmt"
	"sync"
	"time"
)

// ----- the install barrier ------------------------------------------------

// installHoldDeadline bounds how long one held install waits for the rest of
// its batch. Generous: it only ever fires when the batch can never form, and
// then its job is to say so rather than to wedge the run.
const installHoldDeadline = 30 * time.Second

// installGate makes "k installs overlap" a FACT the harness waits for rather
// than something 150ms installs happen to produce.
//
// Every gated node blocks inside its install. A batch is released only when
// BOTH of these are true:
//
//   - exactly min(k, gated nodes not yet released) nodes are held inside their
//     installs at once, and
//   - the harness has RECEIVED node_started for every one of them.
//
// The first makes the sim-side peak reach k by construction. The second makes
// the wire-side peak reach k by construction: at that moment k node_started
// events are delivered and none of their terminal events can have been
// published, because those nodes are still inside their installs.
//
// At the moment of release the gate also checks that nothing ELSE is started —
// no node outside the held batch sits between its first precheck and its
// mark-good. A node in that window is provably inside its scheduler slot, so
// for a scheduler that holds k the count is exactly k, and a (k+1)th start
// while k are held is named rather than inferred.
//
// ⚠️ What this cannot prove is a NEGATIVE that has not happened yet: a
// scheduler that leaks a (k+1)th slot is caught when that extra start has
// reached its precheck, its install, or its node_started by the time it is
// looked for — which in practice is every run, but is not a construction. A
// scheduler that holds k can never fail it.
type installGate struct {
	f     *fleet
	mu    sync.Mutex
	k     int
	gated map[string]bool
	// released counts gated nodes already let through, so the last batch asks
	// for only as many as remain.
	released int
	held     []string
	release  map[string]chan struct{}
	started  map[string]bool
	// batches records the size of every batch released, in order.
	batches []int
	faults  []string
	// broken is set once a deadline fires: the gate has already failed the
	// test by name, and holding further installs would only wedge the run.
	broken bool
}

// holdInstallsInBatches installs a gate over the named nodes for the next run.
func (f *fleet) holdInstallsInBatches(k int, nodeIDs []string) *installGate {
	g := &installGate{
		f: f, k: k,
		gated:   map[string]bool{},
		release: map[string]chan struct{}{},
		started: map[string]bool{},
	}
	for _, id := range nodeIDs {
		g.gated[id] = true
	}
	f.gaugeMu.Lock()
	f.gate = g
	f.gaugeMu.Unlock()
	return g
}

// installGate returns the fleet's gate, or nil. Read under gaugeMu: it is set
// by the test goroutine and read from NATS callbacks.
func (f *fleet) installGate() *installGate {
	f.gaugeMu.Lock()
	defer f.gaugeMu.Unlock()
	return f.gate
}

// hold blocks a gated node inside its install until its batch is released.
func (g *installGate) hold(id string) {
	g.mu.Lock()
	if g.broken || !g.gated[id] {
		g.mu.Unlock()
		return
	}
	ch := make(chan struct{})
	g.held = append(g.held, id)
	g.release[id] = ch
	g.tryReleaseLocked()
	g.mu.Unlock()

	select {
	case <-ch:
	case <-time.After(installHoldDeadline):
		g.mu.Lock()
		defer g.mu.Unlock()
		if _, still := g.release[id]; !still {
			return // released in the same instant the deadline fired
		}
		g.faults = append(g.faults, fmt.Sprintf(
			"%s was held in its install for %s and its batch never formed: needed %d installs in flight "+
				"together with node_started seen for each, had %v held (node_started seen: %v) — the fan-out "+
				"never reached k=%d", id, installHoldDeadline, g.needLocked(), g.held, g.startedHeldLocked(), g.k))
		g.broken = true
		g.releaseHeldLocked()
	}
}

// sawStarted records that the harness received node_started for a node.
func (g *installGate) sawStarted(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.started[id] = true
	g.tryReleaseLocked()
}

func (g *installGate) needLocked() int {
	remaining := len(g.gated) - g.released
	if remaining < g.k {
		return remaining
	}
	return g.k
}

func (g *installGate) startedHeldLocked() []string {
	var out []string
	for _, id := range g.held {
		if g.started[id] {
			out = append(out, id)
		}
	}
	return out
}

func (g *installGate) tryReleaseLocked() {
	if g.broken || len(g.held) == 0 {
		return
	}
	if len(g.held) > g.needLocked() {
		g.faults = append(g.faults, fmt.Sprintf(
			"%d installs held at once %v, more than a batch of %d — a (k+1)th node reached its install",
			len(g.held), g.held, g.needLocked()))
		g.broken = true
		g.releaseHeldLocked()
		return
	}
	if len(g.held) < g.needLocked() || len(g.startedHeldLocked()) != len(g.held) {
		return
	}
	// The batch is formed. Before letting it go: is anything else started?
	heldSet := map[string]bool{}
	for _, id := range g.held {
		heldSet[id] = true
	}
	var extra []string
	for _, id := range g.f.order {
		if heldSet[id] {
			continue
		}
		n := g.f.nodes[id]
		n.mu.Lock()
		// Healthy nodes only: a node that fails is never marked good, so for
		// any other behaviour "not yet marked good" does not mean "in a slot".
		inSlot := n.prechecks > 0 && n.markGoods == 0 && n.spec.Behaviour == simHealthy
		n.mu.Unlock()
		if inSlot {
			extra = append(extra, id)
		}
	}
	if len(extra) > 0 {
		g.faults = append(g.faults, fmt.Sprintf(
			"while %v were held in their installs, %v had also been started (prechecked, not yet marked good) — "+
				"more than k=%d nodes in flight", g.held, extra, g.k))
	}
	g.batches = append(g.batches, len(g.held))
	g.releaseHeldLocked()
}

func (g *installGate) releaseHeldLocked() {
	for _, id := range g.held {
		close(g.release[id])
		delete(g.release, id)
		g.released++
	}
	g.held = nil
}

func (g *installGate) faultList() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.faults...)
}

func (g *installGate) batchSizes() []int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]int(nil), g.batches...)
}
