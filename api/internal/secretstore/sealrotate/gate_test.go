package sealrotate

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// fakeState is a stateReader whose tree a test sets.
type fakeState struct {
	mu   sync.Mutex
	tree Tree
	err  error
}

func (f *fakeState) State() (Tree, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tree, f.err
}

func (f *fakeState) set(shape Shape) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tree = Tree{Fragment: Fragment{Shape: shape, Current: idB}}
}

func newGate(t *testing.T, st *fakeState, running func(context.Context, string) (bool, error)) *Gate {
	t.Helper()
	if running == nil {
		running = func(context.Context, string) (bool, error) { return true, nil }
	}
	log, _ := logkittest.New()
	g, err := NewGate(st, running, log)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// TC-830-08 (a): two TryAcquire calls racing: exactly one wins, and the loser
// is told another rotation runs.
func TestGate_TryAcquireRace(t *testing.T) {
	st := &fakeState{}
	st.set(Clean)
	g := newGate(t, st, nil)
	var wins atomic.Int32
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if errs[i] = g.TryAcquire([]string{"rot-1", "rot-2"}[i]); errs[i] == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d winners, want 1", wins.Load())
	}
	for _, err := range errs {
		if err != nil && !errors.Is(err, errAnotherRotation) {
			t.Errorf("loser's error = %v, want errAnotherRotation", err)
		}
	}
	if g.RotationHolder() == "" {
		t.Error("no rotation holder after a win")
	}
}

// TC-830-08 (b): Acquire waits while a rotation holds the gate, and returns
// only after the release, with the state Clean.
func TestGate_AcquireWaitsForTheRotation(t *testing.T) {
	st := &fakeState{}
	st.set(Staged)
	g := newGate(t, st, nil)
	if err := g.TryAcquire("rot"); err != nil {
		t.Fatal(err)
	}
	var released atomic.Bool
	done := make(chan error, 1)
	go func() { done <- g.Acquire(t.Context(), "backup") }()
	// The waiter is blocked on the gate's channel; nothing else can return it.
	select {
	case err := <-done:
		t.Fatalf("Acquire returned %v while the rotation held the gate", err)
	default:
	}
	st.set(Clean)
	released.Store(true)
	g.Release("rot")
	if err := <-done; err != nil {
		t.Fatalf("Acquire after the release = %v", err)
	}
	if !released.Load() {
		t.Fatal("Acquire returned before the release")
	}
	if err := g.TryAcquire("rot-2"); !errors.Is(err, errBackupHolds) {
		t.Errorf("TryAcquire while the backup holds = %v, want errBackupHolds", err)
	}
	g.Release("backup")
	if err := g.TryAcquire("rot-2"); err != nil {
		t.Errorf("TryAcquire after the backup released = %v", err)
	}
}

// TC-830-08 (c), (d): a state that is not Clean refuses with a sentence, at
// once when nothing holds the gate, and after the wait when the rotation
// releases short of Clean. An unreadable state refuses too.
func TestGate_AcquireRefusesWhenNotClean(t *testing.T) {
	st := &fakeState{}
	st.set(Staged)
	g := newGate(t, st, nil)
	err := g.Acquire(t.Context(), "backup")
	if !errors.Is(err, errBackupRotationIncomplete) || !isSentence(err.Error()) {
		t.Fatalf("(c) Acquire = %v, want the incomplete-rotation sentence", err)
	}

	if err := g.TryAcquire("rot"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- g.Acquire(t.Context(), "backup") }()
	st.set(Verify)
	g.Release("rot")
	if err := <-done; !errors.Is(err, errBackupRotationIncomplete) {
		t.Fatalf("(d) Acquire after a release short of Clean = %v", err)
	}

	st.mu.Lock()
	st.err = errors.New("seal.hcl unreadable")
	st.mu.Unlock()
	if err := g.Acquire(t.Context(), "backup"); !errors.Is(err, errBackupSealUnreadable) || !isSentence(err.Error()) {
		t.Fatalf("Acquire with an unreadable tree = %v", err)
	}
}

// TC-830-08 (e): a cancelled ctx ends the wait with its error.
func TestGate_AcquireCancelled(t *testing.T) {
	st := &fakeState{}
	st.set(Clean)
	g := newGate(t, st, nil)
	if err := g.TryAcquire("rot"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- g.Acquire(ctx, "backup") }()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Acquire = %v, want context.Canceled", err)
	}
	if g.RotationHolder() != "rot" {
		t.Error("the cancelled wait disturbed the holder")
	}
}

// TC-830-08 (f): Release is idempotent, and a non-holder's release frees
// nothing.
func TestGate_ReleaseIdempotent(t *testing.T) {
	st := &fakeState{}
	st.set(Clean)
	g := newGate(t, st, nil)
	if err := g.TryAcquire("rot"); err != nil {
		t.Fatal(err)
	}
	g.Release("someone-else")
	g.Release("")
	if g.RotationHolder() != "rot" {
		t.Fatal("a non-holder's release freed the gate")
	}
	g.Release("rot")
	g.Release("rot")
	if g.RotationHolder() != "" {
		t.Fatal("the gate is still held")
	}
	if err := g.TryAcquire("rot"); err != nil {
		t.Fatal(err)
	}
	if err := g.TryAcquire("rot"); err != nil {
		t.Errorf("the holder's second TryAcquire = %v", err)
	}
}

// A holder whose job is no longer running is dropped, so a leaked hold cannot
// block every backup.
func TestGate_StaleHolderDropped(t *testing.T) {
	st := &fakeState{}
	st.set(Clean)
	g := newGate(t, st, func(context.Context, string) (bool, error) { return false, nil })
	if err := g.TryAcquire("rot-dead"); err != nil {
		t.Fatal(err)
	}
	if err := g.Acquire(t.Context(), "backup"); err != nil {
		t.Fatalf("Acquire past a dead holder = %v", err)
	}
}

func TestNewGate_Refuses(t *testing.T) {
	log, _ := logkittest.New()
	run := func(context.Context, string) (bool, error) { return true, nil }
	if _, err := NewGate(nil, run, log); err == nil {
		t.Error("nil state accepted")
	}
	if _, err := NewGate(&fakeState{}, nil, log); err == nil {
		t.Error("nil JobRunning accepted")
	}
	if _, err := NewGate(&fakeState{}, run, nil); err == nil {
		t.Error("nil logger accepted")
	}
}
