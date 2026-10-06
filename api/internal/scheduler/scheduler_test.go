package scheduler

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// embeddedNATS spins a one-shot in-process server for the runner's emit
// path (which Publish-es job events) and for any registered workflow's NATS
// access.
func embeddedNATS(t *testing.T) *nats.Conn {
	t.Helper()
	opts := &server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true}
	ns, err := server.NewServer(opts)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(2 * time.Second) {
		t.Fatal("nats not ready")
	}
	t.Cleanup(func() {
		ns.Shutdown()
		ns.WaitForShutdown()
	})
	nc, err := nats.Connect("", nats.InProcessServer(ns))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { nc.Close() })
	return nc
}

func newRunner(t *testing.T, nc *nats.Conn) *jobs.Runner {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	store, err := jobs.OpenStore(ctx, filepath.Join(dir, "jobs.db"))
	if err != nil {
		t.Fatalf("jobs.OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return jobs.NewRunner(store, nc)
}

// countingWorkflow registers a workflow that increments a counter on every
// fire. The workflow has one no-op step; the runner's Submit creates the row
// and kicks off the goroutine; we only need to know it was submitted to
// observe the counter advancing.
func countingWorkflow(kind string, counter *int64) jobs.Workflow {
	return jobs.Workflow{
		Kind: kind,
		Steps: []jobs.WorkflowStep{
			{
				Name: "tick", Timeout: time.Second,
				Do: func(sc *jobs.StepCtx) (json.RawMessage, error) {
					atomic.AddInt64(counter, 1)
					return json.RawMessage(`{}`), nil
				},
			},
		},
	}
}

// ============================================================================
// New
// ============================================================================

func TestNew_HoldsEntries(t *testing.T) {
	nc := embeddedNATS(t)
	r := newRunner(t, nc)
	s := New(r, []Entry{
		{Kind: "a", Interval: time.Minute},
		{Kind: "b", Interval: time.Minute},
	})
	if len(s.entries) != 2 {
		t.Errorf("want 2 entries, got %d", len(s.entries))
	}
}

// ============================================================================
// Start / Stop
// ============================================================================

func TestStart_FiresImmediatelyWithSmallInitialDelay(t *testing.T) {
	nc := embeddedNATS(t)
	r := newRunner(t, nc)

	var fired int64
	r.Register(countingWorkflow("tick.test", &fired))

	s := New(r, []Entry{
		{
			Kind: "tick.test",
			// Interval gets clamped to 30s minimum, but InitialDelay is honored
			// untouched (when >0) and that's the only fire we wait for.
			Interval:     time.Hour,
			InitialDelay: time.Nanosecond,
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	defer s.Stop()

	// Wait briefly for the initial fire. We're observing the counter the
	// no-op workflow increments — once it hits 1 we know Submit ran and the
	// saga completed.
	waitFor(t, &fired, 1, 2*time.Second)
}

func TestStart_IsIdempotent(t *testing.T) {
	nc := embeddedNATS(t)
	r := newRunner(t, nc)
	s := New(r, nil) // no entries → no goroutines, but Start should still record started
	ctx := context.Background()
	s.Start(ctx)
	s.Start(ctx) // second call should no-op
	if !s.started {
		t.Error("expected started=true")
	}
	s.Stop()
}

func TestStop_BeforeStartIsSafe(t *testing.T) {
	nc := embeddedNATS(t)
	r := newRunner(t, nc)
	s := New(r, nil)
	// Should not deadlock or panic.
	s.Stop()
}

func TestStop_TerminatesEntryGoroutines(t *testing.T) {
	nc := embeddedNATS(t)
	r := newRunner(t, nc)
	var fired int64
	r.Register(countingWorkflow("noop", &fired))
	s := New(r, []Entry{{
		Kind:         "noop",
		Interval:     time.Hour,
		InitialDelay: time.Nanosecond,
	}})
	ctx := context.Background()
	s.Start(ctx)
	waitFor(t, &fired, 1, 2*time.Second)
	done := make(chan struct{})
	go func() { s.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return in time")
	}
}

// ============================================================================
// fire / submit-error path
// ============================================================================

// lockedBuffer is a log sink safe for writers on other goroutines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLog sends the standard logger to a buffer for the test.
func captureLog(t *testing.T) *lockedBuffer {
	t.Helper()
	var b lockedBuffer
	prev := log.Writer()
	log.SetOutput(&b)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &b
}

// A refused submit is logged with the kind and the reason, and a successful
// one logs no submit line.
func TestFire_UnknownKindLogged(t *testing.T) {
	nc := embeddedNATS(t)
	r := newRunner(t, nc)
	var fired int64
	r.Register(countingWorkflow("known.kind", &fired))
	s := New(r, nil)
	logs := captureLog(t)
	ctx := context.Background()

	s.fire(ctx, "unknown.kind", json.RawMessage(`{}`), "tester")
	if got := logs.String(); !strings.Contains(got, "scheduler: submit unknown.kind: ") {
		t.Errorf("log = %q, want the refused submit logged", got)
	}

	s.fire(ctx, "known.kind", json.RawMessage(`{}`), "tester")
	waitFor(t, &fired, 1, 2*time.Second)
	if got := logs.String(); strings.Contains(got, "scheduler: submit known.kind") {
		t.Errorf("log = %q, want no submit line for a submit that succeeded", got)
	}
}

// ============================================================================
// runEntry default knobs (defaults applied when fields zero)
// ============================================================================

func TestRunEntry_DefaultCreatedByAndSpec(t *testing.T) {
	nc := embeddedNATS(t)
	r := newRunner(t, nc)
	var fired int64
	r.Register(countingWorkflow("defaults", &fired))

	s := New(r, []Entry{{
		Kind: "defaults",
		// No Spec, no CreatedBy, no InitialDelay → all should default cleanly.
		Interval:     time.Hour,
		InitialDelay: time.Nanosecond,
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	defer s.Stop()
	waitFor(t, &fired, 1, 2*time.Second)
}

func TestRunEntry_RespectsExplicitCreatedBy(t *testing.T) {
	nc := embeddedNATS(t)
	r := newRunner(t, nc)
	var fired int64
	r.Register(countingWorkflow("explicit-by", &fired))
	s := New(r, []Entry{{
		Kind:         "explicit-by",
		CreatedBy:    "test-runner",
		Spec:         json.RawMessage(`{"a":1}`),
		Interval:     time.Hour,
		InitialDelay: time.Nanosecond,
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	defer s.Stop()
	waitFor(t, &fired, 1, 2*time.Second)
}

// ============================================================================
// runEntry: ctx-cancel during initial delay returns cleanly
// ============================================================================

func TestRunEntry_CancelDuringInitialDelay(t *testing.T) {
	nc := embeddedNATS(t)
	r := newRunner(t, nc)
	var fired int64
	r.Register(countingWorkflow("slow", &fired))
	s := New(r, []Entry{{
		Kind:         "slow",
		Interval:     time.Hour,
		InitialDelay: time.Hour, // long
	}})
	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)
	cancel() // cancel before InitialDelay elapses
	doneCh := make(chan struct{})
	go func() { s.Stop(); close(doneCh) }()
	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return after ctx cancel during InitialDelay")
	}
	// Counter should be 0 — nothing fired.
	if atomic.LoadInt64(&fired) != 0 {
		t.Errorf("want 0 fires, got %d", atomic.LoadInt64(&fired))
	}
}

// ============================================================================
// Helpers
// ============================================================================

// waitFor polls counter until it reaches want or the deadline elapses.
// Polling interval is 10ms which is well under the 100ms sleep cap and
// makes the tests robust without being flaky.
func waitFor(t *testing.T, counter *int64, want int64, deadline time.Duration) {
	t.Helper()
	timeout := time.After(deadline)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			if atomic.LoadInt64(counter) >= want {
				return
			}
		case <-timeout:
			t.Fatalf("counter never reached %d (got %d) within %v", want, atomic.LoadInt64(counter), deadline)
		}
	}
}

// Ensure scheduler.runEntry's interval-clamp guard is hit at least once.
func TestRunEntry_ClampsTooSmallInterval(t *testing.T) {
	nc := embeddedNATS(t)
	r := newRunner(t, nc)
	var fired int64
	r.Register(countingWorkflow("clamp", &fired))
	// Interval=1s (below 30s floor) — should get clamped to 30s. We only need
	// the initial fire to land before we Stop, so we don't actually wait the
	// 30s second tick.
	s := New(r, []Entry{{
		Kind:         "clamp",
		Interval:     time.Second,
		InitialDelay: time.Nanosecond,
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	defer s.Stop()
	waitFor(t, &fired, 1, 2*time.Second)
}

// Sanity: a no-entry scheduler Start/Stop runs cleanly under -race.
func TestNoEntries_StartStopClean(t *testing.T) {
	nc := embeddedNATS(t)
	r := newRunner(t, nc)
	s := New(r, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	// no entries means no wg.Add → wg.Wait returns immediately.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.Stop()
	}()
	wg.Wait()
}

// ============================================================================
// fire: the raw entry point (geekdojo/geekdojo-brain#825)
// ============================================================================

// TC-825-21: an entry's spec is raw JSON by nature, so fire submits it through
// SubmitRawSpec. An empty spec is stored as {} and a non-empty one as given,
// with no ErrRawSpec raised.
func TestFire_SubmitsTheEntrySpecThroughTheRawEntryPoint(t *testing.T) {
	nc := embeddedNATS(t)
	ctx := context.Background()
	store, err := jobs.OpenStore(ctx, filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatalf("jobs.OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	r := jobs.NewRunner(store, nc)
	var fired int64
	r.Register(countingWorkflow("raw.empty", &fired))
	r.Register(countingWorkflow("raw.given", &fired))
	s := New(r, nil)

	s.fire(ctx, "raw.empty", nil, "tester")
	s.fire(ctx, "raw.given", json.RawMessage(`{"a": [1, 2]}`), "tester")
	r.Wait()

	for kind, want := range map[string]string{"raw.empty": `{}`, "raw.given": `{"a": [1, 2]}`} {
		js, err := store.ListJobsByKind(ctx, kind, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(js) != 1 {
			t.Fatalf("%s: %d jobs, want 1 (a refused submit is only logged, so a missing job is the ErrRawSpec symptom)", kind, len(js))
		}
		if string(js[0].Spec) != want {
			t.Errorf("%s: stored spec %s, want %s", kind, js[0].Spec, want)
		}
	}
	if atomic.LoadInt64(&fired) != 2 {
		t.Errorf("%d jobs ran, want 2", fired)
	}
}
