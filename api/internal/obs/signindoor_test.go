package obs

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// fakeDoorReading answers each door's up fact; with block set, a reading
// waits on it until it is closed, or the context ends.
type fakeDoorReading struct {
	up    map[string]bool
	err   map[string]error
	block chan struct{}
	// entered is signalled on each reading's start.
	entered chan string
}

func (f *fakeDoorReading) DoorUp(ctx context.Context, door string) (bool, error) {
	if f.entered != nil {
		f.entered <- door
	}
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	return f.up[door], f.err[door]
}

type fakeDoorCounts struct{}

func (fakeDoorCounts) DoorCounts(door string, _ time.Time) (uint64, int) {
	if door == "home" {
		return 7, 2
	}
	return 3, 0
}

// recordingWriter records each WriteSeries call, failing with err.
type recordingWriter struct {
	mu    sync.Mutex
	calls [][]Series
	nodes []string
	err   error
}

func (w *recordingWriter) WriteSeries(_ context.Context, nodeID string, _ time.Time, s []Series) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls = append(w.calls, s)
	w.nodes = append(w.nodes, nodeID)
	return w.err
}

func newDoorSink(t *testing.T, inner Sink, r SigninDoorReading, w SeriesWriter) (*SigninDoorSink, *logkittest.Recorder) {
	t.Helper()
	log, rec := logkittest.New()
	s, err := NewSigninDoorSink(inner, SigninDoorDeps{Reading: r, Counts: fakeDoorCounts{}, Writer: w, SelfNodeID: testSelf,
		Now: func() time.Time { return testNow }, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	return s, rec
}

// TC-986-17: another node's sample is forwarded and writes no door series;
// the control plane's own sample writes the three series per door, under the
// self node id, through the VM sink with the rasputin_ prefix; a door whose
// fact cannot be read writes 0.
func TestSigninDoorSink_WritesThreeSeriesPerDoor(t *testing.T) {
	var (
		mu     sync.Mutex
		bodies []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	vm, err := NewVMSink(VMSinkConfig{Supervisor: &fakeSupervisor{healthy: true, baseURL: srv.URL}})
	if err != nil {
		t.Fatal(err)
	}
	inner := &captureSink{}
	reading := &fakeDoorReading{up: map[string]bool{"home": true, "app": true}, err: map[string]error{"app": errors.New("store down")}}
	s, rec := newDoorSink(t, inner, reading, vm)
	ctx := context.Background()
	other := &proto.MetricsEvt{NodeID: "node-2", Ts: testNow, Metrics: map[string]float64{"cpu_percent": 1}}
	self := &proto.MetricsEvt{NodeID: testSelf, Ts: testNow, Metrics: map[string]float64{"cpu_percent": 2}}
	if err := s.Write(ctx, other); err != nil {
		t.Fatal(err)
	}
	s.Wait()
	mu.Lock()
	n := len(bodies)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("another node's sample wrote %d bodies", n)
	}
	if err := s.Write(ctx, self); err != nil {
		t.Fatal(err)
	}
	s.Wait()
	ts := "1793534400000"
	want := `rasputin_signin_door_up{nodeId="cp-1",door="home"} 1 ` + ts + "\n" +
		`rasputin_signin_door_requests_total{nodeId="cp-1",door="home"} 7 ` + ts + "\n" +
		`rasputin_signin_throttled_sources{nodeId="cp-1",door="home"} 2 ` + ts + "\n" +
		`rasputin_signin_door_up{nodeId="cp-1",door="app"} 0 ` + ts + "\n" +
		`rasputin_signin_door_requests_total{nodeId="cp-1",door="app"} 3 ` + ts + "\n" +
		`rasputin_signin_throttled_sources{nodeId="cp-1",door="app"} 0 ` + ts + "\n"
	mu.Lock()
	if len(bodies) != 1 || bodies[0] != want {
		t.Errorf("bodies = %q\nwant %q", bodies, want)
	}
	mu.Unlock()
	inner.mu.Lock()
	if len(inner.got) != 2 || inner.got[0] != other || inner.got[1] != self {
		t.Errorf("inner sink got %v", inner.got)
	}
	inner.mu.Unlock()
	if got := rec.Matching(slog.LevelDebug, "a fact could not be read"); len(got) != 1 {
		t.Errorf("unreadable fact records = %d, want 1:\n%s", len(got), rec.Text())
	}
}

// TC-986-17 (F-986-01): with the reading held blocked, the self sample's
// Write and a following non-self Write return at once, a second self trigger
// is skipped, and once released one sample is written.
func TestSigninDoorSink_ReadingNeverBlocksWrite(t *testing.T) {
	inner := &captureSink{}
	reading := &fakeDoorReading{up: map[string]bool{"home": true}, block: make(chan struct{}), entered: make(chan string, 4)}
	w := &recordingWriter{}
	s, rec := newDoorSink(t, inner, reading, w)
	ctx := context.Background()
	self := &proto.MetricsEvt{NodeID: testSelf, Ts: testNow}
	if err := s.Write(ctx, self); err != nil {
		t.Fatal(err)
	}
	// The sample is now inside the reading, which cannot return: both
	// Writes below run only because Write does not wait for it.
	<-reading.entered
	if err := s.Write(ctx, &proto.MetricsEvt{NodeID: "node-2", Ts: testNow}); err != nil {
		t.Fatal(err)
	}
	if err := s.Write(ctx, self); err != nil {
		t.Fatal(err)
	}
	inner.mu.Lock()
	forwarded := len(inner.got)
	inner.mu.Unlock()
	if forwarded != 3 {
		t.Errorf("forwarded %d events while the reading was held, want 3", forwarded)
	}
	if got := rec.Matching(slog.LevelDebug, "trigger skipped"); len(got) != 1 {
		t.Errorf("skipped-trigger records = %d, want 1", len(got))
	}
	close(reading.block)
	s.Wait()
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.calls) != 1 || len(w.calls[0]) != 6 || w.nodes[0] != testSelf {
		t.Errorf("series writes = %d (%v), want one write of six series under %s", len(w.calls), w.nodes, testSelf)
	}
}

// TC-986-17: a series write error is logged at DEBUG and not returned.
func TestSigninDoorSink_WriteErrorIsLoggedNotReturned(t *testing.T) {
	inner := &captureSink{}
	w := &recordingWriter{err: errors.New("vm down")}
	s, rec := newDoorSink(t, inner, &fakeDoorReading{}, w)
	if err := s.Write(context.Background(), &proto.MetricsEvt{NodeID: testSelf, Ts: testNow}); err != nil {
		t.Fatalf("Write returned %v", err)
	}
	s.Wait()
	if got := rec.Matching(slog.LevelDebug, "sign-in door sample not written"); len(got) != 1 {
		t.Errorf("write-error records = %d, want 1:\n%s", len(got), rec.Text())
	}
}

// TC-986-17: NewSigninDoorSink refuses each missing collaborator.
func TestNewSigninDoorSink_RefusesMissingCollaborators(t *testing.T) {
	log, _ := logkittest.New()
	full := func() (Sink, SigninDoorDeps) {
		return &captureSink{}, SigninDoorDeps{Reading: &fakeDoorReading{}, Counts: fakeDoorCounts{}, Writer: &recordingWriter{},
			SelfNodeID: testSelf, Now: time.Now, Log: log}
	}
	for name, mutate := range map[string]func(*Sink, *SigninDoorDeps){
		"inner":      func(s *Sink, _ *SigninDoorDeps) { *s = nil },
		"reading":    func(_ *Sink, d *SigninDoorDeps) { d.Reading = nil },
		"counts":     func(_ *Sink, d *SigninDoorDeps) { d.Counts = nil },
		"writer":     func(_ *Sink, d *SigninDoorDeps) { d.Writer = nil },
		"self node":  func(_ *Sink, d *SigninDoorDeps) { d.SelfNodeID = "" },
		"clock":      func(_ *Sink, d *SigninDoorDeps) { d.Now = nil },
		"the logger": func(_ *Sink, d *SigninDoorDeps) { d.Log = nil },
	} {
		inner, d := full()
		mutate(&inner, &d)
		if _, err := NewSigninDoorSink(inner, d); err == nil || !strings.Contains(err.Error(), "obs: sign-in doors:") {
			t.Errorf("%s missing: err = %v", name, err)
		}
	}
	inner, d := full()
	if _, err := NewSigninDoorSink(inner, d); err != nil {
		t.Errorf("the full set refused: %v", err)
	}
}
