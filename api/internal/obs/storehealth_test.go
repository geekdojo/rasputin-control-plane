package obs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

const testSelf = "cp-1"

var testNow = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

// fakeReadings answers State from st/err, or blocks on block when set.
type fakeReadings struct {
	mu     sync.Mutex
	st     storestate.State
	err    error
	counts storestate.Counts
	block  chan struct{}
	calls  atomic.Int32
}

func (f *fakeReadings) State(context.Context) (storestate.State, error) {
	f.calls.Add(1)
	if f.block != nil {
		<-f.block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.st, f.err
}

func (f *fakeReadings) Counts() storestate.Counts { return f.counts }

func (f *fakeReadings) set(st storestate.State) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.st = st
}

// captureSink records every event; failStore fails only the store sample's
// write, and failNode fails only other events.
type captureSink struct {
	mu        sync.Mutex
	got       []*proto.MetricsEvt
	failStore error
	failNode  error
}

func isStoreSample(e *proto.MetricsEvt) bool {
	_, ok := e.Metrics[MetricSecretStoreRequestsTotal]
	return ok
}

func (c *captureSink) Write(_ context.Context, e *proto.MetricsEvt) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, e)
	if isStoreSample(e) {
		return c.failStore
	}
	return c.failNode
}

func (c *captureSink) storeSamples() []*proto.MetricsEvt {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*proto.MetricsEvt
	for _, e := range c.got {
		if isStoreSample(e) {
			out = append(out, e)
		}
	}
	return out
}

func (c *captureSink) all() []*proto.MetricsEvt {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*proto.MetricsEvt(nil), c.got...)
}

// logRecords captures slog records.
type logRecords struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (h *logRecords) Enabled(context.Context, slog.Level) bool { return true }
func (h *logRecords) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recs = append(h.recs, r.Clone())
	return nil
}
func (h *logRecords) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *logRecords) WithGroup(string) slog.Handler      { return h }

func (h *logRecords) atOrAbove(l slog.Level) []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []slog.Record
	for _, r := range h.recs {
		if r.Level >= l {
			out = append(out, r)
		}
	}
	return out
}

func attrsOf(r slog.Record) map[string]string {
	m := map[string]string{}
	r.Attrs(func(a slog.Attr) bool { m[a.Key] = a.Value.String(); return true })
	return m
}

type rig struct {
	s     *StoreHealthSink
	inner *captureSink
	r     *fakeReadings
	log   *logRecords
}

func newRig(t *testing.T, r *fakeReadings, dataBytes func() (uint64, error)) rig {
	t.Helper()
	inner := &captureSink{}
	lr := &logRecords{}
	if dataBytes == nil {
		dataBytes = func() (uint64, error) { return 4096, nil }
	}
	s, err := NewStoreHealthSink(inner, StoreHealthDeps{
		Readings: r, DataBytes: dataBytes, SelfNodeID: testSelf,
		Now: func() time.Time { return testNow }, Log: slog.New(lr),
	})
	if err != nil {
		t.Fatal(err)
	}
	return rig{s: s, inner: inner, r: r, log: lr}
}

// trigger writes one control-plane event and waits for its sample.
func (g rig) trigger(t *testing.T) {
	t.Helper()
	if err := g.s.Write(context.Background(), &proto.MetricsEvt{NodeID: testSelf, Ts: testNow, Metrics: map[string]float64{"cpu_percent": 1}}); err != nil {
		t.Fatal(err)
	}
	g.s.Wait()
}

// TC-939-04: a ready store gives all four series, with the control plane's
// id and the injected clock; a sealed one gives sealed=1.
func TestStoreHealthSink_TC_939_04_SampleContent(t *testing.T) {
	r := &fakeReadings{st: storestate.Ready, counts: storestate.Counts{Requests: 7, Errors: 2}}
	g := newRig(t, r, nil)
	g.trigger(t)
	got := g.inner.storeSamples()
	if len(got) != 1 {
		t.Fatalf("%d store samples, want 1", len(got))
	}
	e := got[0]
	if e.NodeID != testSelf || !e.Ts.Equal(testNow) {
		t.Errorf("sample NodeID/Ts = %q/%v, want %q/%v", e.NodeID, e.Ts, testSelf, testNow)
	}
	want := map[string]float64{
		MetricSecretStoreSealed:        0,
		MetricSecretStoreRequestsTotal: 7,
		MetricSecretStoreErrorsTotal:   2,
		MetricSecretStoreStorageBytes:  4096,
	}
	if !reflect.DeepEqual(e.Metrics, want) {
		t.Errorf("sample metrics = %v, want %v", e.Metrics, want)
	}

	r.set(storestate.Sealed)
	g.trigger(t)
	got = g.inner.storeSamples()
	if len(got) != 2 || got[1].Metrics[MetricSecretStoreSealed] != 1 {
		t.Errorf("sealed sample = %v, want secretstore_sealed=1", got[len(got)-1].Metrics)
	}
}

// TC-939-05: a state the store did not answer leaves sealed out, never 0,
// and still carries both counters and the size.
func TestStoreHealthSink_TC_939_05_UnknownStateOmitted(t *testing.T) {
	for _, st := range []storestate.State{storestate.Uninitialised, storestate.Unreachable, storestate.Quiesced} {
		t.Run(string(st), func(t *testing.T) {
			g := newRig(t, &fakeReadings{st: st, counts: storestate.Counts{Requests: 1}}, nil)
			g.trigger(t)
			got := g.inner.storeSamples()
			if len(got) != 1 {
				t.Fatalf("%d store samples, want 1", len(got))
			}
			m := got[0].Metrics
			if _, ok := m[MetricSecretStoreSealed]; ok {
				t.Errorf("sample carries %s=%v for an unknown state", MetricSecretStoreSealed, m[MetricSecretStoreSealed])
			}
			for _, k := range []string{MetricSecretStoreRequestsTotal, MetricSecretStoreErrorsTotal, MetricSecretStoreStorageBytes} {
				if _, ok := m[k]; !ok {
					t.Errorf("sample has no %s", k)
				}
			}
		})
	}
}

// TC-939-06: an unreadable size is left out, with one WARN per outage and one
// INFO on recovery; a missing directory is left out with no WARN.
func TestStoreHealthSink_TC_939_06_SizeReadFails(t *testing.T) {
	t.Run("permission, twice, then recovers", func(t *testing.T) {
		perm := &fs.PathError{Op: "open", Path: "/data/openbao", Err: fs.ErrPermission}
		results := []error{perm, perm, nil}
		i := 0
		g := newRig(t, &fakeReadings{st: storestate.Ready}, func() (uint64, error) {
			err := results[i]
			i++
			if err != nil {
				return 0, fmt.Errorf("storage: sizing: %w", err)
			}
			return 10, nil
		})
		for range 3 {
			g.trigger(t)
		}
		got := g.inner.storeSamples()
		if len(got) != 3 {
			t.Fatalf("%d store samples, want 3", len(got))
		}
		for j, e := range got[:2] {
			if _, ok := e.Metrics[MetricSecretStoreStorageBytes]; ok {
				t.Errorf("sample %d carries a size while it is unreadable", j)
			}
		}
		if got[2].Metrics[MetricSecretStoreStorageBytes] != 10 {
			t.Errorf("recovered sample size = %v, want 10", got[2].Metrics[MetricSecretStoreStorageBytes])
		}
		recs := g.log.atOrAbove(slog.LevelInfo)
		if len(recs) != 2 {
			t.Fatalf("records at INFO and above = %d (%v), want one WARN then one INFO", len(recs), recs)
		}
		w, in := recs[0], recs[1]
		if w.Level != slog.LevelWarn || w.Message != "store size unreadable; storage series omitted" {
			t.Errorf("first record = %s %q", w.Level, w.Message)
		}
		a := attrsOf(w)
		if a["component"] != "obs" || a["event"] != "obs.store_size_unreadable" || a["dir"] != "/data/openbao" || !strings.Contains(a["err"], "permission denied") {
			t.Errorf("WARN attrs = %v", a)
		}
		if in.Level != slog.LevelInfo || in.Message != "store size readable again" {
			t.Errorf("second record = %s %q, want INFO \"store size readable again\"", in.Level, in.Message)
		}
	})
	t.Run("not exist: omitted, no WARN", func(t *testing.T) {
		g := newRig(t, &fakeReadings{st: storestate.Ready}, func() (uint64, error) {
			return 0, &fs.PathError{Op: "lstat", Path: "/data/openbao", Err: fs.ErrNotExist}
		})
		g.trigger(t)
		g.trigger(t)
		for _, e := range g.inner.storeSamples() {
			if _, ok := e.Metrics[MetricSecretStoreStorageBytes]; ok {
				t.Error("sample carries a size for a missing directory")
			}
		}
		if recs := g.log.atOrAbove(slog.LevelInfo); len(recs) != 0 {
			t.Errorf("records at INFO and above = %v, want none", recs)
		}
	})
}

// TC-939-07: a reading cancelled by shutdown writes nothing and logs nothing
// above DEBUG.
func TestStoreHealthSink_TC_939_07_ReadCancelled(t *testing.T) {
	g := newRig(t, &fakeReadings{err: fmt.Errorf("storestate: reading: %w", context.Canceled)}, nil)
	g.trigger(t)
	if n := len(g.inner.storeSamples()); n != 0 {
		t.Errorf("%d store samples written, want 0", n)
	}
	if n := len(g.inner.all()); n != 1 {
		t.Errorf("inner sink saw %d events, want only the forwarded one", n)
	}
	if recs := g.log.atOrAbove(slog.LevelInfo); len(recs) != 0 {
		t.Errorf("records above DEBUG = %v, want none", recs)
	}
}

// TC-939-08: every event is forwarded unchanged with the inner sink's
// result; another node's event reads nothing; a failing store-sample write
// never changes a forwarded Write's result.
func TestStoreHealthSink_TC_939_08_ForwardsAndIsolates(t *testing.T) {
	r := &fakeReadings{st: storestate.Ready}
	g := newRig(t, r, nil)
	nodeErr := errors.New("vm not healthy")
	g.inner.failNode = nodeErr
	g.inner.failStore = errors.New("store sample write failed")

	other := &proto.MetricsEvt{NodeID: "worker-1", Ts: testNow, Metrics: map[string]float64{"cpu_percent": 5}}
	otherCopy := *other
	otherCopy.Metrics = map[string]float64{"cpu_percent": 5}
	if err := g.s.Write(context.Background(), other); !errors.Is(err, nodeErr) {
		t.Errorf("Write(other) = %v, want the inner sink's %v", err, nodeErr)
	}
	g.s.Wait()
	if n := r.calls.Load(); n != 0 {
		t.Errorf("another node's event made %d State calls, want 0", n)
	}

	self := &proto.MetricsEvt{NodeID: testSelf, Ts: testNow, Metrics: map[string]float64{"cpu_percent": 9}}
	if err := g.s.Write(context.Background(), self); !errors.Is(err, nodeErr) {
		t.Errorf("Write(self) = %v, want the inner sink's %v, untouched by the store sample", err, nodeErr)
	}
	g.s.Wait()
	g.inner.failNode = nil
	if err := g.s.Write(context.Background(), self); err != nil {
		t.Errorf("Write(self) with a healthy inner sink = %v, want nil although the store sample's write fails", err)
	}
	g.s.Wait()

	all := g.inner.all()
	var forwarded []*proto.MetricsEvt
	for _, e := range all {
		if !isStoreSample(e) {
			forwarded = append(forwarded, e)
		}
	}
	if len(forwarded) != 3 || forwarded[0] != other || forwarded[1] != self || forwarded[2] != self {
		t.Fatalf("forwarded = %v, want [other self self] as the same events", forwarded)
	}
	if !reflect.DeepEqual(*forwarded[0], otherCopy) {
		t.Errorf("forwarded event changed: %+v, want %+v", *forwarded[0], otherCopy)
	}
	if n := len(g.inner.storeSamples()); n != 2 {
		t.Errorf("%d store samples attempted, want 2", n)
	}
}

// TC-939-09: Write returns while the reading is blocked; a second trigger
// meanwhile starts no second reading; once released, the next trigger reads
// again. Run under -race.
func TestStoreHealthSink_TC_939_09_NeverBlocksSingleFlight(t *testing.T) {
	release := make(chan struct{})
	r := &fakeReadings{st: storestate.Ready, block: release}
	g := newRig(t, r, nil)
	self := &proto.MetricsEvt{NodeID: testSelf, Ts: testNow, Metrics: map[string]float64{"cpu_percent": 1}}

	returned := make(chan error, 1)
	go func() { returned <- g.s.Write(context.Background(), self) }()
	if err := <-returned; err != nil { // returns although State has not been released
		t.Fatal(err)
	}
	waitUntil(t, func() bool { return r.calls.Load() == 1 })
	if err := g.s.Write(context.Background(), self); err != nil {
		t.Fatal(err)
	}
	if n := r.calls.Load(); n != 1 {
		t.Fatalf("State calls while the first is blocked = %d, want 1", n)
	}
	close(release)
	g.s.Wait()
	g.trigger(t)
	if n := r.calls.Load(); n != 2 {
		t.Fatalf("State calls after release = %d, want 2", n)
	}
	if n := len(g.inner.storeSamples()); n != 2 {
		t.Errorf("%d store samples, want 2", n)
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition never held")
		}
		time.Sleep(time.Millisecond)
	}
}

// TC-939-10: the constructor refuses each missing collaborator.
func TestNewStoreHealthSink_TC_939_10_RefusesNil(t *testing.T) {
	ok := StoreHealthDeps{
		Readings: &fakeReadings{}, DataBytes: func() (uint64, error) { return 0, nil },
		SelfNodeID: testSelf, Now: time.Now, Log: slog.New(&logRecords{}),
	}
	if s, err := NewStoreHealthSink(&captureSink{}, ok); err != nil || s == nil {
		t.Fatalf("valid deps: %v, %v", s, err)
	}
	for name, mut := range map[string]func(*StoreHealthDeps, *Sink){
		"inner":      func(_ *StoreHealthDeps, in *Sink) { *in = nil },
		"readings":   func(d *StoreHealthDeps, _ *Sink) { d.Readings = nil },
		"data bytes": func(d *StoreHealthDeps, _ *Sink) { d.DataBytes = nil },
		"self id":    func(d *StoreHealthDeps, _ *Sink) { d.SelfNodeID = "" },
		"now":        func(d *StoreHealthDeps, _ *Sink) { d.Now = nil },
		"log":        func(d *StoreHealthDeps, _ *Sink) { d.Log = nil },
	} {
		t.Run(name, func(t *testing.T) {
			d := ok
			var in Sink = &captureSink{}
			mut(&d, &in)
			if s, err := NewStoreHealthSink(in, d); err == nil || s != nil {
				t.Errorf("NewStoreHealthSink = %v, %v; want an error and no sink", s, err)
			}
		})
	}
}
