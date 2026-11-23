package obs

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

type fakeSigninReading struct{ state string }

func (f fakeSigninReading) MetricState(time.Time) (string, bool) { return f.state, f.state != "" }

// TC-995-18: the control plane's own sample writes exactly three one-hot
// series, with exact Prometheus text, through the VM sink's one POST; another
// node's sample writes none; every event still reaches the inner sink.
func TestSigninNameSink(t *testing.T) {
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
	log, _ := logkittest.New()
	s, err := NewSigninNameSink(inner, vm, SigninNameDeps{
		Reading: fakeSigninReading{state: "conflict"}, SelfNodeID: testSelf,
		Now: func() time.Time { return testNow }, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	other := &proto.MetricsEvt{NodeID: "node-2", Ts: testNow, Metrics: map[string]float64{"cpu_percent": 1}}
	self := &proto.MetricsEvt{NodeID: testSelf, Ts: testNow, Metrics: map[string]float64{"cpu_percent": 2}}
	if err := s.Write(ctx, other); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	n := len(bodies)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("another node's sample wrote %d bodies", n)
	}
	if err := s.Write(ctx, self); err != nil {
		t.Fatal(err)
	}
	ts := "1793534400000"
	want := `rasputin_signin_name_state{nodeId="cp-1",state="ok"} 0 ` + ts + "\n" +
		`rasputin_signin_name_state{nodeId="cp-1",state="conflict"} 1 ` + ts + "\n" +
		`rasputin_signin_name_state{nodeId="cp-1",state="unpublished"} 0 ` + ts + "\n"
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 || bodies[0] != want {
		t.Fatalf("bodies = %q\nwant %q", bodies, want)
	}
	inner.mu.Lock()
	defer inner.mu.Unlock()
	if len(inner.got) != 2 || inner.got[0] != other || inner.got[1] != self {
		t.Errorf("inner sink got %v", inner.got)
	}
}

// NewSigninNameSink refuses a missing collaborator.
func TestNewSigninNameSinkRefuses(t *testing.T) {
	log, _ := logkittest.New()
	ok := SigninNameDeps{Reading: fakeSigninReading{"ok"}, SelfNodeID: testSelf, Now: time.Now, Log: log}
	vm := &VMSink{}
	for name, c := range map[string]struct {
		inner Sink
		vm    SeriesWriter
		d     SigninNameDeps
	}{
		"inner":   {nil, vm, ok},
		"vm":      {&captureSink{}, nil, ok},
		"reading": {&captureSink{}, vm, SigninNameDeps{SelfNodeID: testSelf, Now: time.Now, Log: log}},
		"self":    {&captureSink{}, vm, SigninNameDeps{Reading: ok.Reading, Now: time.Now, Log: log}},
		"now":     {&captureSink{}, vm, SigninNameDeps{Reading: ok.Reading, SelfNodeID: testSelf, Log: log}},
		"log":     {&captureSink{}, vm, SigninNameDeps{Reading: ok.Reading, SelfNodeID: testSelf, Now: time.Now}},
	} {
		if _, err := NewSigninNameSink(c.inner, c.vm, c.d); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
