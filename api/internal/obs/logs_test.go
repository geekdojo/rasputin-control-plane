package obs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stubLoki captures the most recent Loki query for assertions.
type stubLoki struct {
	calls     atomic.Int32
	lastQuery atomic.Value // string
	lastStart atomic.Value // string
	lastEnd   atomic.Value // string
	lastLimit atomic.Value // string
	status    atomic.Int32 // overridable; 0 → 200
	body      atomic.Value // string — what we return
}

func (s *stubLoki) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/loki/api/v1/query_range", func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		s.lastQuery.Store(r.URL.Query().Get("query"))
		s.lastStart.Store(r.URL.Query().Get("start"))
		s.lastEnd.Store(r.URL.Query().Get("end"))
		s.lastLimit.Store(r.URL.Query().Get("limit"))
		status := int(s.status.Load())
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		body, _ := s.body.Load().(string)
		if body == "" {
			body = `{"status":"success","data":{"resultType":"streams","result":[]}}`
		}
		_, _ = w.Write([]byte(body))
	})
	return mux
}

func TestLogsClient_RequiresSupervisor(t *testing.T) {
	if _, err := NewLogsClient(LogsClientConfig{}); err == nil {
		t.Fatal("expected error when Supervisor nil")
	}
}

func TestLogsClient_EmptyQueryRejected(t *testing.T) {
	c, _ := NewLogsClient(LogsClientConfig{
		Supervisor: &fakeSupervisor{lokiURL: "http://x"},
	})
	if _, err := c.QueryRange(context.Background(), LogsQuery{}); err == nil {
		t.Fatal("empty query should error")
	}
}

func TestLogsClient_RejectsWhenLokiDisabled(t *testing.T) {
	c, _ := NewLogsClient(LogsClientConfig{
		Supervisor: &fakeSupervisor{lokiURL: ""}, // Loki off
	})
	_, err := c.QueryRange(context.Background(), LogsQuery{Query: `{foo="bar"}`})
	if err == nil {
		t.Fatal("expected error when LokiBaseURL empty")
	}
	if !strings.Contains(err.Error(), "Loki not configured") {
		t.Errorf("err = %v; want Loki-not-configured message", err)
	}
}

func TestLogsClient_HappyPath(t *testing.T) {
	loki := &stubLoki{}
	loki.body.Store(`{"status":"success","data":{"resultType":"streams","result":[{"stream":{"container":"foo"},"values":[["1700000000000000000","hello"]]}]}}`)
	srv := httptest.NewServer(loki.handler())
	defer srv.Close()

	c, _ := NewLogsClient(LogsClientConfig{
		Supervisor: &fakeSupervisor{lokiURL: srv.URL},
		HTTPClient: srv.Client(),
	})
	start := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	end := start.Add(1 * time.Hour)
	body, err := c.QueryRange(context.Background(), LogsQuery{
		Query: `{container="foo"}`,
		Start: start,
		End:   end,
		Limit: 50,
	})
	if err != nil {
		t.Fatalf("QueryRange: %v", err)
	}
	if !strings.Contains(string(body), "hello") {
		t.Errorf("body lost the line: %s", body)
	}
	if loki.calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", loki.calls.Load())
	}
	if got, _ := loki.lastQuery.Load().(string); got != `{container="foo"}` {
		t.Errorf("forwarded query = %q", got)
	}
	if got, _ := loki.lastLimit.Load().(string); got != "50" {
		t.Errorf("limit = %q, want 50", got)
	}
}

func TestLogsClient_LimitClampedTo5000(t *testing.T) {
	loki := &stubLoki{}
	srv := httptest.NewServer(loki.handler())
	defer srv.Close()
	c, _ := NewLogsClient(LogsClientConfig{
		Supervisor: &fakeSupervisor{lokiURL: srv.URL},
		HTTPClient: srv.Client(),
	})
	_, _ = c.QueryRange(context.Background(), LogsQuery{Query: `{x="1"}`, Limit: 999999})
	if got, _ := loki.lastLimit.Load().(string); got != "5000" {
		t.Errorf("limit clamp = %q, want 5000", got)
	}
}

func TestLogsClient_DefaultsApplied(t *testing.T) {
	loki := &stubLoki{}
	srv := httptest.NewServer(loki.handler())
	defer srv.Close()
	c, _ := NewLogsClient(LogsClientConfig{
		Supervisor: &fakeSupervisor{lokiURL: srv.URL},
		HTTPClient: srv.Client(),
	})
	_, _ = c.QueryRange(context.Background(), LogsQuery{Query: `{x="1"}`})
	if got, _ := loki.lastLimit.Load().(string); got != "100" {
		t.Errorf("default limit = %q, want 100", got)
	}
	if got, _ := loki.lastStart.Load().(string); got == "" {
		t.Error("start should default to ~1h ago")
	}
	if got, _ := loki.lastEnd.Load().(string); got == "" {
		t.Error("end should default to now")
	}
}

// TestComposedExpr covers the LogQL-construction helper directly so
// the test stays independent of the HTTP roundtrip.
func TestComposedExpr(t *testing.T) {
	cases := []struct {
		name string
		in   LogsQuery
		want string
	}{
		{"empty", LogsQuery{}, ``},
		{"node only", LogsQuery{NodeID: "cp-1"}, `{node_id="cp-1"}`},
		{"container only", LogsQuery{Container: "rasputin-vm"}, `{container="rasputin-vm"}`},
		{
			"both labels",
			LogsQuery{NodeID: "cp-1", Container: "rasputin-vm"},
			`{node_id="cp-1",container="rasputin-vm"}`,
		},
		{
			"node + grep",
			LogsQuery{NodeID: "cp-1", Grep: "error"},
			"{node_id=\"cp-1\"} |~ `(?i)error`",
		},
		{
			"grep with backticks stripped",
			LogsQuery{NodeID: "cp-1", Grep: "a`b"},
			"{node_id=\"cp-1\"} |~ `(?i)ab`",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := composedExpr(tc.in); got != tc.want {
				t.Errorf("composedExpr =\n  %q\nwant\n  %q", got, tc.want)
			}
		})
	}
}

// TestLogsClient_ComposedFormWinsOverRawQuery confirms the composed
// fields take precedence — partial-migration safety so a UI sending
// both doesn't silently bypass the per-node filter.
func TestLogsClient_ComposedFormWinsOverRawQuery(t *testing.T) {
	loki := &stubLoki{}
	srv := httptest.NewServer(loki.handler())
	defer srv.Close()
	c, _ := NewLogsClient(LogsClientConfig{
		Supervisor: &fakeSupervisor{lokiURL: srv.URL},
		HTTPClient: srv.Client(),
	})
	_, _ = c.QueryRange(context.Background(), LogsQuery{
		Query:  `{container="raw"}`,
		NodeID: "cp-1",
	})
	got, _ := loki.lastQuery.Load().(string)
	if got != `{node_id="cp-1"}` {
		t.Fatalf("forwarded query = %q, want composed selector", got)
	}
}

func TestLogsClient_PropagatesHTTPError(t *testing.T) {
	loki := &stubLoki{}
	loki.status.Store(http.StatusBadRequest)
	loki.body.Store(`parse error: missing closing brace`)
	srv := httptest.NewServer(loki.handler())
	defer srv.Close()
	c, _ := NewLogsClient(LogsClientConfig{
		Supervisor: &fakeSupervisor{lokiURL: srv.URL},
		HTTPClient: srv.Client(),
	})
	_, err := c.QueryRange(context.Background(), LogsQuery{Query: `{foo=`})
	if err == nil {
		t.Fatal("expected error from Loki 400")
	}
	if !strings.Contains(err.Error(), "parse error") {
		t.Errorf("err should carry Loki message: %v", err)
	}
}
