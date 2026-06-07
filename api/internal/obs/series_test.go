package obs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSeriesClient_RequiresSupervisor(t *testing.T) {
	if _, err := NewSeriesClient(SeriesClientConfig{}); err == nil {
		t.Fatal("expected error when Supervisor nil")
	}
}

func TestSeriesClient_RequiresNode(t *testing.T) {
	c, _ := NewSeriesClient(SeriesClientConfig{
		Supervisor: &fakeSupervisor{baseURL: "http://x"},
	})
	_, err := c.Query(context.Background(), SeriesQuery{Metric: SeriesCPUPercent})
	if err == nil || !strings.Contains(err.Error(), "nodeId required") {
		t.Fatalf("expected nodeId-required error, got %v", err)
	}
}

func TestSeriesClient_UnknownMetric(t *testing.T) {
	c, _ := NewSeriesClient(SeriesClientConfig{
		Supervisor: &fakeSupervisor{baseURL: "http://x"},
	})
	_, err := c.Query(context.Background(), SeriesQuery{
		NodeID: "n1", Metric: SeriesKey("nope"),
	})
	if err == nil || !strings.Contains(err.Error(), "unknown metric") {
		t.Fatalf("expected unknown-metric error, got %v", err)
	}
}

func TestSeriesClient_EmptyBaseURL(t *testing.T) {
	c, _ := NewSeriesClient(SeriesClientConfig{
		Supervisor: &fakeSupervisor{baseURL: ""},
	})
	_, err := c.Query(context.Background(), SeriesQuery{
		NodeID: "n1", Metric: SeriesCPUPercent,
	})
	if err == nil || !strings.Contains(err.Error(), "VM base url empty") {
		t.Fatalf("expected base-url-empty error, got %v", err)
	}
}

// TestSeriesClient_QueryShape verifies the wire request — that we hit
// /api/v1/query_range with the correct PromQL for the requested metric
// and the right time bounds.
func TestSeriesClient_QueryShape(t *testing.T) {
	var seenPath, seenQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`))
	}))
	defer srv.Close()

	c, _ := NewSeriesClient(SeriesClientConfig{
		Supervisor: &fakeSupervisor{baseURL: srv.URL},
	})

	cases := []struct {
		metric   SeriesKey
		wantExpr string
	}{
		{SeriesCPUPercent, `rasputin_cpu_percent{nodeId="n1"}`},
		{SeriesMemPercent, `100 * rasputin_mem_used_bytes{nodeId="n1"} / ignoring(__name__) rasputin_mem_total_bytes{nodeId="n1"}`},
		{SeriesMemUsedBytes, `rasputin_mem_used_bytes{nodeId="n1"}`},
		{SeriesDiskPercent, `100 * rasputin_disk_used_bytes{nodeId="n1"} / ignoring(__name__) rasputin_disk_total_bytes{nodeId="n1"}`},
	}
	for _, tc := range cases {
		t.Run(string(tc.metric), func(t *testing.T) {
			_, err := c.Query(context.Background(), SeriesQuery{
				NodeID: "n1", Metric: tc.metric, Range: 30 * time.Minute,
			})
			if err != nil {
				t.Fatalf("Query: %v", err)
			}
			if seenPath != "/api/v1/query_range" {
				t.Fatalf("path = %q, want /api/v1/query_range", seenPath)
			}
			params, _ := url.ParseQuery(seenQuery)
			if got := params.Get("query"); got != tc.wantExpr {
				t.Fatalf("query expr =\n  %q\nwant\n  %q", got, tc.wantExpr)
			}
			if params.Get("step") == "" {
				t.Fatal("step param missing")
			}
		})
	}
}

// TestSeriesClient_DecodesMatrix verifies the response decoder unwraps
// VM's standard matrix response into SeriesPoint slices.
func TestSeriesClient_DecodesMatrix(t *testing.T) {
	resp := map[string]any{
		"status": "success",
		"data": map[string]any{
			"resultType": "matrix",
			"result": []map[string]any{
				{
					"metric": map[string]string{"nodeId": "n1"},
					"values": [][]any{
						{1717891200.0, "12.5"},
						{1717891230.0, "13.0"},
						{1717891260.0, "NaN"}, // skipped silently
						{1717891290.0, "14.2"},
					},
				},
			},
		},
	}
	body, _ := json.Marshal(resp)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c, _ := NewSeriesClient(SeriesClientConfig{
		Supervisor: &fakeSupervisor{baseURL: srv.URL},
	})
	res, err := c.Query(context.Background(), SeriesQuery{
		NodeID: "n1", Metric: SeriesCPUPercent,
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(res.Points) != 3 {
		t.Fatalf("got %d points, want 3 (NaN should be dropped)", len(res.Points))
	}
	if res.Points[0].Value != 12.5 {
		t.Fatalf("first point value = %v, want 12.5", res.Points[0].Value)
	}
	if res.Unit != "percent" {
		t.Fatalf("unit = %q, want percent", res.Unit)
	}
}

// TestSeriesClient_EmptyResultNotError covers the common "no data yet"
// case — VM returns success with an empty result. UI gets an empty
// points slice, not an error.
func TestSeriesClient_EmptyResultNotError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`))
	}))
	defer srv.Close()
	c, _ := NewSeriesClient(SeriesClientConfig{
		Supervisor: &fakeSupervisor{baseURL: srv.URL},
	})
	res, err := c.Query(context.Background(), SeriesQuery{
		NodeID: "n1", Metric: SeriesCPUPercent,
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if res.Points == nil {
		t.Fatal("Points should be non-nil empty slice for empty result")
	}
	if len(res.Points) != 0 {
		t.Fatalf("got %d points, want 0", len(res.Points))
	}
}

// TestSeriesClient_VMError surfaces VM's error body in the returned
// error so the operator can spot config issues without log-diving.
func TestSeriesClient_VMError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"status":"error","error":"invalid expression"}`))
	}))
	defer srv.Close()
	c, _ := NewSeriesClient(SeriesClientConfig{
		Supervisor: &fakeSupervisor{baseURL: srv.URL},
	})
	_, err := c.Query(context.Background(), SeriesQuery{
		NodeID: "n1", Metric: SeriesCPUPercent,
	})
	if err == nil || !strings.Contains(err.Error(), "HTTP 400") {
		t.Fatalf("expected HTTP 400 error, got %v", err)
	}
}

// TestSeriesClient_StepDefaulting confirms the autocomputed step caps
// at 10s for very short windows and 5m for very long ones.
func TestSeriesClient_StepDefaulting(t *testing.T) {
	var seenStep string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenStep = r.URL.Query().Get("step")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`))
	}))
	defer srv.Close()
	c, _ := NewSeriesClient(SeriesClientConfig{
		Supervisor: &fakeSupervisor{baseURL: srv.URL},
	})
	// 5m / 120 = 2.5s → clamped up to 10s
	_, _ = c.Query(context.Background(), SeriesQuery{
		NodeID: "n1", Metric: SeriesCPUPercent, Range: 5 * time.Minute,
	})
	if seenStep != "10s" {
		t.Fatalf("short-range step = %q, want 10s (lower clamp)", seenStep)
	}
	// 24h / 120 = 12m → clamped down to 5m
	_, _ = c.Query(context.Background(), SeriesQuery{
		NodeID: "n1", Metric: SeriesCPUPercent, Range: 24 * time.Hour,
	})
	if seenStep != "300s" {
		t.Fatalf("long-range step = %q, want 300s (upper clamp)", seenStep)
	}
}
