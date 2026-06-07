package obs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestContainersClient_RequiresSupervisor(t *testing.T) {
	if _, err := NewContainersClient(ContainersClientConfig{}); err == nil {
		t.Fatal("expected error when Supervisor nil")
	}
}

func TestContainersClient_EmptyBaseURL(t *testing.T) {
	c, _ := NewContainersClient(ContainersClientConfig{
		Supervisor: &fakeSupervisor{baseURL: ""},
	})
	_, err := c.List(context.Background(), "n1")
	if err == nil || !strings.Contains(err.Error(), "VM base url empty") {
		t.Fatalf("expected base-url-empty error, got %v", err)
	}
}

// instantResp builds VM's standard instant-query envelope from a
// metric→value map; tests use it to stub three responses.
func instantResp(samples []struct {
	name, image string
	value       float64
},
) string {
	type kv struct {
		Metric map[string]string `json:"metric"`
		Value  [2]any            `json:"value"`
	}
	rs := make([]kv, 0, len(samples))
	for _, s := range samples {
		rs = append(rs, kv{
			Metric: map[string]string{"name": s.name, "image": s.image},
			// Prometheus serializes the sample value as a JSON string
			// to preserve float precision; the decoder ParseFloat's it.
			Value: [2]any{1717891200.0, strconv.FormatFloat(s.value, 'f', -1, 64)},
		})
	}
	body := map[string]any{
		"status": "success",
		"data":   map[string]any{"resultType": "vector", "result": rs},
	}
	b, _ := json.Marshal(body)
	return string(b)
}

// TestContainersClient_HappyPath drives the three-query merge end to
// end against a stub VM that returns distinct values for CPU / mem /
// restart. The resulting rows are sorted by CPU descending.
func TestContainersClient_HappyPath(t *testing.T) {
	// Each query returns the SAME two containers with DIFFERENT values
	// so the merge keying-by-name is exercised.
	cpu := instantResp([]struct {
		name, image string
		value       float64
	}{
		{"rasputin-vm", "victoriametrics:1.103", 0.25},
		{"rasputin-grafana", "grafana:11.5", 0.05},
	})
	mem := instantResp([]struct {
		name, image string
		value       float64
	}{
		{"rasputin-vm", "victoriametrics:1.103", 128_000_000},
		{"rasputin-grafana", "grafana:11.5", 64_000_000},
	})
	res := instantResp([]struct {
		name, image string
		value       float64
	}{
		{"rasputin-vm", "victoriametrics:1.103", 1717880000},
		{"rasputin-grafana", "grafana:11.5", 1717860000},
	})

	respByQuery := map[string]string{
		"cpu":      cpu,
		"memory":   mem,
		"restarts": res,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		switch {
		case strings.Contains(q, "container_cpu_usage_seconds_total"):
			_, _ = w.Write([]byte(respByQuery["cpu"]))
		case strings.Contains(q, "container_memory_working_set_bytes"):
			_, _ = w.Write([]byte(respByQuery["memory"]))
		case strings.Contains(q, "container_start_time_seconds"):
			_, _ = w.Write([]byte(respByQuery["restarts"]))
		default:
			t.Errorf("unexpected query %q", q)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	c, _ := NewContainersClient(ContainersClientConfig{
		Supervisor: &fakeSupervisor{baseURL: srv.URL},
	})
	rows, err := c.List(context.Background(), "cp-1")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0].Name != "rasputin-vm" {
		t.Fatalf("CPU-desc sort: top = %q, want rasputin-vm", rows[0].Name)
	}
	if rows[0].CPU != 0.25 {
		t.Errorf("rasputin-vm CPU = %v, want 0.25", rows[0].CPU)
	}
	if rows[0].MemBytes != 128_000_000 {
		t.Errorf("rasputin-vm mem = %v, want 128_000_000", rows[0].MemBytes)
	}
}

// TestContainersClient_EmptyResultNotError covers the cold-start case:
// no containers reporting yet (or cAdvisor not scraped). List returns
// an empty slice, not an error.
func TestContainersClient_EmptyResultNotError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	defer srv.Close()
	c, _ := NewContainersClient(ContainersClientConfig{
		Supervisor: &fakeSupervisor{baseURL: srv.URL},
	})
	rows, err := c.List(context.Background(), "cp-1")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("got %d rows, want 0", len(rows))
	}
}

// TestContainersClient_VMError surfaces VM's error body so the
// operator can diagnose without log-diving.
func TestContainersClient_VMError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"status":"error","error":"parse"}`))
	}))
	defer srv.Close()
	c, _ := NewContainersClient(ContainersClientConfig{
		Supervisor: &fakeSupervisor{baseURL: srv.URL},
	})
	_, err := c.List(context.Background(), "cp-1")
	if err == nil || !strings.Contains(err.Error(), "HTTP 400") {
		t.Fatalf("expected HTTP 400 error, got %v", err)
	}
}
