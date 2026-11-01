//go:build linux

// Functional test for the "Secret store" dashboard (geekdojo/geekdojo-brain#939),
// against the real pinned Grafana and VictoriaMetrics images, driven by the
// supervisor. Same opt-in and harness as grafana_functional_linux_test.go:
// RASPUTIN_GRAFANA_FUNCTIONAL=required in CI turns every skip into a failure.

package obs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// seedSecretStoreMetrics writes five minutes of the four store-health series,
// rendered by encodePromText exactly as VMSink sends them, one sample every
// 10s ending 30s back, then waits for the fact that VictoriaMetrics serves
// them over a range.
func seedSecretStoreMetrics(t *testing.T, sup *DockerComposeSupervisor) {
	t.Helper()
	now := time.Now()
	var b bytes.Buffer
	for i := 30; i >= 3; i-- {
		n := float64(30 - i)
		b.Write(encodePromText(&proto.MetricsEvt{
			NodeID: "cp-func",
			Ts:     now.Add(-time.Duration(i) * 10 * time.Second),
			Metrics: map[string]float64{
				MetricSecretStoreSealed:        0,
				MetricSecretStoreRequestsTotal: 100 + 5*n,
				MetricSecretStoreErrorsTotal:   1 + n,
				MetricSecretStoreStorageBytes:  1 << 20,
			},
		}))
	}
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Post(sup.VMBaseURL()+"/api/v1/import/prometheus", "text/plain", &b)
	if err != nil {
		t.Fatalf("seed VM: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("seed VM: HTTP %d", resp.StatusCode)
	}
	// Bounds only how long VM may take to make an accepted import
	// searchable; the outcome is decided by the query answer.
	deadline := time.Now().Add(90 * time.Second)
	var last string
	for {
		end := time.Now().Unix()
		r, err := c.Get(fmt.Sprintf("%s/api/v1/query_range?query=count(rasputin_%s)&start=%d&end=%d&step=15",
			sup.VMBaseURL(), MetricSecretStoreStorageBytes, end-900, end))
		if err == nil {
			body, _ := io.ReadAll(r.Body)
			_ = r.Body.Close()
			last = string(body)
			if rangeLastValueIs(last, "1") {
				return
			}
		} else {
			last = err.Error()
		}
		if time.Now().After(deadline) {
			t.Fatalf("VictoriaMetrics never served the seeded store series within 90s (last: %.300s)", last)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// TC-939-17: the "Secret store" dashboard, loaded through the real Grafana by
// uid, runs every panel's own query through Grafana's datasource against the
// real VictoriaMetrics and gets data; the sealed panel reads 0 and Grafana's
// model maps 0 to "Unsealed".
func TestSecretStoreDashboard_TC_939_17_RealGrafana(t *testing.T) {
	requireDocker(t)
	stateDir := funcStateDir(t)
	composeDown()
	t.Cleanup(composeDown)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	sup := grafanaFuncSupervisor(t, stateDir, true)
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitForGrafanaProvisioned(t, stateDir, vmDatasourceUID, vmDatasourceUID, 3*time.Minute)
	waitForDashboardRow(t, stateDir, secretStoreDashboardUID, 3*time.Minute)
	seedSecretStoreMetrics(t, sup)

	const user = "alice"
	qs := dashboardPanelQueriesOf(t, sup, user, secretStoreDashboardUID)
	titles := map[string]bool{}
	for _, q := range qs {
		titles[q.title] = true
		if q.dsUID != vmDatasourceUID {
			t.Errorf("panel %q points at datasource %q, want %q", q.title, q.dsUID, vmDatasourceUID)
		}
		code, body := runPanelQuery(t, sup, user, q)
		if code != http.StatusOK {
			t.Errorf("panel %q: ds/query = %d %.400s", q.title, code, body)
			continue
		}
		var resp struct {
			Results map[string]struct {
				Error  string `json:"error"`
				Frames []struct {
					Data struct {
						Values [][]any `json:"values"`
					} `json:"data"`
				} `json:"frames"`
			} `json:"results"`
		}
		if err := json.Unmarshal([]byte(body), &resp); err != nil {
			t.Errorf("panel %q: ds/query json: %v", q.title, err)
			continue
		}
		r := resp.Results["A"]
		var last any
		points := 0
		for _, f := range r.Frames {
			if len(f.Data.Values) >= 2 && len(f.Data.Values[1]) > 0 {
				points += len(f.Data.Values[1])
				last = f.Data.Values[1][len(f.Data.Values[1])-1]
			}
		}
		if r.Error != "" || points == 0 {
			t.Errorf("panel %q: no data (error %q): %.400s", q.title, r.Error, body)
			continue
		}
		t.Logf("panel %q: %d points, last %v", q.title, points, last)
		if q.title == "Sealed" && last != float64(0) {
			t.Errorf("Sealed panel last value = %v, want 0", last)
		}
	}
	for _, want := range []string{"Sealed", "Requests per second", "Errors per second", "Storage used"} {
		if !titles[want] {
			t.Errorf("Grafana's model has no %q panel", want)
		}
	}

	// The value mapping as Grafana serves it to the browser.
	code, body := grafanaGet(t, sup, "/api/dashboards/uid/"+secretStoreDashboardUID, user)
	if code != http.StatusOK {
		t.Fatalf("dashboard model = %d", code)
	}
	var model struct {
		Dashboard struct {
			Panels []struct {
				Title       string `json:"title"`
				FieldConfig struct {
					Defaults struct {
						Mappings []struct {
							Options map[string]struct {
								Text string `json:"text"`
							} `json:"options"`
						} `json:"mappings"`
					} `json:"defaults"`
				} `json:"fieldConfig"`
			} `json:"panels"`
		} `json:"dashboard"`
	}
	if err := json.Unmarshal([]byte(body), &model); err != nil {
		t.Fatal(err)
	}
	mapped := ""
	for _, p := range model.Dashboard.Panels {
		if p.Title == "Sealed" && len(p.FieldConfig.Defaults.Mappings) > 0 {
			mapped = p.FieldConfig.Defaults.Mappings[0].Options["0"].Text
		}
	}
	if mapped != "Unsealed" {
		t.Errorf("Grafana maps the Sealed panel's 0 to %q, want \"Unsealed\"", mapped)
	}
	if strings.Contains(strings.ToLower(body), "openbao") {
		t.Error("the dashboard as Grafana serves it names the vendor")
	}
}
