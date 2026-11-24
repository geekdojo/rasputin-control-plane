//go:build linux

// Functional test for the starter dashboard's datasource reference, against
// the real pinned Grafana and VictoriaMetrics images, driven by the
// supervisor. Same opt-in and harness as grafana_functional_linux_test.go.
//
// From 2026-06-02 every panel of "Cluster Overview" pointed at datasource uid
// PBFA97CFB590B2093, which Rasputin never provisioned: Grafana derived
// P4169E866C3094E38 from the name "VictoriaMetrics" instead, and every panel
// showed "Datasource PBFA97CFB590B2093 was not found". The unit tests check
// the reference statically; this proves Grafana agrees, and that an EXISTING
// cluster — whose Grafana database already holds the datasource under the
// derived uid — converges on the next Start with nothing done by hand.

package obs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// grafanaPost is grafanaGet's POST twin, for /api/ds/query.
func grafanaPost(t *testing.T, sup *DockerComposeSupervisor, path, webauthUser, body string) (int, string) {
	t.Helper()
	c := &http.Client{Timeout: 30 * time.Second}
	if tr := sup.GrafanaTransport(); tr != nil {
		c.Transport = tr
	}
	req, err := http.NewRequest(http.MethodPost, sup.GrafanaBaseURL()+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webauth-User", webauthUser)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// legacyGrafanaProvisioning is the provisioning as it shipped before the fix:
// the datasources and starter dashboard from testdata, the (unchanged)
// dashboard provider from today.
func legacyGrafanaProvisioning(t *testing.T) []grafanaFile {
	t.Helper()
	read := func(name string) string { return string(readLegacyGrafana(t, name)) }
	return []grafanaFile{
		{grafanaDatasourcesPath, read("datasources.yaml")},
		{grafanaDashboardsPath, grafanaDashboardsYAML},
		{grafanaStarterDashboardPath, read("cluster-overview.json")},
	}
}

// previousGrafanaImage is the Grafana every cluster ran before
// geekdojo/geekdojo-brain#999, so the database the transition test starts
// from is the one an existing cluster really has.
const previousGrafanaImage = "grafana/grafana:11.5.1@sha256:5781759b3d27734d4d548fcbaf60b1180dbf4290e708f01f292faa6ae764c5e6"

// seedClusterMetrics writes two nodes' worth of the rasputin_* series the
// starter dashboard plots straight into VictoriaMetrics, then waits for the
// checkable fact that VM serves them. The newest sample is 30s old so VM's
// search latency offset does not hide it.
func seedClusterMetrics(t *testing.T, sup *DockerComposeSupervisor) {
	t.Helper()
	// A sample every 10s for the last five minutes, ending 30s back, as an
	// agent reports: VictoriaMetrics gives a lone sample a short lookbehind,
	// so a range query would see it at one step only (measured on v1.103.0).
	now := time.Now()
	var b bytes.Buffer
	for i := 3; i <= 30; i++ {
		ts := now.Add(-time.Duration(i) * 10 * time.Second).UnixMilli()
		for _, n := range []struct {
			id       string
			cpu, mem float64
		}{{"func-a", 12.5, 1.5e9}, {"func-b", 30, 2.5e9}} {
			fmt.Fprintf(&b, "rasputin_cpu_percent{nodeId=%q} %g %d\n", n.id, n.cpu, ts)
			fmt.Fprintf(&b, "rasputin_mem_used_bytes{nodeId=%q} %g %d\n", n.id, n.mem, ts)
			fmt.Fprintf(&b, "rasputin_mem_total_bytes{nodeId=%q} %g %d\n", n.id, 4e9, ts)
		}
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
		// The fact the panels read: a RANGE query of the panels' shape whose
		// newest point counts every seeded node. An instant query is not
		// enough — right after an import VM answers instant queries with the
		// new series while range queries still miss them for a moment
		// (measured on v1.103.0: instant 2, range 1).
		end := time.Now().Unix()
		r, err := c.Get(fmt.Sprintf("%s/api/v1/query_range?query=count(rasputin_cpu_percent)&start=%d&end=%d&step=15",
			sup.VMBaseURL(), end-900, end))
		if err == nil {
			body, _ := io.ReadAll(r.Body)
			_ = r.Body.Close()
			last = string(body)
			if rangeLastValueIs(last, fmt.Sprint(2)) {
				return
			}
		} else {
			last = err.Error()
		}
		if time.Now().After(deadline) {
			t.Fatalf("VictoriaMetrics never served the seeded series within 90s (last: %.300s)", last)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

type panelQuery struct {
	title   string
	dsUID   string
	dsType  string
	expr    string
	legend  string
	instant bool
	isCount bool
}

// dashboardPanelQueries loads the starter dashboard THROUGH GRAFANA — the
// model the browser renders — and returns each panel's query with the
// datasource the panel names.
func dashboardPanelQueries(t *testing.T, sup *DockerComposeSupervisor, user string) []panelQuery {
	t.Helper()
	return dashboardPanelQueriesOf(t, sup, user, starterDashboardUID)
}

// dashboardPanelQueriesOf is dashboardPanelQueries for the dashboard with
// uid.
func dashboardPanelQueriesOf(t *testing.T, sup *DockerComposeSupervisor, user, uid string) []panelQuery {
	t.Helper()
	code, body := grafanaGet(t, sup, "/api/dashboards/uid/"+uid, user)
	if code != http.StatusOK {
		t.Fatalf("dashboard model = %d %.300s", code, body)
	}
	var model struct {
		Dashboard struct {
			Panels []struct {
				Title      string `json:"title"`
				Datasource struct {
					UID  string `json:"uid"`
					Type string `json:"type"`
				} `json:"datasource"`
				Targets []struct {
					Expr         string `json:"expr"`
					LegendFormat string `json:"legendFormat"`
					Instant      bool   `json:"instant"`
				} `json:"targets"`
			} `json:"panels"`
			Templating struct {
				List []struct {
					Name     string `json:"name"`
					AllValue string `json:"allValue"`
				} `json:"list"`
			} `json:"templating"`
		} `json:"dashboard"`
	}
	if err := json.Unmarshal([]byte(body), &model); err != nil {
		t.Fatalf("dashboard model json: %v", err)
	}
	// The dashboard as opened directly: every variable at "All", which
	// Grafana's frontend interpolates as the variable's allValue before
	// the query reaches /api/ds/query (the backend does not interpolate).
	allOf := func(expr string) string {
		for _, v := range model.Dashboard.Templating.List {
			expr = strings.ReplaceAll(expr, "${"+v.Name+"}", v.AllValue)
			expr = strings.ReplaceAll(expr, "$"+v.Name, v.AllValue)
		}
		return expr
	}
	var out []panelQuery
	for _, p := range model.Dashboard.Panels {
		for _, tg := range p.Targets {
			out = append(out, panelQuery{
				title: p.Title, dsUID: p.Datasource.UID, dsType: p.Datasource.Type,
				expr: allOf(tg.Expr), legend: tg.LegendFormat, instant: tg.Instant,
				isCount: strings.HasPrefix(tg.Expr, "count("),
			})
		}
	}
	if len(out) == 0 {
		t.Fatalf("dashboard has no panel queries: %.300s", body)
	}
	return out
}

// runPanelQuery issues a panel's query the way the dashboard does, through
// Grafana's /api/ds/query with the panel's own datasource reference.
func runPanelQuery(t *testing.T, sup *DockerComposeSupervisor, user string, q panelQuery) (int, string) {
	t.Helper()
	req := map[string]any{
		"queries": []any{map[string]any{
			"refId":         "A",
			"datasource":    map[string]string{"uid": q.dsUID, "type": q.dsType},
			"expr":          q.expr,
			"legendFormat":  q.legend,
			"range":         !q.instant,
			"instant":       q.instant,
			"intervalMs":    15000,
			"maxDataPoints": 100,
		}},
		"from": "now-15m",
		"to":   "now",
	}
	b, _ := json.Marshal(req)
	return grafanaPost(t, sup, "/api/ds/query", user, string(b))
}

// assertPanelsReturnData runs every panel's query and requires data frames
// with values — the seeded two nodes — and no datasource error.
func assertPanelsReturnData(t *testing.T, sup *DockerComposeSupervisor, user string) {
	t.Helper()
	for _, q := range dashboardPanelQueries(t, sup, user) {
		if q.dsUID != vmDatasourceUID {
			t.Errorf("panel %q points at datasource %q, want %q", q.title, q.dsUID, vmDatasourceUID)
		}
		code, body := runPanelQuery(t, sup, user, q)
		if code != http.StatusOK || strings.Contains(strings.ToLower(body), "not found") {
			t.Errorf("panel %q: ds/query = %d %.400s", q.title, code, body)
			continue
		}
		var resp struct {
			Results map[string]struct {
				Status int    `json:"status"`
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
		r, ok := resp.Results["A"]
		if !ok || r.Error != "" || (r.Status != 0 && r.Status != http.StatusOK) {
			t.Errorf("panel %q: result = %+v", q.title, r)
			continue
		}
		var series int
		var lastCount any
		for _, f := range r.Frames {
			if len(f.Data.Values) >= 2 && len(f.Data.Values[1]) > 0 {
				series++
				v := f.Data.Values[1]
				lastCount = v[len(v)-1]
			}
		}
		want := 2 // two seeded nodes, one series each
		if q.isCount {
			want = 1
			if lastCount != float64(2) {
				t.Errorf("panel %q: nodes reporting = %v, want 2", q.title, lastCount)
			}
		}
		if series != want {
			t.Errorf("panel %q: %d series with data, want %d: %.400s", q.title, series, want, body)
		}
	}
}

// frontendDS is one datasource in the list Grafana hands its frontend, what
// panels resolve their references against.
type frontendDS struct {
	ID   int    `json:"id"`
	UID  string `json:"uid"`
	Type string `json:"type"`
}

// frontendDatasources is the datasource list Grafana hands its frontend —
// what panels resolve their references against — keyed by name.
func frontendDatasources(t *testing.T, sup *DockerComposeSupervisor, user string) map[string]frontendDS {
	t.Helper()
	code, body := grafanaGet(t, sup, "/api/frontend/settings", user)
	if code != http.StatusOK {
		t.Fatalf("frontend settings = %d", code)
	}
	var fs struct {
		Datasources map[string]frontendDS `json:"datasources"`
	}
	if err := json.Unmarshal([]byte(body), &fs); err != nil {
		t.Fatalf("frontend settings json: %v", err)
	}
	return fs.Datasources
}

// waitForGrafanaProvisioned waits for the checkable facts that Grafana has
// applied the provisioning now on disk, as Grafana itself reports them: the
// VictoriaMetrics datasource its frontend settings list carries wantDSUID
// ("" = any uid), and the starter dashboard model it serves contains
// wantDashRef. Not Grafana's database: from Grafana 13 the dashboard lives in
// unified storage and the legacy dashboard table stays empty (see
// waitForProvisionedDashboard). A request that fails while the (re)started
// Grafana comes up is retried; the deadline bounds only how long Grafana may
// take to provision.
func waitForGrafanaProvisioned(t *testing.T, sup *DockerComposeSupervisor, wantDSUID, wantDashRef string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	var lastUID string
	var lastRef bool
	var lastErr error
	for {
		lastUID, lastRef, lastErr = provisionedState(sup, wantDashRef)
		if lastErr == nil && lastUID != "" && (wantDSUID == "" || lastUID == wantDSUID) && lastRef {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Grafana did not apply the provisioning within %s: datasource uid = %q (want %q), dashboard contains %q = %v, last error = %v\n%s",
				within, lastUID, wantDSUID, wantDashRef, lastRef, lastErr, grafanaProvisioningDiagnostics(sup))
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// provisionedState reads, from Grafana's API, the VictoriaMetrics
// datasource's uid and whether the starter dashboard model contains ref.
func provisionedState(sup *DockerComposeSupervisor, ref string) (string, bool, error) {
	code, body, err := grafanaFetch(sup, "/api/frontend/settings")
	if err != nil {
		return "", false, err
	}
	if code != http.StatusOK {
		return "", false, fmt.Errorf("frontend settings = %d", code)
	}
	var fs struct {
		Datasources map[string]frontendDS `json:"datasources"`
	}
	if err := json.Unmarshal([]byte(body), &fs); err != nil {
		return "", false, fmt.Errorf("frontend settings json: %w", err)
	}
	uid := fs.Datasources["VictoriaMetrics"].UID
	code, body, err = grafanaFetch(sup, "/api/dashboards/uid/"+starterDashboardUID)
	if err != nil {
		return uid, false, err
	}
	if code != http.StatusOK {
		return uid, false, fmt.Errorf("dashboard model = %d", code)
	}
	return uid, strings.Contains(body, ref), nil
}

// TestGrafanaDatasourceUID_TransitionFromAutoUID: a cluster provisioned by
// the pre-fix api on the Grafana it shipped with (11.5.1: datasource with a
// Grafana-derived uid, dashboard pointing at a uid that does not exist) is
// started by the new code, at the new pin, on the same state and Grafana
// database. With nothing done by hand, the datasource row takes the fixed uid
// in place and every panel returns data. Grafana 13.3.1 refuses to start on
// that database by itself; the supervisor's carryDatasourceUIDs is what makes
// this pass.
func TestGrafanaDatasourceUID_TransitionFromAutoUID(t *testing.T) {
	requireDocker(t)
	stateDir := funcStateDir(t)
	composeDown()
	t.Cleanup(composeDown)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// --- BEFORE: the provisioning and the Grafana every such cluster runs.
	before := grafanaFuncSupervisor(t, stateDir, true)
	before.grafanaProvisioning = legacyGrafanaProvisioning(t)
	before.cfg.GrafanaImage = previousGrafanaImage
	if err := before.Start(ctx); err != nil {
		t.Fatalf("start (pre-fix provisioning, Grafana 11.5.1): %v", err)
	}
	waitForGrafanaProvisioned(t, before, "", "PBFA97CFB590B2093", 3*time.Minute)
	waitForProvisionedDashboard(t, before, 3*time.Minute)
	seedClusterMetrics(t, before)

	dsBefore := frontendDatasources(t, before, "alice")["VictoriaMetrics"]
	if dsBefore.UID == "" || dsBefore.UID == vmDatasourceUID {
		t.Fatalf("precondition: VictoriaMetrics uid = %q; want Grafana's derived uid", dsBefore.UID)
	}
	t.Logf("pre-fix: VictoriaMetrics has Grafana-derived uid %s (row id %d)", dsBefore.UID, dsBefore.ID)
	// Reproduce the customer-visible bug: the panel's own query names a
	// datasource Grafana does not have. (The browser renders this as
	// "Datasource PBFA97CFB590B2093 was not found"; the API answers 404
	// "Data source not found", measured on 11.5.1.)
	qs := dashboardPanelQueries(t, before, "alice")
	if qs[0].dsUID != "PBFA97CFB590B2093" {
		t.Fatalf("precondition: pre-fix dashboard points at %q", qs[0].dsUID)
	}
	code, body := runPanelQuery(t, before, "alice", qs[0])
	if code != http.StatusNotFound || !strings.Contains(body, "Data source not found") {
		t.Fatalf("precondition: the pre-fix panel query should fail with datasource-not-found, got %d %.400s", code, body)
	}
	t.Logf("pre-fix panel query, as on the bench: %d %.200s", code, body)

	// --- AFTER: the new code at the new pin, same state dir and Grafana
	// database. This is exactly what the api does on its next Start after
	// an update.
	after := grafanaFuncSupervisor(t, stateDir, true)
	if err := after.Start(ctx); err != nil {
		t.Fatalf("start (fixed provisioning): %v\n%s", err, grafanaProvisioningDiagnostics(after))
	}
	waitForGrafanaProvisioned(t, after, vmDatasourceUID, vmDatasourceUID, 3*time.Minute)

	t.Run("datasource took the fixed uid in place", func(t *testing.T) {
		all := frontendDatasources(t, after, "alice")
		ds := all["VictoriaMetrics"]
		if ds.UID != vmDatasourceUID {
			t.Fatalf("VictoriaMetrics uid = %q, want %q", ds.UID, vmDatasourceUID)
		}
		// Same row, not a second datasource beside the old one.
		if ds.ID != dsBefore.ID {
			t.Errorf("datasource id %d -> %d; want the existing row updated", dsBefore.ID, ds.ID)
		}
		prom := 0
		for name, d := range all {
			if d.Type == "prometheus" {
				prom++
				if name != "VictoriaMetrics" {
					t.Errorf("unexpected prometheus datasource %q (%s)", name, d.UID)
				}
			}
		}
		if prom != 1 {
			t.Errorf("%d prometheus datasources, want 1", prom)
		}
		if lk := all["Loki"]; lk.UID != "" {
			// Loki is off in this harness; if present it must be fixed too.
			if lk.UID != lokiDatasourceUID {
				t.Errorf("Loki uid = %q, want %q", lk.UID, lokiDatasourceUID)
			}
		}
	})

	t.Run("every panel returns data", func(t *testing.T) {
		waitForProvisionedDashboard(t, after, 3*time.Minute)
		assertPanelsReturnData(t, after, "alice")
	})
}

// TestGrafanaDatasourceUID_FreshInstall: a node that has never run the obs
// stack gets the fixed uid directly and every panel returns data.
func TestGrafanaDatasourceUID_FreshInstall(t *testing.T) {
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
	waitForGrafanaProvisioned(t, sup, vmDatasourceUID, vmDatasourceUID, 3*time.Minute)
	waitForProvisionedDashboard(t, sup, 3*time.Minute)
	seedClusterMetrics(t, sup)
	assertPanelsReturnData(t, sup, "alice")
}

// grafanaProvisioningDiagnostics is what a failed wait prints: the stored
// dashboard's datasource references, as Grafana serves the model, and
// Grafana's provisioning log lines.
func grafanaProvisioningDiagnostics(sup *DockerComposeSupervisor) string {
	var b strings.Builder
	if code, data, err := grafanaFetch(sup, "/api/dashboards/uid/"+starterDashboardUID); err == nil && code == http.StatusOK {
		for _, part := range strings.Split(data, `"datasource"`)[1:] {
			fmt.Fprintf(&b, "stored datasource ref: %.80s\n", part)
		}
	} else {
		fmt.Fprintf(&b, "dashboard model: %d %v\n", code, err)
	}
	logs, _ := exec.Command("docker", "logs", "--tail", "400", grafanaFuncContainer).CombinedOutput()
	for _, l := range strings.Split(string(logs), "\n") {
		if strings.Contains(l, "provisioning") || strings.Contains(l, "level=error") {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}

// rangeLastValueIs reports whether a Prometheus query_range response has
// exactly one series whose newest point is want.
func rangeLastValueIs(body, want string) bool {
	var resp struct {
		Data struct {
			Result []struct {
				Values [][]any `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if json.Unmarshal([]byte(body), &resp) != nil || len(resp.Data.Result) != 1 {
		return false
	}
	v := resp.Data.Result[0].Values
	if len(v) == 0 || len(v[len(v)-1]) != 2 {
		return false
	}
	return v[len(v)-1][1] == want
}
