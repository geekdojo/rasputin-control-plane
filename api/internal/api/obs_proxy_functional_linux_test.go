//go:build linux

// Functional test: the UI still renders Grafana after geekdojo-brain#453.
//
// The browser never talks to Grafana. It talks to the api's /observability/
// reverse proxy (obs_proxy.go), which now reaches Grafana over a unix socket
// instead of a TCP port. This test puts the REAL proxy handler in front of the
// REAL pinned Grafana image, brought up by the api's own supervisor in socket
// mode, and drives it the way the UI's iframe does:
//
//	(a) pages render — the app shell HTML, the static assets it references
//	    under serve_from_sub_path, and a dashboard page;
//	(b) the Grafana API calls the UI makes succeed — frontend settings,
//	    search, the dashboard model, and a panel query through the
//	    VictoriaMetrics datasource;
//	(c) Grafana Live's WebSocket upgrade works through the proxy: the
//	    httputil.ReverseProxy upgrade path over a unix-dialing transport,
//	    carried as far as a real Live (centrifuge) connect reply.
//
// Opt-in: RASPUTIN_GRAFANA_FUNCTIONAL must be set; "required" turns skips into
// failures (what CI sets). Linux + docker only — see obs's
// grafana_functional_linux_test.go for why it is opt-in.

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	_ "modernc.org/sqlite"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
)

const proxyFuncProject = "rasputin-obs-proxyfunc"

func proxyFuncRequireDocker(t *testing.T) {
	t.Helper()
	mode := os.Getenv("RASPUTIN_GRAFANA_FUNCTIONAL")
	if mode == "" {
		t.Skip("set RASPUTIN_GRAFANA_FUNCTIONAL=1 to run (needs docker)")
	}
	fail := func(format string, args ...any) {
		t.Helper()
		if mode == "required" {
			t.Fatalf("RASPUTIN_GRAFANA_FUNCTIONAL=required but "+format, args...)
		}
		t.Skipf(format, args...)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		fail("docker not on PATH: %v", err)
	}
	if out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		fail("docker daemon unreachable: %v (%s)", err, strings.TrimSpace(string(out)))
	}
}

func proxyFuncComposeDown() {
	_ = exec.Command("docker", "compose", "-p", proxyFuncProject, "down", "-v",
		"--remove-orphans").Run()
}

func TestObsProxyGrafanaUI_OverSocket(t *testing.T) {
	proxyFuncRequireDocker(t)

	// Short: the socket path must stay under the ~104-byte sun_path limit.
	stateDir, err := os.MkdirTemp("/tmp", "rgp")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })
	proxyFuncComposeDown()
	t.Cleanup(proxyFuncComposeDown)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	on, off := true, false
	sup, err := obs.NewDockerComposeSupervisor(obs.DockerComposeSupervisorConfig{
		StateDir:         stateDir,
		ProjectName:      proxyFuncProject,
		VMListenAddr:     "127.0.0.1:19316",
		UseGrafanaSocket: &on,
		EnableLoki:       &off,
		EnableVMAlert:    &off,
		EnableCadvisor:   &off,
		HealthTimeout:    150 * time.Second,
		PullTimeout:      5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("supervisor: %v", err)
	}
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if sup.GrafanaSocketPath() == "" || sup.GrafanaTransport() == nil {
		t.Fatal("Grafana is not on a socket — this test would prove nothing")
	}

	// The real handler, behind a stand-in for the session middleware: in
	// production RequireSession puts the passkey user in the context.
	sink, err := obs.NewVMSink(obs.VMSinkConfig{Supervisor: sup})
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	srv := &Server{obs: obs.NewStatus(sup, sink, nil)}
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(auth.WithUser(r.Context(), &auth.User{Name: "alice"}))
		srv.handleObservabilityProxy(w, r)
	}))
	defer front.Close()

	client := front.Client()
	client.Timeout = 30 * time.Second
	get := func(t *testing.T, path string) (int, http.Header, string) {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, front.URL+path, nil)
		// A browser on the operator's session may carry anything; the
		// proxy must overwrite it.
		req.Header.Set("X-Webauth-User", "admin")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header, string(b)
	}

	// Before ANY authenticated request: wait until Grafana has committed the
	// provisioned dashboard to its own DB. On a fresh Grafana database a
	// request that lands before first-boot provisioning finishes hides the
	// dashboard from search for a while (a fixed 60s idle, longer under load
	// — measured, and the same on main's config). Once the row is committed
	// the first search sees it, so after this wait there is ONE read.
	waitForGrafanaDashboardRow(t, filepath.Join(stateDir, "grafana-data", "grafana.db"),
		starterDashboardUID, 3*time.Minute)
	dashUID := starterDashboardUID
	if code, _, body := get(t, "/observability/api/search?type=dash-db"); code != http.StatusOK ||
		!strings.Contains(body, `"uid":"`+dashUID+`"`) {
		logs, _ := exec.Command("docker", "logs", "--tail", "300", "rasputin-grafana").CombinedOutput()
		var keep []string
		for _, l := range strings.Split(string(logs), "\n") {
			ll := strings.ToLower(l)
			if strings.Contains(ll, "provision") || strings.Contains(ll, "folder") ||
				strings.Contains(ll, "level=error") {
				keep = append(keep, l)
			}
		}
		t.Fatalf("dashboard row is committed but search through the proxy does not show it: %d %s\n--- grafana log (filtered) ---\n%s",
			code, body, strings.Join(keep, "\n"))
	}

	t.Run("a: pages and static assets render", func(t *testing.T) {
		code, hdr, html := get(t, "/observability/")
		if code != http.StatusOK {
			t.Fatalf("app shell = %d", code)
		}
		if ct := hdr.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("app shell content-type = %q", ct)
		}
		// serve_from_sub_path: the shell sets <base href="/observability/">
		// and references its assets relative to it (public/build/…), so a
		// browser fetches /observability/public/…. Resolve them the same way
		// and load every one through the proxy.
		base := regexp.MustCompile(`<base href="([^"]+)"`).FindStringSubmatch(html)
		if base == nil || base[1] != "/observability/" {
			t.Fatalf("shell <base href> = %v, want /observability/", base)
		}
		refs := regexp.MustCompile(`(?:src|href)="((?:/observability/)?public/(?:build|img)/[^"]+)"`).
			FindAllStringSubmatch(html, -1)
		seen := map[string]bool{}
		kinds := map[string]int{}
		for _, m := range refs {
			a := m[1]
			if !strings.HasPrefix(a, "/") {
				a = base[1] + a
			}
			if seen[a] {
				continue
			}
			seen[a] = true
			code, hdr, body := get(t, a)
			if code != http.StatusOK || len(body) == 0 {
				t.Errorf("asset %s = %d (%d bytes)", a, code, len(body))
				continue
			}
			ct := hdr.Get("Content-Type")
			switch {
			case strings.Contains(ct, "javascript"):
				kinds["js"]++
			case strings.Contains(ct, "css"):
				kinds["css"]++
			case strings.HasPrefix(ct, "image/"):
				kinds["img"]++
			default:
				t.Errorf("asset %s content-type = %q", a, ct)
			}
		}
		// Grafana 11.5.1's shell references both (measured: 8 js, 2 css).
		if kinds["css"] == 0 || kinds["js"] == 0 {
			t.Fatalf("shell assets not all loaded through the proxy: %v (refs: %v)", kinds, refs)
		}
		t.Logf("loaded %d distinct static assets through the proxy: %v", len(seen), kinds)

		// A dashboard page — what the UI's iframe actually points at.
		code, hdr, _ = get(t, "/observability/d/"+dashUID)
		if code != http.StatusOK || !strings.HasPrefix(hdr.Get("Content-Type"), "text/html") {
			t.Errorf("dashboard page = %d %q", code, hdr.Get("Content-Type"))
		}
		// allow_embedding: the iframe must not be refused by the browser.
		if xfo := hdr.Get("X-Frame-Options"); strings.EqualFold(xfo, "deny") {
			t.Errorf("X-Frame-Options = %q; the UI's iframe embed would be blocked", xfo)
		}
	})

	var vmUID string
	t.Run("b: the API calls the UI makes succeed", func(t *testing.T) {
		code, _, body := get(t, "/observability/api/frontend/settings")
		if code != http.StatusOK {
			t.Fatalf("frontend settings = %d", code)
		}
		var fs struct {
			AppURL      string `json:"appUrl"`
			AppSubURL   string `json:"appSubUrl"`
			Datasources map[string]struct {
				UID string `json:"uid"`
			} `json:"datasources"`
		}
		if err := json.Unmarshal([]byte(body), &fs); err != nil {
			t.Fatalf("frontend settings json: %v", err)
		}
		if fs.AppSubURL != "/observability" {
			t.Errorf("appSubUrl = %q, want /observability", fs.AppSubURL)
		}
		// Regression guard: with protocol = socket, a %(protocol)s root_url
		// became socket://… in every URL Grafana generates.
		if !strings.HasPrefix(fs.AppURL, "http://") {
			t.Errorf("appUrl = %q, want http://… (not socket://)", fs.AppURL)
		}
		vmUID = fs.Datasources["VictoriaMetrics"].UID
		if vmUID == "" {
			t.Fatalf("VictoriaMetrics datasource not in frontend settings: %.500s", body)
		}

		// Identity: the proxy's header wins over the client's `admin`.
		code, _, body = get(t, "/observability/api/user")
		if code != http.StatusOK || !strings.Contains(body, `"login":"alice"`) {
			t.Errorf("/api/user = %d %s; want the session user alice", code, body)
		}

		code, _, body = get(t, "/observability/api/dashboards/uid/"+dashUID)
		if code != http.StatusOK || !strings.Contains(body, "Cluster Overview") {
			t.Errorf("dashboard model = %d %.300s", code, body)
		}

		// A panel query, exactly as a dashboard panel issues it.
		// vector(1) returns a sample without depending on any series having
		// been scraped yet.
		q := fmt.Sprintf(`{"queries":[{"refId":"A","datasource":{"uid":%q,"type":"prometheus"},`+
			`"expr":"vector(1)","instant":true}],"from":"now-5m","to":"now"}`, vmUID)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
			front.URL+"/observability/api/ds/query", strings.NewReader(q))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", front.URL)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("ds/query: %v", err)
		}
		qb, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("ds/query = %d %.500s", resp.StatusCode, qb)
		}
		if !strings.Contains(string(qb), `"A"`) || !strings.Contains(string(qb), `"values"`) {
			t.Errorf("ds/query returned no frame for A: %.500s", qb)
		}
	})

	// The query above names the datasource by the uid Grafana reports, so it
	// could not see the bug that shipped from 2026-06-02: the DASHBOARD's
	// panels named a datasource uid that did not exist, and every panel
	// showed "Datasource PBFA97CFB590B2093 was not found". This runs each
	// panel's own query, with the panel's own datasource reference, from the
	// dashboard model the browser loads through the proxy.
	// The dashboard model the browser loads through the proxy, and a panel
	// query issued exactly as a panel issues it — with the panel's own
	// datasource reference, after template interpolation.
	type dashVar struct {
		Name       string `json:"name"`
		Type       string `json:"type"`
		Multi      bool   `json:"multi"`
		IncludeAll bool   `json:"includeAll"`
		AllValue   string `json:"allValue"`
		Datasource struct {
			UID string `json:"uid"`
		} `json:"datasource"`
	}
	type dashPanel struct {
		Title      string          `json:"title"`
		Datasource json.RawMessage `json:"datasource"`
		Targets    []struct {
			Expr    string `json:"expr"`
			Instant bool   `json:"instant"`
		} `json:"targets"`
	}
	loadDashboard := func(t *testing.T) ([]dashPanel, []dashVar) {
		t.Helper()
		code, _, body := get(t, "/observability/api/dashboards/uid/"+dashUID)
		if code != http.StatusOK {
			t.Fatalf("dashboard model = %d", code)
		}
		var model struct {
			Dashboard struct {
				Panels     []dashPanel `json:"panels"`
				Templating struct {
					List []dashVar `json:"list"`
				} `json:"templating"`
			} `json:"dashboard"`
		}
		if err := json.Unmarshal([]byte(body), &model); err != nil {
			t.Fatalf("dashboard model json: %v", err)
		}
		if len(model.Dashboard.Panels) == 0 {
			t.Fatalf("dashboard has no panels: %.300s", body)
		}
		return model.Dashboard.Panels, model.Dashboard.Templating.List
	}
	type series struct {
		labels map[string]string
		last   any
		tail   string // newest timestamps and values, for failure messages
	}
	runPanelQuery := func(t *testing.T, ds json.RawMessage, expr string, instant bool) ([]series, bool) {
		t.Helper()
		qj, _ := json.Marshal(expr)
		q := fmt.Sprintf(`{"queries":[{"refId":"A","datasource":%s,"expr":%s,"range":%t,"instant":%t,`+
			`"intervalMs":15000,"maxDataPoints":100}],"from":"now-15m","to":"now"}`, ds, qj, !instant, instant)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
			front.URL+"/observability/api/ds/query", strings.NewReader(q))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", front.URL)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("ds/query: %v", err)
		}
		qb, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || strings.Contains(strings.ToLower(string(qb)), "not found") {
			t.Errorf("ds/query %s = %d %.400s", expr, resp.StatusCode, qb)
			return nil, false
		}
		var out struct {
			Results map[string]struct {
				Error  string `json:"error"`
				Frames []struct {
					Schema struct {
						Fields []struct {
							Labels map[string]string `json:"labels"`
						} `json:"fields"`
					} `json:"schema"`
					Data struct {
						Values [][]any `json:"values"`
					} `json:"data"`
				} `json:"frames"`
			} `json:"results"`
		}
		if err := json.Unmarshal(qb, &out); err != nil {
			t.Errorf("ds/query json: %v", err)
			return nil, false
		}
		r := out.Results["A"]
		if r.Error != "" {
			t.Errorf("ds/query %s: error %q", expr, r.Error)
			return nil, false
		}
		var got []series
		for _, f := range r.Frames {
			if len(f.Data.Values) < 2 || len(f.Data.Values[1]) == 0 {
				continue
			}
			vs := f.Data.Values[1]
			sr := series{last: vs[len(vs)-1], tail: fmt.Sprint(f.Data.Values[0][max(0, len(vs)-4):], vs[max(0, len(vs)-4):])}
			if len(f.Schema.Fields) > 1 {
				sr.labels = f.Schema.Fields[1].Labels
			}
			got = append(got, sr)
		}
		return got, true
	}
	// interpolate does what Grafana's frontend does to a Prometheus query
	// before it reaches /api/ds/query (the backend does not interpolate
	// dashboard variables): "All" becomes the variable's allValue verbatim;
	// a selected value of a multi/includeAll variable is regex-escaped as
	// prometheusSpecialRegexEscape does. A dashboard with no such variable
	// leaves the expression unchanged — which is how the pre-variable
	// dashboard ignored var-nodeId.
	interpolate := func(expr string, vars []dashVar, selected map[string]string) string {
		for _, v := range vars {
			val, ok := selected[v.Name]
			if !ok {
				val = v.AllValue
			} else {
				val = regexp.MustCompile(`[\\$^*{}\[\]'+?.()|]`).ReplaceAllString(val, `\\$0`)
			}
			expr = strings.ReplaceAll(expr, "${"+v.Name+"}", val)
			expr = strings.ReplaceAll(expr, "$"+v.Name, val)
		}
		return expr
	}

	// The DASHBOARD's panels named a datasource uid that did not exist until
	// 2026-09-18 (every panel: "Datasource PBFA97CFB590B2093 was not
	// found"), and the query in b names the datasource by the uid Grafana
	// reports, so it could not see that. This runs each panel's own query,
	// with the panel's own datasource reference.
	//
	// Two nodes whose ids are prefixes of one another, so "exactly that
	// node" is tested and not just "a node".
	nodeA, nodeB := "cp-compute1", "cp-compute10"
	seeded := false
	t.Run("b2: every starter-dashboard panel returns data", func(t *testing.T) {
		if vmUID == "" {
			t.Skip("subtest b found no VictoriaMetrics datasource")
		}
		seedStarterDashboardMetrics(t, "http://127.0.0.1:19316", nodeA, nodeB)
		seeded = true
		panels, vars := loadDashboard(t)
		for _, p := range panels {
			var ds struct {
				UID string `json:"uid"`
			}
			_ = json.Unmarshal(p.Datasource, &ds)
			if ds.UID != vmUID {
				t.Errorf("panel %q names datasource %s; the provisioned VictoriaMetrics is %q",
					p.Title, p.Datasource, vmUID)
			}
			for _, tg := range p.Targets {
				got, ok := runPanelQuery(t, p.Datasource, interpolate(tg.Expr, vars, nil), tg.Instant)
				if ok && len(got) == 0 {
					t.Errorf("panel %q (%s): no data frames", p.Title, tg.Expr)
				}
			}
		}
	})

	// The node drawer's "in Grafana" link sends var-nodeId=<node id>. Opened
	// with one node selected, every panel shows only that node; opened
	// directly (All), every node.
	t.Run("b3: a node's link shows only that node", func(t *testing.T) {
		if !seeded {
			t.Skip("b2 did not seed metrics")
		}
		panels, vars := loadDashboard(t)
		var nodeVar *dashVar
		for i := range vars {
			if vars[i].Name == "nodeId" {
				nodeVar = &vars[i]
			}
		}
		if nodeVar == nil {
			t.Errorf("the dashboard declares no nodeId variable, so the UI's var-nodeId is ignored (variables: %+v)", vars)
		} else {
			if nodeVar.Datasource.UID != vmUID {
				t.Errorf("nodeId variable datasource = %q, want %q", nodeVar.Datasource.UID, vmUID)
			}
			// The variable's options come from Grafana's own datasource
			// resource call, as the variable's label_values query makes it;
			// the link's value must be one of them, or Grafana has nothing
			// to select.
			code, _, body := get(t, "/observability/api/datasources/uid/"+vmUID+
				"/resources/api/v1/label/nodeId/values?match[]=rasputin_cpu_percent")
			if code != http.StatusOK || !strings.Contains(body, `"`+nodeA+`"`) || !strings.Contains(body, `"`+nodeB+`"`) {
				t.Errorf("nodeId options through Grafana = %d %.300s; want %s and %s", code, body, nodeA, nodeB)
			}
		}
		nodesOf := func(got []series) []string {
			var ids []string
			for _, s := range got {
				ids = append(ids, s.labels["nodeId"])
			}
			sort.Strings(ids)
			return ids
		}
		for _, p := range panels {
			for _, tg := range p.Targets {
				isCount := strings.HasPrefix(tg.Expr, "count(")
				one, ok1 := runPanelQuery(t, p.Datasource, interpolate(tg.Expr, vars, map[string]string{"nodeId": nodeA}), tg.Instant)
				all, ok2 := runPanelQuery(t, p.Datasource, interpolate(tg.Expr, vars, nil), tg.Instant)
				if !ok1 || !ok2 {
					continue
				}
				if isCount {
					if len(one) != 1 || one[0].last != float64(1) {
						t.Errorf("panel %q with var-nodeId=%s: %+v; want 1 node reporting", p.Title, nodeA, one)
					}
					if len(all) != 1 || all[0].last != float64(2) {
						t.Errorf("panel %q with All: %+v; want 2 nodes reporting", p.Title, all)
					}
					// A node that is not reporting: no value, which the
					// panel's noValue shows as 0.
					silent, ok := runPanelQuery(t, p.Datasource,
						interpolate(tg.Expr, vars, map[string]string{"nodeId": "cp-compute9"}), tg.Instant)
					if ok && len(silent) != 0 {
						t.Errorf("panel %q for a silent node: %+v; want no value", p.Title, silent)
					}
					continue
				}
				if got := nodesOf(one); len(got) != 1 || got[0] != nodeA {
					t.Errorf("panel %q with var-nodeId=%s shows nodes %v; want only %s", p.Title, nodeA, got, nodeA)
				}
				if got := nodesOf(all); len(got) != 2 || got[0] != nodeA || got[1] != nodeB {
					t.Errorf("panel %q with All shows nodes %v; want %s and %s", p.Title, got, nodeA, nodeB)
				}
			}
		}
	})

	t.Run("c: Grafana Live websocket upgrades through the proxy", func(t *testing.T) {
		wsURL := "ws" + strings.TrimPrefix(front.URL, "http") + "/observability/api/live/ws"
		dctx, dcancel := context.WithTimeout(ctx, 30*time.Second)
		defer dcancel()
		// Same-origin, as the browser sends it: Grafana Live refuses a
		// cross-origin upgrade.
		conn, resp, err := websocket.Dial(dctx, wsURL, &websocket.DialOptions{
			HTTPHeader: http.Header{"Origin": []string{front.URL}},
		})
		if err != nil {
			status := 0
			if resp != nil {
				status = resp.StatusCode
			}
			t.Fatalf("websocket dial through the proxy: %v (HTTP %d)", err, status)
		}
		defer conn.Close(websocket.StatusNormalClosure, "")
		if resp.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("upgrade status = %d, want 101", resp.StatusCode)
		}
		// Carry it past the handshake: a Live (centrifuge JSON) connect
		// command must get its reply back through the hijacked socket.
		if err := conn.Write(dctx, websocket.MessageText, []byte(`{"id":1,"connect":{}}`)); err != nil {
			t.Fatalf("write connect: %v", err)
		}
		_, msg, err := conn.Read(dctx)
		if err != nil {
			t.Fatalf("read connect reply: %v", err)
		}
		if !strings.Contains(string(msg), `"id":1`) || !strings.Contains(string(msg), `"connect"`) {
			t.Fatalf("unexpected Live reply: %s", msg)
		}
		t.Logf("Live connect reply through the proxy: %.200s", msg)
	})
}

// seedStarterDashboardMetrics writes the rasputin_* series the starter
// dashboard plots into VictoriaMetrics, stamped at least 30s back so VM's
// search latency offset does not hide them, and waits for the checkable fact that VM
// serves them. The deadline bounds only VM making an accepted import
// searchable.
func seedStarterDashboardMetrics(t *testing.T, vmURL string, nodes ...string) {
	t.Helper()
	// A sample every 10s for the last five minutes, ending 30s back, as an
	// agent reports. A single sample is not enough: VictoriaMetrics gives a
	// lone sample a short lookbehind, so a range query sees it at one step
	// only, and "count(...) or vector(0)" then reads 0 at the last step
	// (measured on v1.103.0).
	now := time.Now()
	var b strings.Builder
	for i := 3; i <= 30; i++ {
		ts := now.Add(-time.Duration(i) * 10 * time.Second).UnixMilli()
		for _, n := range nodes {
			fmt.Fprintf(&b, "rasputin_cpu_percent{nodeId=%q} 20 %d\n", n, ts)
			fmt.Fprintf(&b, "rasputin_mem_used_bytes{nodeId=%q} 1e9 %d\n", n, ts)
		}
	}
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Post(vmURL+"/api/v1/import/prometheus", "text/plain", strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("seed VM: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("seed VM: HTTP %d", resp.StatusCode)
	}
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
			vmURL, end-900, end))
		if err == nil {
			body, _ := io.ReadAll(r.Body)
			_ = r.Body.Close()
			last = string(body)
			if rangeLastValueIs(last, fmt.Sprint(len(nodes))) {
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

// starterDashboardUID is the fixed uid in the provisioned cluster-overview
// dashboard (obs package, starterDashboardJSON).
const starterDashboardUID = "rasputin-cluster-overview"

// waitForGrafanaDashboardRow polls Grafana's own SQLite database, read-only,
// until the dashboard row exists. Same fact as obs's
// waitForProvisionedDashboardRow; duplicated because test helpers cannot
// cross packages.
func waitForGrafanaDashboardRow(t *testing.T, dbPath, uid string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	var lastErr error
	for {
		db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro&_pragma=busy_timeout(2000)")
		if err == nil {
			var n int
			qctx, qcancel := context.WithTimeout(context.Background(), 3*time.Second)
			err = db.QueryRowContext(qctx, `SELECT COUNT(*) FROM dashboard WHERE uid = ?`, uid).Scan(&n)
			qcancel()
			_ = db.Close()
			if err == nil && n > 0 {
				return
			}
		}
		if err != nil {
			lastErr = err
		}
		if time.Now().After(deadline) {
			t.Fatalf("Grafana never committed dashboard %q to %s within %s (last error: %v)",
				uid, dbPath, within, lastErr)
		}
		time.Sleep(250 * time.Millisecond)
	}
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
