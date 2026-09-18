package obs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The UI's "in Grafana" link from a node sends var-nodeId=<node id>. Until
// 2026-09-18 the starter dashboard declared no variable, so the parameter
// was ignored and every node's link showed the whole cluster. These tests
// hold the three names that have to agree — the label VMSink writes, the
// dashboard's variable, and the URL parameter the UI sends — to each other,
// and require every panel query to filter by the variable.

type starterDashboard struct {
	Templating struct {
		List []struct {
			Name       string          `json:"name"`
			Type       string          `json:"type"`
			Datasource json.RawMessage `json:"datasource"`
			Definition string          `json:"definition"`
			Query      json.RawMessage `json:"query"`
			Multi      bool            `json:"multi"`
			IncludeAll bool            `json:"includeAll"`
			AllValue   string          `json:"allValue"`
			Current    struct {
				Value json.RawMessage `json:"value"`
			} `json:"current"`
		} `json:"list"`
	} `json:"templating"`
	Panels []struct {
		Title   string `json:"title"`
		Targets []struct {
			Expr string `json:"expr"`
		} `json:"targets"`
	} `json:"panels"`
}

func parseStarterDashboard(t *testing.T, body string) starterDashboard {
	t.Helper()
	var d starterDashboard
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatalf("starter dashboard json: %v", err)
	}
	return d
}

// sinkNodeLabel reads the node label name off VMSink's real output, so the
// dashboard is checked against what is actually stored, not a constant.
func sinkNodeLabel(t *testing.T) string {
	t.Helper()
	out := string(encodePromText(&proto.MetricsEvt{
		NodeID: "probe-node", Ts: time.UnixMilli(1_700_000_000_000),
		Metrics: map[string]float64{"cpu_percent": 1},
	}))
	m := regexp.MustCompile(`^rasputin_cpu_percent\{([A-Za-z_][A-Za-z0-9_]*)="probe-node"\} `).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("cannot find the node label in VMSink output %q", out)
	}
	return m[1]
}

func TestStarterDashboard_NodeVariable(t *testing.T) {
	label := sinkNodeLabel(t)
	if label != vmNodeLabel {
		t.Fatalf("VMSink labels nodes %q but the dashboard uses %q", label, vmNodeLabel)
	}
	d := parseStarterDashboard(t, starterDashboardJSON)
	var found bool
	for _, v := range d.Templating.List {
		if v.Name != dashboardNodeVar {
			continue
		}
		found = true
		if v.Type != "query" {
			t.Errorf("variable %s type = %q, want query", v.Name, v.Type)
		}
		var ds struct {
			UID  string `json:"uid"`
			Type string `json:"type"`
		}
		_ = json.Unmarshal(v.Datasource, &ds)
		if ds.UID != vmDatasourceUID || ds.Type != "prometheus" {
			t.Errorf("variable %s datasource = %s, want VictoriaMetrics (%s)", v.Name, v.Datasource, vmDatasourceUID)
		}
		want := "label_values(rasputin_cpu_percent, " + label + ")"
		if v.Definition != want || !strings.Contains(string(v.Query), want) {
			t.Errorf("variable %s query = %s / %q, want %q", v.Name, v.Query, v.Definition, want)
		}
		if !v.Multi || !v.IncludeAll {
			t.Errorf("variable %s multi=%v includeAll=%v; want both, so opening the dashboard shows the whole cluster", v.Name, v.Multi, v.IncludeAll)
		}
		if v.AllValue != ".+" {
			t.Errorf("variable %s allValue = %q, want .+ (every node, including ones that joined after load)", v.Name, v.AllValue)
		}
		if !strings.Contains(string(v.Current.Value), "$__all") {
			t.Errorf("variable %s default = %s, want All", v.Name, v.Current.Value)
		}
	}
	if !found {
		t.Fatalf("starter dashboard has no %q variable, so var-%s in the UI's link is ignored", dashboardNodeVar, dashboardNodeVar)
	}
}

// Every metric selector in every panel query is filtered by the node
// variable. A new panel that forgets the filter would show every node from a
// single node's link.
func TestStarterDashboard_EveryPanelQueryFiltersByNode(t *testing.T) {
	d := parseStarterDashboard(t, starterDashboardJSON)
	checkEveryPanelFiltersByNode(t, d, false)
}

func checkEveryPanelFiltersByNode(t *testing.T, d starterDashboard, wantFail bool) {
	t.Helper()
	filter := vmNodeLabel + `=~"$` + dashboardNodeVar + `"`
	sel := regexp.MustCompile(`rasputin_[A-Za-z0-9_]+(\{[^}]*\})?`)
	var bad []string
	n := 0
	for _, p := range d.Panels {
		if len(p.Targets) == 0 {
			bad = append(bad, p.Title+": no targets")
		}
		for _, tg := range p.Targets {
			ms := sel.FindAllStringSubmatch(tg.Expr, -1)
			if len(ms) == 0 {
				bad = append(bad, p.Title+": query selects no rasputin_* metric: "+tg.Expr)
			}
			for _, m := range ms {
				n++
				if !strings.Contains(m[1], filter) {
					bad = append(bad, p.Title+": "+m[0]+" is not filtered by "+filter)
				}
			}
		}
	}
	if wantFail {
		if len(bad) == 0 {
			t.Fatal("the check passed a dashboard it should reject")
		}
		return
	}
	if n == 0 {
		t.Fatal("no metric selectors found — the check would pass vacuously")
	}
	for _, b := range bad {
		t.Error(b)
	}
}

// The check rejects the dashboard as it shipped before the variable.
func TestStarterDashboard_FilterCheckCatchesUnfilteredDashboard(t *testing.T) {
	d := parseStarterDashboard(t, string(readLegacyGrafana(t, "cluster-overview.json")))
	checkEveryPanelFiltersByNode(t, d, true)
	if len(d.Templating.List) != 0 {
		t.Fatal("legacy dashboard unexpectedly declares variables")
	}
}

// Every Grafana dashboard link in the UI passes only parameters the starter
// dashboard declares, and the node link passes the node variable. Reads the
// UI source next to this package's source (runtime.Caller, not the working
// directory: CI runs the compiled binary from the repo root).
func TestUIGrafanaLinks_UseDashboardVariable(t *testing.T) {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	uiDir := filepath.Join(filepath.Dir(self), "..", "..", "..", "ui")
	if _, err := os.Stat(uiDir); err != nil {
		t.Fatalf("UI source not found at %s: %v", uiDir, err)
	}
	vars := map[string]bool{}
	for _, v := range parseStarterDashboard(t, starterDashboardJSON).Templating.List {
		vars[v.Name] = true
	}
	var meta struct {
		UID string `json:"uid"`
	}
	if err := json.Unmarshal([]byte(starterDashboardJSON), &meta); err != nil || meta.UID == "" {
		t.Fatalf("starter dashboard uid: %v", err)
	}
	link := regexp.MustCompile("observability/d/" + regexp.QuoteMeta(meta.UID) + "[^`'\"]*")
	param := regexp.MustCompile(`var-([A-Za-z0-9_]+)=`)
	links, nodeLinks := 0, 0
	for _, sub := range []string{"app", "components", "lib"} {
		err := filepath.WalkDir(filepath.Join(uiDir, sub), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !(strings.HasSuffix(p, ".tsx") || strings.HasSuffix(p, ".ts")) {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for _, l := range link.FindAllString(string(b), -1) {
				links++
				for _, m := range param.FindAllStringSubmatch(l, -1) {
					if !vars[m[1]] {
						t.Errorf("%s links var-%s, which the dashboard does not declare (declared: %v)", p, m[1], vars)
					}
					if m[1] == dashboardNodeVar {
						nodeLinks++
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", sub, err)
		}
	}
	if links == 0 || nodeLinks == 0 {
		t.Fatalf("found %d dashboard links, %d passing var-%s — expected the node drawer's link", links, nodeLinks, dashboardNodeVar)
	}
}

// The reference check also covers template variables' own datasources: a
// variable pointing at an unprovisioned uid is flagged, and the starter
// dashboard's node variable is among the references it resolves.
func TestUnresolvedDatasourceRefs_CoversTemplateVariables(t *testing.T) {
	dss := []provisionedDatasource{{Name: "VictoriaMetrics", UID: vmDatasourceUID, Type: "prometheus", IsDefault: true}}
	bad, checked, err := unresolvedDatasourceRefs([]byte(
		`{"templating":{"list":[{"name":"nodeId","type":"query","datasource":{"type":"prometheus","uid":"PBFA97CFB590B2093"}}]}}`), dss)
	if err != nil {
		t.Fatal(err)
	}
	if checked != 1 || len(bad) != 1 || !strings.Contains(bad[0], "$.templating.list[0].datasource") {
		t.Fatalf("checked=%d bad=%v; want the variable's datasource flagged", checked, bad)
	}
	bad, checked, err = unresolvedDatasourceRefs([]byte(starterDashboardJSON), dss)
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) != 0 {
		t.Fatalf("starter dashboard refs unresolved: %v", bad)
	}
	// 3 panels + the node variable.
	if checked != 4 {
		t.Fatalf("checked %d datasource refs in the starter dashboard, want 4 (3 panels + %s variable)", checked, dashboardNodeVar)
	}
}

// "Nodes reporting" answers for now, not for the last point of a range, and
// shows 0 rather than "No data" for a silent selection. A range query with
// "or vector(0)" read 0 at its newest step while both nodes reported.
func TestStarterDashboard_NodesReportingIsInstant(t *testing.T) {
	var d struct {
		Panels []struct {
			Title   string `json:"title"`
			Targets []struct {
				Expr    string `json:"expr"`
				Instant bool   `json:"instant"`
				Range   *bool  `json:"range"`
			} `json:"targets"`
			FieldConfig struct {
				Defaults struct {
					NoValue string `json:"noValue"`
				} `json:"defaults"`
			} `json:"fieldConfig"`
		} `json:"panels"`
	}
	if err := json.Unmarshal([]byte(starterDashboardJSON), &d); err != nil {
		t.Fatal(err)
	}
	for _, p := range d.Panels {
		if p.Title != "Nodes reporting" {
			continue
		}
		if len(p.Targets) != 1 || !p.Targets[0].Instant || p.Targets[0].Range == nil || *p.Targets[0].Range {
			t.Errorf("Nodes reporting targets = %+v; want one instant (not range) query", p.Targets)
		}
		if strings.Contains(p.Targets[0].Expr, "vector(0)") {
			t.Errorf("Nodes reporting uses vector(0): %s", p.Targets[0].Expr)
		}
		if p.FieldConfig.Defaults.NoValue != "0" {
			t.Errorf("Nodes reporting noValue = %q, want \"0\"", p.FieldConfig.Defaults.NoValue)
		}
		return
	}
	t.Fatal("no Nodes reporting panel")
}
