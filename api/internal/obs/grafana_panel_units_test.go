package obs

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// Until 2026-09-18 the starter dashboard's panels declared no unit, so
// "Memory used (bytes) per node" plotted raw byte counts (3000000000) and
// CPU % a bare number. These tests require every panel to declare one, pin
// the units that match what the UI shows, and hold the "Memory % per node"
// panel to the UI's own expression.

type unitPanel struct {
	Title       string `json:"title"`
	FieldConfig struct {
		Defaults struct {
			Unit string   `json:"unit"`
			Min  *float64 `json:"min"`
			Max  *float64 `json:"max"`
		} `json:"defaults"`
	} `json:"fieldConfig"`
	Targets []struct {
		Expr string `json:"expr"`
	} `json:"targets"`
	GridPos struct {
		X, Y, W, H int
	} `json:"gridPos"`
}

func unitPanels(t *testing.T, body string) []unitPanel {
	t.Helper()
	var d struct {
		Panels []unitPanel `json:"panels"`
	}
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatalf("dashboard json: %v", err)
	}
	if len(d.Panels) == 0 {
		t.Fatal("dashboard has no panels")
	}
	return d.Panels
}

// panelsWithoutUnit lists the panels that declare no unit.
func panelsWithoutUnit(ps []unitPanel) []string {
	var out []string
	for _, p := range ps {
		if p.FieldConfig.Defaults.Unit == "" {
			out = append(out, p.Title)
		}
	}
	return out
}

func TestStarterDashboard_EveryPanelDeclaresAUnit(t *testing.T) {
	for _, title := range panelsWithoutUnit(unitPanels(t, starterDashboardJSON)) {
		t.Errorf("panel %q declares no unit (fieldConfig.defaults.unit); its axis would show raw numbers", title)
	}
}

// The check rejects the dashboard as it shipped before units.
func TestStarterDashboard_UnitCheckCatchesPreFixDashboard(t *testing.T) {
	if got := panelsWithoutUnit(unitPanels(t, string(readLegacyGrafana(t, "cluster-overview.json")))); len(got) != 3 {
		t.Fatalf("panels without a unit in the pre-fix dashboard = %v, want all 3", got)
	}
}

func TestStarterDashboard_PanelUnits(t *testing.T) {
	want := map[string]string{
		"CPU % per node": "percent",
		// Grafana's "bytes" is IEC (1024), as the UI's humanBytes is.
		"Memory used (bytes) per node": "bytes",
		"Memory % per node":            "percent",
		"Nodes reporting":              "none",
	}
	seen := map[string]bool{}
	for _, p := range unitPanels(t, starterDashboardJSON) {
		seen[p.Title] = true
		if w, ok := want[p.Title]; ok && p.FieldConfig.Defaults.Unit != w {
			t.Errorf("panel %q unit = %q, want %q", p.Title, p.FieldConfig.Defaults.Unit, w)
		}
	}
	for title := range want {
		if !seen[title] {
			t.Errorf("no %q panel", title)
		}
	}
}

// "Memory % per node" runs the expression the UI's own memory chart runs
// (promExpr, SeriesMemPercent), with the UI's single-node matcher replaced by
// the dashboard's node filter, and is bounded 0..100.
func TestStarterDashboard_MemoryPercentMatchesUI(t *testing.T) {
	const probe = "probe-node"
	uiExpr, uiUnit, err := promExpr(SeriesMemPercent, probe)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.ReplaceAll(uiExpr,
		vmNodeLabel+"="+strconv.Quote(probe),
		vmNodeLabel+`=~"$`+dashboardNodeVar+`"`)
	if want == uiExpr {
		t.Fatalf("could not find the node matcher in the UI's expression %q", uiExpr)
	}
	for _, p := range unitPanels(t, starterDashboardJSON) {
		if p.Title != "Memory % per node" {
			continue
		}
		if len(p.Targets) != 1 || p.Targets[0].Expr != want {
			t.Errorf("Memory %% expr = %+v, want %q", p.Targets, want)
		}
		if p.FieldConfig.Defaults.Unit != uiUnit {
			t.Errorf("Memory %% unit = %q, the UI's is %q", p.FieldConfig.Defaults.Unit, uiUnit)
		}
		mn, mx := p.FieldConfig.Defaults.Min, p.FieldConfig.Defaults.Max
		if mn == nil || mx == nil || *mn != 0 || *mx != 100 {
			t.Errorf("Memory %% min/max = %v/%v, want 0/100", mn, mx)
		}
		return
	}
	t.Fatal("no \"Memory % per node\" panel")
}

// No two panels overlap on Grafana's 24-column grid, and none spills past it.
func TestStarterDashboard_PanelsDoNotOverlap(t *testing.T) {
	ps := unitPanels(t, starterDashboardJSON)
	for i, a := range ps {
		g := a.GridPos
		if g.W <= 0 || g.H <= 0 || g.X < 0 || g.Y < 0 || g.X+g.W > 24 {
			t.Errorf("panel %q gridPos %+v is off the 24-column grid", a.Title, g)
		}
		for _, b := range ps[i+1:] {
			h := b.GridPos
			if g.X < h.X+h.W && h.X < g.X+g.W && g.Y < h.Y+h.H && h.Y < g.Y+g.H {
				t.Errorf("panels %q %+v and %q %+v overlap", a.Title, g, b.Title, h)
			}
		}
	}
}
