package obs

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
)

var rasputinMetricName = regexp.MustCompile(`rasputin_[A-Za-z0-9_]+`)

// TC-939-14: the metric names the "Secret store" panels query are exactly
// the names encodePromText renders from a store sample.
func TestSecretStoreDashboard_TC_939_14_QueriesWhatTheSamplerEmits(t *testing.T) {
	queried := map[string]bool{}
	for _, p := range unitPanels(t, secretStoreDashboardJSON) {
		if len(p.Targets) == 0 {
			t.Errorf("panel %q has no query", p.Title)
		}
		for _, tg := range p.Targets {
			for _, n := range rasputinMetricName.FindAllString(tg.Expr, -1) {
				queried[n] = true
			}
		}
	}

	// A full sample, from the sampler itself, rendered as VMSink sends it.
	g := newRig(t, &fakeReadings{st: storestate.Sealed, counts: storestate.Counts{Requests: 1, Errors: 1}}, nil)
	g.trigger(t)
	samples := g.inner.storeSamples()
	if len(samples) != 1 {
		t.Fatalf("%d store samples, want 1", len(samples))
	}
	emitted := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(encodePromText(samples[0]))), "\n") {
		emitted[line[:strings.IndexByte(line, '{')]] = true
	}
	want := []string{"rasputin_secretstore_errors_total", "rasputin_secretstore_requests_total", "rasputin_secretstore_sealed", "rasputin_secretstore_storage_bytes"}
	if got := keys(emitted); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("emitted names = %v, want %v", got, want)
	}
	if got := keys(queried); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("queried names = %v, want exactly the emitted %v", got, want)
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var vendorName = regexp.MustCompile(`(?i)openbao|\bbao\b|vault|hashicorp`)

// vendorStrings walks every key and string value of a JSON document and
// returns those that name the vendor.
func vendorStrings(t *testing.T, body string) []string {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("dashboard json: %v", err)
	}
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				if vendorName.MatchString(k) {
					out = append(out, k)
				}
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		case string:
			if vendorName.MatchString(x) {
				out = append(out, x)
			}
		}
	}
	walk(v)
	return out
}

// TC-939-15: no key or string in the dashboard names the vendor, and the
// check catches a vendor name planted in a nested panel field.
func TestSecretStoreDashboard_TC_939_15_VendorNeutralCopy(t *testing.T) {
	if bad := vendorStrings(t, secretStoreDashboardJSON); len(bad) != 0 {
		t.Errorf("dashboard names the vendor: %q", bad)
	}

	var d map[string]any
	if err := json.Unmarshal([]byte(secretStoreDashboardJSON), &d); err != nil {
		t.Fatal(err)
	}
	panel := d["panels"].([]any)[0].(map[string]any)
	opts := panel["fieldConfig"].(map[string]any)["defaults"].(map[string]any)["mappings"].([]any)[0].(map[string]any)["options"].(map[string]any)
	opts["1"].(map[string]any)["text"] = "OpenBao sealed"
	planted, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if bad := vendorStrings(t, string(planted)); len(bad) != 1 || bad[0] != "OpenBao sealed" {
		t.Errorf("planted copy: check found %q, want exactly the planted string", bad)
	}
}

// TC-939-16: every panel's unit, the sealed panel's value mappings, the uid,
// and the file's place in the provisioning list.
func TestSecretStoreDashboard_TC_939_16_UnitsAndProvisioning(t *testing.T) {
	for _, title := range panelsWithoutUnit(unitPanels(t, secretStoreDashboardJSON)) {
		t.Errorf("panel %q declares no unit", title)
	}
	wantUnit := map[string]string{
		"Sealed":              "none",
		"Requests per second": "reqps",
		"Errors per second":   "reqps",
		"Storage used":        "bytes",
	}
	seen := map[string]bool{}
	for _, p := range unitPanels(t, secretStoreDashboardJSON) {
		seen[p.Title] = true
		w, ok := wantUnit[p.Title]
		if !ok {
			t.Errorf("unexpected panel %q", p.Title)
			continue
		}
		if p.FieldConfig.Defaults.Unit != w {
			t.Errorf("panel %q unit = %q, want %q", p.Title, p.FieldConfig.Defaults.Unit, w)
		}
	}
	for title := range wantUnit {
		if !seen[title] {
			t.Errorf("no %q panel", title)
		}
	}

	var d struct {
		UID    string `json:"uid"`
		Title  string `json:"title"`
		Panels []struct {
			Title       string `json:"title"`
			FieldConfig struct {
				Defaults struct {
					NoValue  string `json:"noValue"`
					Mappings []struct {
						Type    string `json:"type"`
						Options map[string]struct {
							Text string `json:"text"`
						} `json:"options"`
					} `json:"mappings"`
				} `json:"defaults"`
			} `json:"fieldConfig"`
		} `json:"panels"`
	}
	if err := json.Unmarshal([]byte(secretStoreDashboardJSON), &d); err != nil {
		t.Fatal(err)
	}
	if d.UID != "rasputin-secret-store" || d.Title != "Secret store" {
		t.Errorf("uid/title = %q/%q, want rasputin-secret-store/Secret store", d.UID, d.Title)
	}
	for _, p := range d.Panels {
		if p.FieldConfig.Defaults.NoValue != "No data from the secret store" {
			t.Errorf("panel %q noValue = %q", p.Title, p.FieldConfig.Defaults.NoValue)
		}
		if p.Title != "Sealed" {
			continue
		}
		if len(p.FieldConfig.Defaults.Mappings) != 1 || p.FieldConfig.Defaults.Mappings[0].Type != "value" {
			t.Fatalf("Sealed mappings = %+v, want one value mapping", p.FieldConfig.Defaults.Mappings)
		}
		o := p.FieldConfig.Defaults.Mappings[0].Options
		if len(o) != 2 || o["0"].Text != "Unsealed" || o["1"].Text != "Sealed" {
			t.Errorf("Sealed mapping options = %+v, want 0 Unsealed, 1 Sealed", o)
		}
	}

	found := false
	for _, f := range defaultGrafanaProvisioning {
		if f.path == "grafana-config/dashboards/secret-store.json" {
			found = f.body == secretStoreDashboardJSON
		}
	}
	if !found {
		t.Error("grafana-config/dashboards/secret-store.json with the dashboard is not in defaultGrafanaProvisioning")
	}
}
