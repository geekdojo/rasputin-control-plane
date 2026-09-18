package obs

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The starter dashboard shipped from 2026-06-02 to 2026-09-18 with every
// panel pointing at datasource uid PBFA97CFB590B2093 — a datasource Rasputin
// never provisioned — so every panel on every cluster showed "Datasource
// PBFA97CFB590B2093 was not found". Nothing checked the reference against the
// provisioning. These tests do, for every dashboard the api provisions.

// legacyGrafanaFS holds the provisioning files exactly as they shipped
// before the fix (copied from origin/main 2b0bd8c). Used to prove the check
// catches the bug, and by the functional transition test as the "before".
// Embedded, not read from disk: CI runs the compiled test binary from the
// repo root, where a relative testdata path does not resolve.
//
//go:embed testdata/grafana-pre-2026-09-18
var legacyGrafanaFS embed.FS

const legacyGrafanaDir = "testdata/grafana-pre-2026-09-18"

func readLegacyGrafana(t *testing.T, name string) []byte {
	t.Helper()
	b, err := legacyGrafanaFS.ReadFile(legacyGrafanaDir + "/" + name)
	if err != nil {
		t.Fatalf("read legacy %s: %v", name, err)
	}
	return b
}

type provisionedDatasource struct {
	Name      string `yaml:"name"`
	UID       string `yaml:"uid"`
	Type      string `yaml:"type"`
	IsDefault bool   `yaml:"isDefault"`
}

func parseDatasources(t *testing.T, body []byte) []provisionedDatasource {
	t.Helper()
	var doc struct {
		Datasources []provisionedDatasource `yaml:"datasources"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("datasources yaml: %v", err)
	}
	if len(doc.Datasources) == 0 {
		t.Fatal("datasources yaml provisions no datasources")
	}
	return doc.Datasources
}

// grafanaBuiltinDatasources are uids Grafana itself serves, never provisioned.
var grafanaBuiltinDatasources = map[string]bool{
	"grafana": true, "-- Grafana --": true, "-- Mixed --": true, "-- Dashboard --": true,
}

// unresolvedDatasourceRefs returns one line per datasource reference in the
// dashboard that would not resolve against the provisioned datasources, and
// the number of references it checked. A reference resolves when it names a
// provisioned uid (object form, with a matching type if one is given), a
// provisioned name or uid (legacy string form), a Grafana builtin, or a
// dashboard variable of type "datasource" whose plugin type is provisioned.
// A null/absent reference means "the default datasource" and resolves only if
// one datasource is marked default.
func unresolvedDatasourceRefs(dashboard []byte, dss []provisionedDatasource) ([]string, int, error) {
	var root any
	if err := json.Unmarshal(dashboard, &root); err != nil {
		return nil, 0, err
	}
	byUID := map[string]provisionedDatasource{}
	byName := map[string]provisionedDatasource{}
	hasDefault := false
	for _, d := range dss {
		if d.UID != "" {
			byUID[d.UID] = d
		}
		byName[d.Name] = d
		hasDefault = hasDefault || d.IsDefault
	}
	// Datasource-type template variables, name -> plugin type.
	dsVars := map[string]string{}
	if m, ok := root.(map[string]any); ok {
		if tpl, ok := m["templating"].(map[string]any); ok {
			list, _ := tpl["list"].([]any)
			for _, v := range list {
				vm, _ := v.(map[string]any)
				if vm["type"] == "datasource" {
					name, _ := vm["name"].(string)
					q, _ := vm["query"].(string)
					dsVars[name] = q
				}
			}
		}
	}
	typeProvisioned := func(typ string) bool {
		for _, d := range dss {
			if d.Type == typ {
				return true
			}
		}
		return false
	}
	resolveVar := func(ref string) (bool, bool) {
		name := strings.TrimPrefix(ref, "$")
		name = strings.TrimSuffix(strings.TrimPrefix(name, "{"), "}")
		if name == ref {
			return false, false // not a variable reference
		}
		typ, ok := dsVars[name]
		return true, ok && typeProvisioned(typ)
	}

	var bad []string
	checked := 0
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				child := x[k]
				p := path + "." + k
				if k == "datasource" {
					checked++
					if msg := checkRef(child, byUID, byName, hasDefault, resolveVar); msg != "" {
						bad = append(bad, p+": "+msg)
					}
					continue
				}
				walk(p, child)
			}
		case []any:
			for i, e := range x {
				walk(fmt.Sprintf("%s[%d]", path, i), e)
			}
		}
	}
	walk("$", root)
	return bad, checked, nil
}

func checkRef(v any, byUID, byName map[string]provisionedDatasource, hasDefault bool,
	resolveVar func(string) (bool, bool)) string {
	switch r := v.(type) {
	case nil:
		if !hasDefault {
			return "null (default datasource) but no provisioned datasource is isDefault"
		}
		return ""
	case string:
		if grafanaBuiltinDatasources[r] {
			return ""
		}
		if isVar, ok := resolveVar(r); isVar {
			if !ok {
				return fmt.Sprintf("%q is not a datasource variable of a provisioned type", r)
			}
			return ""
		}
		if _, ok := byUID[r]; ok {
			return ""
		}
		if _, ok := byName[r]; ok {
			return ""
		}
		return fmt.Sprintf("%q is neither a provisioned datasource uid nor name", r)
	case map[string]any:
		uid, _ := r["uid"].(string)
		typ, _ := r["type"].(string)
		if uid == "" {
			if !hasDefault {
				return "no uid (default datasource) but no provisioned datasource is isDefault"
			}
			return ""
		}
		if grafanaBuiltinDatasources[uid] {
			return ""
		}
		if isVar, ok := resolveVar(uid); isVar {
			if !ok {
				return fmt.Sprintf("uid %q is not a datasource variable of a provisioned type", uid)
			}
			return ""
		}
		d, ok := byUID[uid]
		if !ok {
			return fmt.Sprintf("uid %q is not a provisioned datasource uid", uid)
		}
		if typ != "" && typ != d.Type {
			return fmt.Sprintf("uid %q is type %q in the dashboard but %q in provisioning", uid, typ, d.Type)
		}
		return ""
	default:
		return fmt.Sprintf("unexpected datasource reference %v", v)
	}
}

// renderGrafanaProvisioning writes the real Grafana config into a temp state
// dir, exactly as Start does, and returns the state dir.
func renderGrafanaProvisioning(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{StateDir: dir})
	if err != nil {
		t.Fatalf("NewDockerComposeSupervisor: %v", err)
	}
	if err := sup.prepareHostDirs(); err != nil {
		t.Fatalf("prepareHostDirs: %v", err)
	}
	if err := sup.writeGrafanaConfig(); err != nil {
		t.Fatalf("writeGrafanaConfig: %v", err)
	}
	return dir
}

// Every provisioned datasource carries an explicit, unique uid. Without one
// Grafana derives it from the name, and a dashboard has nothing stable to
// point at.
func TestProvisionedDatasources_HaveFixedUniqueUIDs(t *testing.T) {
	dir := renderGrafanaProvisioning(t)
	body, err := os.ReadFile(filepath.Join(dir, grafanaDatasourcesPath))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	defaults := 0
	for _, d := range parseDatasources(t, body) {
		if d.IsDefault {
			defaults++
		}
		if d.UID == "" {
			t.Errorf("datasource %q has no uid; Grafana would generate one", d.Name)
			continue
		}
		if prev, dup := seen[d.UID]; dup {
			t.Errorf("uid %q used by both %q and %q", d.UID, prev, d.Name)
		}
		seen[d.UID] = d.Name
	}
	if seen[vmDatasourceUID] != "VictoriaMetrics" {
		t.Errorf("VictoriaMetrics is not provisioned with uid %q (got %v)", vmDatasourceUID, seen)
	}
	if defaults != 1 {
		t.Errorf("%d default datasources, want exactly 1", defaults)
	}
}

// Every dashboard the api provisions — every JSON file in the directory the
// dashboard provider reads — references only datasources the api provisions.
func TestProvisionedDashboards_EveryDatasourceRefResolves(t *testing.T) {
	dir := renderGrafanaProvisioning(t)
	dsBody, err := os.ReadFile(filepath.Join(dir, grafanaDatasourcesPath))
	if err != nil {
		t.Fatal(err)
	}
	dss := parseDatasources(t, dsBody)

	// The provider must read the directory the compose file mounts the
	// rendered dashboards into, or the files below are not what Grafana loads.
	provBody, err := os.ReadFile(filepath.Join(dir, grafanaDashboardsPath))
	if err != nil {
		t.Fatal(err)
	}
	var prov struct {
		Providers []struct {
			Options struct {
				Path string `yaml:"path"`
			} `yaml:"options"`
		} `yaml:"providers"`
	}
	if err := yaml.Unmarshal(provBody, &prov); err != nil {
		t.Fatalf("dashboards yaml: %v", err)
	}
	if len(prov.Providers) != 1 || prov.Providers[0].Options.Path != "/var/lib/grafana/dashboards" {
		t.Fatalf("dashboard providers = %+v; this test walks grafana-config/dashboards, which compose mounts at /var/lib/grafana/dashboards", prov.Providers)
	}

	var dashboards []string
	root := filepath.Join(dir, grafanaConfigSubdir, "dashboards")
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".json") {
			dashboards = append(dashboards, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dashboards) == 0 {
		t.Fatal("no provisioned dashboards found — the check would pass vacuously")
	}
	for _, p := range dashboards {
		body, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		bad, checked, err := unresolvedDatasourceRefs(body, dss)
		if err != nil {
			t.Errorf("%s: invalid JSON: %v", filepath.Base(p), err)
			continue
		}
		if checked == 0 {
			t.Errorf("%s: no datasource references found — the check would pass vacuously", filepath.Base(p))
		}
		for _, b := range bad {
			t.Errorf("%s: %s", filepath.Base(p), b)
		}
	}
}

// The check catches the shipped bug: run against the pre-fix files it
// reports every panel's reference to PBFA97CFB590B2093.
func TestProvisionedDashboards_CheckCatchesPreFixDashboard(t *testing.T) {
	dsBody := readLegacyGrafana(t, "datasources.yaml")
	dash := readLegacyGrafana(t, "cluster-overview.json")
	bad, checked, err := unresolvedDatasourceRefs(dash, parseDatasources(t, dsBody))
	if err != nil {
		t.Fatal(err)
	}
	if checked != 3 || len(bad) != 3 {
		t.Fatalf("checked %d refs, flagged %d: %v; want all 3 panels flagged", checked, len(bad), bad)
	}
	for _, b := range bad {
		if !strings.Contains(b, "PBFA97CFB590B2093") {
			t.Errorf("flagged for the wrong reason: %s", b)
		}
	}
}

// The resolver's other branches, so a future dashboard using a variable, a
// builtin or the default datasource is judged correctly.
func TestUnresolvedDatasourceRefs_Forms(t *testing.T) {
	dss := []provisionedDatasource{
		{Name: "VictoriaMetrics", UID: "vm", Type: "prometheus", IsDefault: true},
		{Name: "Loki", UID: "lk", Type: "loki"},
	}
	cases := []struct {
		name string
		ref  string
		vars string
		ok   bool
	}{
		{"provisioned uid", `{"type":"prometheus","uid":"vm"}`, ``, true},
		{"unknown uid", `{"type":"prometheus","uid":"PBFA97CFB590B2093"}`, ``, false},
		{"type mismatch", `{"type":"loki","uid":"vm"}`, ``, false},
		{"default (null)", `null`, ``, true},
		{"default (no uid)", `{"type":"prometheus"}`, ``, true},
		{"legacy name string", `"Loki"`, ``, true},
		{"legacy unknown string", `"Prometheus"`, ``, false},
		{"builtin", `{"type":"datasource","uid":"grafana"}`, ``, true},
		{"datasource variable", `{"type":"prometheus","uid":"${ds}"}`,
			`{"name":"ds","type":"datasource","query":"prometheus"}`, true},
		{"variable of unprovisioned type", `{"uid":"$ds"}`,
			`{"name":"ds","type":"datasource","query":"influxdb"}`, false},
		{"undeclared variable", `{"uid":"${nope}"}`, ``, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vars := "[]"
			if c.vars != "" {
				vars = "[" + c.vars + "]"
			}
			dash := fmt.Sprintf(`{"templating":{"list":%s},"panels":[{"datasource":%s}]}`, vars, c.ref)
			bad, checked, err := unresolvedDatasourceRefs([]byte(dash), dss)
			if err != nil {
				t.Fatal(err)
			}
			if checked != 1 {
				t.Fatalf("checked %d refs, want 1", checked)
			}
			if got := len(bad) == 0; got != c.ok {
				t.Errorf("resolved = %v, want %v (%v)", got, c.ok, bad)
			}
		})
	}
}

// Grafana reads datasource provisioning only at startup, and compose
// recreates the container only when its definition changes. Before the fix
// the digest covered grafana.ini alone, so a changed datasources file (this
// fix's uid) would have left the running Grafana on the old uid until the
// next reboot. Every provisioned file must move the digest.
func TestRenderCompose_GrafanaDigestCoversProvisioning(t *testing.T) {
	// One state dir for every variant: its path is part of the digest
	// input, so only the file contents may differ between renders.
	dir := t.TempDir()
	digest := func(files []grafanaFile) string {
		sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{StateDir: dir})
		if err != nil {
			t.Fatalf("NewDockerComposeSupervisor: %v", err)
		}
		sup.grafanaProvisioning = files
		if err := sup.prepareHostDirs(); err != nil {
			t.Fatalf("prepareHostDirs: %v", err)
		}
		if err := sup.writeGrafanaConfig(); err != nil {
			t.Fatalf("writeGrafanaConfig: %v", err)
		}
		raw, err := sup.renderCompose()
		if err != nil {
			t.Fatalf("renderCompose: %v", err)
		}
		lines := strings.Split(string(raw), "\n")
		for i, l := range lines {
			if strings.TrimSpace(l) != "grafana:" {
				continue
			}
			for _, x := range lines[i:min(i+12, len(lines))] {
				if strings.Contains(x, "RASPUTIN_OBS_CONFIG_DIGEST") {
					return strings.TrimSpace(x)
				}
			}
		}
		t.Fatalf("no grafana config digest in compose:\n%s", raw)
		return ""
	}
	// Each variant changes exactly one file.
	base := digest(defaultGrafanaProvisioning)
	if again := digest(defaultGrafanaProvisioning); again != base {
		t.Fatalf("digest unstable across identical renders: %q vs %q", base, again)
	}
	for i := range defaultGrafanaProvisioning {
		changed := append([]grafanaFile(nil), defaultGrafanaProvisioning...)
		changed[i].body += "\n# changed\n"
		if d := digest(changed); d == base {
			t.Errorf("changing %s did not change Grafana's config digest — the running container would keep the old file",
				changed[i].path)
		}
	}
}
