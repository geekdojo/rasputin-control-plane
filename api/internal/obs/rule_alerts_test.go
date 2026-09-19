package obs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubAlertsVM answers /api/v1/query with a canned vector per query string and
// records the params each query arrived with.
type stubAlertsVM struct {
	mu      sync.Mutex
	byQuery map[string]string // query -> JSON body
	status  int
	seen    []map[string]string
}

func (s *stubAlertsVM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/query" {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	s.mu.Lock()
	s.seen = append(s.seen, map[string]string{"query": q.Get("query"), "step": q.Get("step")})
	s.mu.Unlock()
	if s.status != 0 {
		w.WriteHeader(s.status)
		return
	}
	body, ok := s.byQuery[q.Get("query")]
	if !ok {
		body = `{"status":"success","data":{"resultType":"vector","result":[]}}`
	}
	_, _ = w.Write([]byte(body))
}

func newRuleAlertsClient(t *testing.T, vm http.Handler) *RuleAlertsClient {
	t.Helper()
	srv := httptest.NewServer(vm)
	t.Cleanup(srv.Close)
	c, err := NewRuleAlertsClient(RuleAlertsClientConfig{Supervisor: &fakeSupervisor{baseURL: srv.URL}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRuleAlertsClient_FiringJoinsActivationTime(t *testing.T) {
	vm := &stubAlertsVM{byQuery: map[string]string{
		firingAlertsQuery: `{"status":"success","data":{"resultType":"vector","result":[
			{"metric":{"__name__":"ALERTS","alertname":"HighCPU","alertgroup":"rasputin-default","alertstate":"firing","severity":"warning","source":"vmalert","nodeId":"n1"},"value":[1789836786,"1"]},
			{"metric":{"__name__":"ALERTS","alertname":"NodeDown","alertgroup":"rasputin-default","alertstate":"firing","severity":"critical","source":"vmalert"},"value":[1789836786,"1"]}]}}`,
		alertsForStateQuery: `{"status":"success","data":{"resultType":"vector","result":[
			{"metric":{"__name__":"ALERTS_FOR_STATE","alertname":"HighCPU","alertgroup":"rasputin-default","severity":"warning","source":"vmalert","nodeId":"n1"},"value":[1789836786,"1789836740"]},
			{"metric":{"__name__":"ALERTS_FOR_STATE","alertname":"HighCPU","alertgroup":"rasputin-default","severity":"warning","source":"vmalert","nodeId":"n9"},"value":[1789836786,"1789836000"]}]}}`,
	}}
	got, err := newRuleAlertsClient(t, vm).Firing(context.Background())
	if err != nil {
		t.Fatalf("Firing: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d alerts, want 2: %+v", len(got), got)
	}
	byName := map[string]RuleAlert{}
	for _, a := range got {
		if _, ok := a.Labels["__name__"]; ok {
			t.Errorf("labels kept __name__: %v", a.Labels)
		}
		if _, ok := a.Labels["alertstate"]; ok {
			t.Errorf("labels kept alertstate: %v", a.Labels)
		}
		byName[a.Labels["alertname"]] = a
	}
	if want := time.Unix(1789836740, 0).UTC(); !byName["HighCPU"].ActiveAt.Equal(want) {
		t.Errorf("HighCPU activeAt = %v, want %v", byName["HighCPU"].ActiveAt, want)
	}
	if byName["HighCPU"].Labels["nodeId"] != "n1" {
		t.Errorf("HighCPU labels = %v", byName["HighCPU"].Labels)
	}
	if !byName["NodeDown"].ActiveAt.IsZero() {
		t.Errorf("NodeDown has no ALERTS_FOR_STATE series; activeAt = %v, want zero", byName["NodeDown"].ActiveAt)
	}
	// Both queries carry the staleness bound as the lookbehind window.
	wantStep := "120s" // 30s evalDelay + 3 x 30s interval
	if len(vm.seen) != 2 {
		t.Fatalf("queries = %v, want 2", vm.seen)
	}
	for _, q := range vm.seen {
		if q["step"] != wantStep {
			t.Errorf("query %q step = %q, want %q (RuleAlertFreshness)", q["query"], q["step"], wantStep)
		}
	}
}

func TestRuleAlertsClient_NothingFiringSkipsSecondQuery(t *testing.T) {
	vm := &stubAlertsVM{byQuery: map[string]string{}}
	got, err := newRuleAlertsClient(t, vm).Firing(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("got %#v, want an empty, non-nil set", got)
	}
	if len(vm.seen) != 1 || vm.seen[0]["query"] != firingAlertsQuery {
		t.Errorf("queries = %v, want only the ALERTS query", vm.seen)
	}
}

// An unreachable or failing VM is "unknown", never "nothing firing".
func TestRuleAlertsClient_ErrorsAreNotAnEmptySet(t *testing.T) {
	vm := &stubAlertsVM{status: http.StatusServiceUnavailable}
	if got, err := newRuleAlertsClient(t, vm).Firing(context.Background()); err == nil {
		t.Fatalf("got %v, want an error on a 503", got)
	}
	c, _ := NewRuleAlertsClient(RuleAlertsClientConfig{Supervisor: &fakeSupervisor{}})
	if _, err := c.Firing(context.Background()); err == nil {
		t.Fatal("want an error with no VM base URL")
	}
	if _, err := NewRuleAlertsClient(RuleAlertsClientConfig{}); err == nil {
		t.Fatal("want an error with no supervisor")
	}
}

func TestRuleAlertFreshness_DerivedFromVMAlertTiming(t *testing.T) {
	if RuleAlertFreshness != VMAlertEvalDelay+3*VMAlertEvaluationInterval {
		t.Fatalf("RuleAlertFreshness = %v", RuleAlertFreshness)
	}
	// It must outlast the age of the newest sample of a healthy vmalert
	// (evalDelay + one interval), or live alerts would flap.
	if RuleAlertFreshness <= VMAlertEvalDelay+VMAlertEvaluationInterval {
		t.Fatalf("RuleAlertFreshness %v does not cover a healthy vmalert's sample age", RuleAlertFreshness)
	}
}

func TestIsReservedMetricName(t *testing.T) {
	for name, want := range map[string]bool{
		"rasputin_cpu_percent":               true,
		"rasputin_":                          true,
		"ALERTS":                             true,
		"ALERTS_FOR_STATE":                   true,
		"container_cpu_usage_seconds_total":  false,
		"alerts":                             false,
		"node_rasputin_x":                    false,
		"Rasputin_cpu":                       false,
		"":                                   false,
		"go_gc_duration_seconds":             false,
		"prometheus_remote_storage_samples_": false,
	} {
		if got := IsReservedMetricName(name); got != want {
			t.Errorf("IsReservedMetricName(%q) = %v, want %v", name, got, want)
		}
	}
}

// Every rule in the starter set has operator text, and the rules file no
// longer carries annotations nobody reads.
func TestRuleAlertSummaryCoversEveryRule(t *testing.T) {
	names := regexp.MustCompile(`(?m)^\s*- alert: (\S+)$`).FindAllStringSubmatch(vmalertRulesYAML, -1)
	if len(names) == 0 {
		t.Fatal("no rules found in vmalertRulesYAML")
	}
	for _, m := range names {
		if RuleAlertSummary(map[string]string{"alertname": m[1], vmNodeLabel: "n1"}) == "" {
			t.Errorf("rule %s has no RuleAlertSummary", m[1])
		}
	}
	if strings.Contains(vmalertRulesYAML, "annotations:") {
		t.Error("vmalertRulesYAML carries annotations; with no notifier they never leave vmalert")
	}
	if got := RuleAlertSummary(map[string]string{"alertname": "HighCPU", vmNodeLabel: "n7"}); got != "Sustained CPU > 90% on n7" {
		t.Errorf("HighCPU summary = %q", got)
	}
	if !strings.Contains(vmalertRulesYAML, "interval: "+VMAlertEvaluationInterval.String()+"\n") {
		t.Error("rule group interval is not VMAlertEvaluationInterval")
	}
}

func TestRenderCompose_VMAlertHasNoNotifier(t *testing.T) {
	sup, _ := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{StateDir: t.TempDir()})
	body, err := sup.renderCompose()
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(body)
	for _, want := range []string{
		`"-notifier.blackhole"`,
		`"-remoteWrite.url=http://victoriametrics:8428"`,
		`"-evaluationInterval=` + VMAlertEvaluationInterval.String() + `"`,
		`"-rule.evalDelay=` + VMAlertEvalDelay.String() + `"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("compose missing %s\n--- compose ---\n%s", want, s)
		}
	}
	for _, gone := range []string{"-notifier.url", "-notifier.headers", "host.docker.internal", "/api/alerts/webhook"} {
		if strings.Contains(s, gone) {
			t.Errorf("compose still contains %q", gone)
		}
	}
}
