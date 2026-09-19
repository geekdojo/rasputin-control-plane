package obs

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// vmalert evaluates the rule group on its own schedule and writes each active
// alert's state back to VictoriaMetrics over remote-write: an `ALERTS` series
// (value 1, label alertstate="pending"|"firing") and an `ALERTS_FOR_STATE`
// series whose value is the unix second the alert became active. It has no
// notifier (-notifier.blackhole); the api reads those series instead
// (RuleAlertsClient), so nothing calls into the api.

// VMAlertEvaluationInterval is the rule group's evaluation interval. It is both
// the group's `interval:` and vmalert's -evaluationInterval, so the rules file
// and the compose flag cannot disagree.
const VMAlertEvaluationInterval = 30 * time.Second

// VMAlertEvalDelay is vmalert's -rule.evalDelay, set explicitly rather than left
// to the upstream default: vmalert evaluates at (now - evalDelay) and stamps the
// ALERTS samples it writes with that evaluation time, so the newest ALERTS
// sample is always at least this old. RuleAlertFreshness has to include it.
const VMAlertEvalDelay = 30 * time.Second

// RuleAlertFreshness is the oldest an ALERTS sample may be and still count as
// "vmalert says this is firing now".
//
// Why a bound exists at all: vmalert writes an ALERTS sample on every
// evaluation while an alert is active, and a staleness marker when it stops. If
// vmalert itself stops (crash, stack partially down), neither arrives, and the
// last firing sample would otherwise be read as current forever. The fact being
// checked is "vmalert wrote this state recently"; the bound is how recently.
//
// Why this value: the newest sample is stamped VMAlertEvalDelay in the past
// (see above); the next evaluation is up to one interval away; remote-write
// flushes on its own cadence (5s upstream default), for which one more interval
// is ample; and one further interval tolerates a single slow or skipped
// evaluation without flapping the alert. So evalDelay + 3 intervals. It is
// derived from vmalert's configured timing, and changes with it.
const RuleAlertFreshness = VMAlertEvalDelay + 3*VMAlertEvaluationInterval

// Reserved metric names. Only processes on the controlplane write these: the
// api's own host-metrics sink (rasputin_*) and vmalert (ALERTS, ALERTS_FOR_STATE).
// The node collector ingress refuses them, so no collector can write a series
// the alert rules evaluate or the api reads back as rule state.
const (
	ReservedMetricPrefixRasputin = "rasputin_"
	ReservedMetricPrefixAlerts   = "ALERTS"
)

// IsReservedMetricName reports whether name is one only the controlplane may
// write (see the Reserved* constants).
func IsReservedMetricName(name string) bool {
	return strings.HasPrefix(name, ReservedMetricPrefixRasputin) || strings.HasPrefix(name, ReservedMetricPrefixAlerts)
}

// RuleAlert is one alert vmalert currently reports as firing.
type RuleAlert struct {
	// Labels are the alert's labels as vmalert sends them to a notifier:
	// alertname, alertgroup, the rule's labels and the expression's series
	// labels. The series name and the alertstate label are removed.
	Labels map[string]string
	// ActiveAt is when the alert became active (pending, then firing), from
	// ALERTS_FOR_STATE. Zero when that series was not found.
	ActiveAt time.Time
}

// RuleAlertsClient reads vmalert's firing alerts from VictoriaMetrics.
type RuleAlertsClient struct {
	sup    Supervisor
	client *http.Client
}

// RuleAlertsClientConfig is the constructor input.
type RuleAlertsClientConfig struct {
	// Supervisor must report a non-empty VMBaseURL() once VM is up.
	Supervisor Supervisor
	// HTTPClient bounds each query. Defaults to a 5s client — two small
	// instant queries.
	HTTPClient *http.Client
}

// NewRuleAlertsClient constructs a RuleAlertsClient. Supervisor is required.
func NewRuleAlertsClient(cfg RuleAlertsClientConfig) (*RuleAlertsClient, error) {
	if cfg.Supervisor == nil {
		return nil, errors.New("obs: RuleAlertsClient requires a Supervisor")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &RuleAlertsClient{sup: cfg.Supervisor, client: client}, nil
}

// Queries the client runs. Both are instant queries with step=RuleAlertFreshness:
// VictoriaMetrics uses an instant query's step as the lookbehind window for the
// raw sample, so a series whose newest sample is older than RuleAlertFreshness,
// or is vmalert's staleness marker, is absent from the result.
const (
	firingAlertsQuery   = `ALERTS{alertstate="firing"}`
	alertsForStateQuery = `ALERTS_FOR_STATE`
)

// Firing returns every alert vmalert reported as firing within
// RuleAlertFreshness. An error means the answer is unknown (VM unreachable, bad
// response), never "nothing is firing" — callers must not resolve on it.
func (c *RuleAlertsClient) Firing(ctx context.Context) ([]RuleAlert, error) {
	base := c.sup.VMBaseURL()
	if base == "" {
		return nil, errors.New("obs.RuleAlerts: VM base url empty (obs not started?)")
	}
	firing, err := c.query(ctx, base, firingAlertsQuery)
	if err != nil {
		return nil, err
	}
	if len(firing) == 0 {
		return []RuleAlert{}, nil
	}
	forState, err := c.query(ctx, base, alertsForStateQuery)
	if err != nil {
		return nil, err
	}
	activeAt := make(map[string]time.Time, len(forState))
	for _, r := range forState {
		if r.value <= 0 {
			continue
		}
		activeAt[labelKey(alertLabels(r.metric))] = time.Unix(int64(r.value), 0).UTC()
	}
	out := make([]RuleAlert, 0, len(firing))
	for _, r := range firing {
		ls := alertLabels(r.metric)
		out = append(out, RuleAlert{Labels: ls, ActiveAt: activeAt[labelKey(ls)]})
	}
	return out, nil
}

func (c *RuleAlertsClient) query(ctx context.Context, base, expr string) ([]queryResult, error) {
	params := url.Values{}
	params.Set("query", expr)
	params.Set("step", strconv.Itoa(int(RuleAlertFreshness/time.Second))+"s")
	res, err := vmQueryInstant(ctx, c.client, base, params)
	if err != nil {
		return nil, fmt.Errorf("vm query %q: %w", expr, err)
	}
	return res, nil
}

// alertLabels strips the series name and alertstate, leaving the labels vmalert
// puts on the alert itself — the same set it used to send to a notifier, so a
// fingerprint derived from them is unchanged.
func alertLabels(metric map[string]string) map[string]string {
	out := make(map[string]string, len(metric))
	for k, v := range metric {
		if k == "__name__" || k == "alertstate" {
			continue
		}
		out[k] = v
	}
	return out
}

// labelKey is a canonical string for a label set, for joining ALERTS to
// ALERTS_FOR_STATE.
func labelKey(ls map[string]string) string {
	keys := make([]string, 0, len(ls))
	for k := range ls {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, k+"="+strconv.Quote(ls[k]))
	}
	return strings.Join(pairs, ",")
}

// RuleAlertSummary is the one-line operator text for an alert the starter rule
// set (vmalertRulesYAML) raises. The api renders it rather than vmalert, because
// with no notifier vmalert's annotations never leave vmalert. Keyed by the
// rule's alert name; TestRuleAlertSummaryCoversEveryRule holds the two lists
// together.
func RuleAlertSummary(labels map[string]string) string {
	node := labels[vmNodeLabel]
	switch labels["alertname"] {
	case "NodeDown":
		return "Node has not reported metrics in 5 minutes"
	case "HighCPU":
		return "Sustained CPU > 90% on " + node
	case "DiskAlmostFull":
		return "Root disk above 85% on " + node
	}
	return ""
}
