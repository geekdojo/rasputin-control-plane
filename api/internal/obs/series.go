package obs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SeriesClient queries VictoriaMetrics via /api/v1/query_range and
// translates the result into the {ts, value} point list the UI's chart
// components expect.
//
// The job of the shim is to keep PromQL out of the UI. The page asks for
// "give me CPU% for node X for the last 30m at 30s steps" — we know
// which underlying metric maps to that and build the query here. Adding
// a new chart on the front-end is a one-line MetricKey case in this
// file, not a new PromQL string in TypeScript.
type SeriesClient struct {
	sup    Supervisor
	client *http.Client
}

// SeriesClientConfig is the constructor input.
type SeriesClientConfig struct {
	// Supervisor must report a non-empty VMBaseURL() once VM is up.
	Supervisor Supervisor
	// HTTPClient is the transport used for the query. Defaults to a 10s
	// client — range queries with wide windows can take a few seconds.
	HTTPClient *http.Client
}

// NewSeriesClient constructs a SeriesClient. Supervisor is required.
func NewSeriesClient(cfg SeriesClientConfig) (*SeriesClient, error) {
	if cfg.Supervisor == nil {
		return nil, errors.New("obs: SeriesClient requires a Supervisor")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &SeriesClient{sup: cfg.Supervisor, client: client}, nil
}

// SeriesKey names a UI-facing metric. The shim maps each key to a
// concrete PromQL expression — so the UI's contract is the key set,
// not the underlying metric names.
type SeriesKey string

const (
	// SeriesCPUPercent — the agent's rasputin_cpu_percent. 0..100.
	SeriesCPUPercent SeriesKey = "cpu"
	// SeriesMemPercent — derived as 100 * used/total. Easier to read
	// on a single-axis chart than absolute bytes.
	SeriesMemPercent SeriesKey = "mem"
	// SeriesMemUsedBytes — raw bytes used; useful for "is it growing?"
	// over a long window.
	SeriesMemUsedBytes SeriesKey = "mem_bytes"
	// SeriesDiskPercent — derived as 100 * used/total of the root fs.
	SeriesDiskPercent SeriesKey = "disk"
	// SeriesLoad1 — agent-emitted 1-minute load average. Not currently
	// published by the v0 agent; included so the UI can ask for it once
	// the metric lands without a contract bump.
	SeriesLoad1 SeriesKey = "load1"
)

// SeriesQuery names a single chart-worth of data.
type SeriesQuery struct {
	// NodeID is required — every UI-facing metric is per-node.
	NodeID string
	// Metric is one of the SeriesKey constants above.
	Metric SeriesKey
	// Range is how far back to look. Defaults to 30m if zero.
	Range time.Duration
	// Step is the resolution. Defaults to Range/120 (≈120 points) so
	// the same query at 30m vs. 24h returns a chart-sized series, not
	// 2880 points the browser has to thin client-side.
	Step time.Duration
}

// SeriesPoint matches the UI's MetricPoint shape.
type SeriesPoint struct {
	Ts    time.Time `json:"ts"`
	Value float64   `json:"value"`
}

// SeriesResult bundles the resolved query with its points.
type SeriesResult struct {
	NodeID string        `json:"nodeId"`
	Metric SeriesKey     `json:"metric"`
	Unit   string        `json:"unit"`
	Range  string        `json:"range"`
	Step   string        `json:"step"`
	Points []SeriesPoint `json:"points"`
}

// Query returns a chart-shaped series. Returns an empty Points slice
// (not nil) when VM has no data for the window — the UI renders that
// as "no samples" rather than treating it as an error.
func (c *SeriesClient) Query(ctx context.Context, q SeriesQuery) (*SeriesResult, error) {
	if q.NodeID == "" {
		return nil, errors.New("obs.Series: nodeId required")
	}
	if q.Range <= 0 {
		q.Range = 30 * time.Minute
	}
	if q.Step <= 0 {
		// Aim for ~120 points; clamp to [10s, 5m] so very short or very
		// long windows don't degenerate.
		q.Step = q.Range / 120
		if q.Step < 10*time.Second {
			q.Step = 10 * time.Second
		}
		if q.Step > 5*time.Minute {
			q.Step = 5 * time.Minute
		}
	}
	expr, unit, err := promExpr(q.Metric, q.NodeID)
	if err != nil {
		return nil, err
	}
	base := c.sup.VMBaseURL()
	if base == "" {
		return nil, errors.New("obs.Series: VM base url empty (obs not started?)")
	}
	now := time.Now().UTC()
	start := now.Add(-q.Range)

	params := url.Values{}
	params.Set("query", expr)
	params.Set("start", strconv.FormatInt(start.Unix(), 10))
	params.Set("end", strconv.FormatInt(now.Unix(), 10))
	params.Set("step", fmt.Sprintf("%ds", int(q.Step.Seconds())))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/api/v1/query_range?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vm query_range: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("vm query_range HTTP %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}
	pts, err := decodeMatrixFirstSeries(body)
	if err != nil {
		return nil, err
	}
	return &SeriesResult{
		NodeID: q.NodeID,
		Metric: q.Metric,
		Unit:   unit,
		Range:  q.Range.String(),
		Step:   q.Step.String(),
		Points: pts,
	}, nil
}

// promExpr maps a UI SeriesKey to a PromQL expression scoped by nodeId.
// Returns the unit string the UI uses for axis formatting.
func promExpr(key SeriesKey, nodeID string) (expr, unit string, err error) {
	// PromQL string escaping: nodeId labels we mint are derived from
	// inventory ids (lowercase + dashes), so backslash/quote escaping is
	// not in play — but we still quote-wrap to keep the query
	// well-formed if a future id ever contains punctuation.
	id := strconv.Quote(nodeID)
	switch key {
	case SeriesCPUPercent:
		return fmt.Sprintf(`rasputin_cpu_percent{nodeId=%s}`, id), "percent", nil
	case SeriesMemPercent:
		return fmt.Sprintf(
			`100 * rasputin_mem_used_bytes{nodeId=%s} / `+
				`ignoring(__name__) rasputin_mem_total_bytes{nodeId=%s}`,
			id, id), "percent", nil
	case SeriesMemUsedBytes:
		return fmt.Sprintf(`rasputin_mem_used_bytes{nodeId=%s}`, id), "bytes", nil
	case SeriesDiskPercent:
		return fmt.Sprintf(
			`100 * rasputin_disk_used_bytes{nodeId=%s} / `+
				`ignoring(__name__) rasputin_disk_total_bytes{nodeId=%s}`,
			id, id), "percent", nil
	case SeriesLoad1:
		// Not yet emitted; included as a forward-compat hook so the UI
		// can ask without the api bouncing the request.
		return fmt.Sprintf(`rasputin_load1{nodeId=%s}`, id), "load", nil
	default:
		return "", "", fmt.Errorf("obs.Series: unknown metric %q", key)
	}
}

// decodeMatrixFirstSeries unwraps VM's standard Prometheus-compatible
// response and returns the first series's points. Returns an empty
// slice (not an error) when no series matched — that's "no data yet,"
// the UI's normal startup state.
//
// Response shape:
//
//	{"status":"success","data":{"resultType":"matrix","result":[
//	   {"metric":{...},"values":[[<ts_s_float>, "<value_str>"], ...]},
//	   ...
//	]}}
func decodeMatrixFirstSeries(body []byte) ([]SeriesPoint, error) {
	var env struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Metric map[string]string `json:"metric"`
				Values [][2]any          `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("vm response decode: %w", err)
	}
	if env.Status != "success" {
		return nil, fmt.Errorf("vm response status=%q error=%q",
			env.Status, env.Error)
	}
	if len(env.Data.Result) == 0 {
		return []SeriesPoint{}, nil
	}
	raw := env.Data.Result[0].Values
	out := make([]SeriesPoint, 0, len(raw))
	for _, pair := range raw {
		// pair[0] is float seconds; pair[1] is string value (Prom JSON).
		tsF, ok := pair[0].(float64)
		if !ok {
			continue
		}
		valStr, ok := pair[1].(string)
		if !ok {
			continue
		}
		val, err := strconv.ParseFloat(valStr, 64)
		if err != nil {
			continue
		}
		if math.IsNaN(val) || math.IsInf(val, 0) {
			// Prom serializes gaps as "NaN" / "+Inf" / "-Inf"; ParseFloat
			// accepts those without erroring, so we drop them here. Charts
			// render gaps as breaks rather than spurious zeroes.
			continue
		}
		out = append(out, SeriesPoint{
			Ts:    time.Unix(int64(tsF), 0).UTC(),
			Value: val,
		})
	}
	return out, nil
}
