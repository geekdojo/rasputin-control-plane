package obs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// LogsClient queries Loki via the supervisor's LokiBaseURL. Defined in
// the obs package so the api's HTTP layer doesn't have to know which
// Loki endpoint to call or how to encode the parameters — it just hands
// the query through.
//
// Slice 1.3 supports a single shape: instant + range LogQL via
// /loki/api/v1/query_range. Streaming / WebSocket tail can land later
// as a separate method (Loki's /tail endpoint is a WebSocket).
type LogsClient struct {
	sup    Supervisor
	client *http.Client
}

// LogsClientConfig is the constructor input.
type LogsClientConfig struct {
	// Supervisor must report a non-empty LokiBaseURL() once Loki is up.
	Supervisor Supervisor
	// HTTPClient is the transport used for the proxy. Defaults to a
	// 30s-timeout client — log queries can fan out across days of data.
	HTTPClient *http.Client
}

// NewLogsClient constructs a LogsClient. Supervisor is required.
func NewLogsClient(cfg LogsClientConfig) (*LogsClient, error) {
	if cfg.Supervisor == nil {
		return nil, errors.New("obs: LogsClient requires a Supervisor")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &LogsClient{sup: cfg.Supervisor, client: client}, nil
}

// LogsQuery is the input to a LogQL range query.
//
// Two shapes are supported:
//
//  1. Raw LogQL — set Query directly. Power-user escape hatch; the
//     handler exposes this when the UI passes ?query=.
//  2. Composed — set NodeID and/or Container and/or Grep. The shim
//     builds a LogQL selector from them so the UI never has to think
//     about LogQL. This is the path the Drawer's Logs tab uses.
//
// Composed wins over Query when both are set, mainly so a partially-
// migrated UI call doesn't silently bypass the per-node filter.
//
// LogQL reference: https://grafana.com/docs/loki/latest/logql/.
// Common shapes the composed form produces:
//
//	{node_id="cp-1"}                                  — every line for that node
//	{node_id="cp-1", container="rasputin-headscale"}  — narrowed to one container
//	{node_id="cp-1"} |~ "(?i)warn"                    — case-insensitive grep
type LogsQuery struct {
	Query     string    // Raw LogQL expression. Optional.
	NodeID    string    // node_id label filter (composed form).
	Container string    // container label filter (composed form).
	Grep      string    // case-insensitive regex line filter (composed form).
	Start     time.Time // Range start. Defaults to "1h ago" if zero.
	End       time.Time // Range end. Defaults to "now" if zero.
	Limit     int       // Max entries. Defaults to 100; capped at 5000.
}

// composedExpr builds a LogQL expression from the per-label filter
// fields. Returns "" when no filters are set (caller falls back to
// raw Query). Exposed (lower-cased) so the test layer can assert the
// exact selectors without invoking the HTTP path.
func composedExpr(q LogsQuery) string {
	var sels []string
	if q.NodeID != "" {
		sels = append(sels, fmt.Sprintf(`node_id=%q`, q.NodeID))
	}
	if q.Container != "" {
		sels = append(sels, fmt.Sprintf(`container=%q`, q.Container))
	}
	if len(sels) == 0 {
		return ""
	}
	expr := "{" + strings.Join(sels, ",") + "}"
	if q.Grep != "" {
		// Wrap in case-insensitive flag + escape backticks (LogQL uses
		// backticks for raw regex literals). The shim leans on LogQL's
		// `|~` so the operator can paste a regex straight from grep.
		expr += " |~ `(?i)" + strings.ReplaceAll(q.Grep, "`", "") + "`"
	}
	return expr
}

// QueryRange proxies a LogQL range query to Loki and returns the raw
// JSON response body. We pass through the body unmodified so the UI
// can switch between matrix (metric) and streams (log line) response
// shapes without the api having to canonicalize them.
//
// Returns (nil, error) on transport failure or non-2xx; the error
// includes a body snippet so the operator can spot LogQL syntax
// errors without tailing Loki's logs.
func (c *LogsClient) QueryRange(ctx context.Context, q LogsQuery) ([]byte, error) {
	// Composed form wins over raw — see LogsQuery comment for why.
	if expr := composedExpr(q); expr != "" {
		q.Query = expr
	}
	if q.Query == "" {
		return nil, errors.New("obs: logs query is required (set Query, or NodeID/Container/Grep)")
	}
	base := c.sup.LokiBaseURL()
	if base == "" {
		return nil, errors.New("obs: Loki not configured (LokiBaseURL empty)")
	}
	now := time.Now().UTC()
	if q.End.IsZero() {
		q.End = now
	}
	if q.Start.IsZero() {
		q.Start = q.End.Add(-1 * time.Hour)
	}
	if q.Limit <= 0 {
		q.Limit = 100
	}
	if q.Limit > 5000 {
		q.Limit = 5000
	}

	// Loki accepts start/end as either RFC3339 strings or nanosecond
	// epoch integers. Nanoseconds avoid timezone parsing on both ends.
	params := url.Values{}
	params.Set("query", q.Query)
	params.Set("start", strconv.FormatInt(q.Start.UnixNano(), 10))
	params.Set("end", strconv.FormatInt(q.End.UnixNano(), 10))
	params.Set("limit", strconv.Itoa(q.Limit))
	params.Set("direction", "backward") // newest first — what the UI wants

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/loki/api/v1/query_range?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("loki query: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // 8 MiB cap
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("loki query HTTP %d: %s",
			resp.StatusCode, string(body))
	}
	return body, nil
}
