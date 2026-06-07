package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
)

// maxSeriesRange caps how far back a single /api/obs/series request
// can ask for. 24h is plenty for a homelab dashboard and keeps a
// runaway client from forcing VM into a multi-day scan. The UI's
// range selector only offers values up to "Last 24h" so this is a
// belt-and-suspenders bound, not the primary UX limiter.
const maxSeriesRange = 24 * time.Hour

// handleObsStatus returns a snapshot of the obs stack — whether it's
// enabled (RASPUTIN_OBS_ENABLED at startup), whether VictoriaMetrics
// reports healthy, and when the metrics fan-out last succeeded / failed.
// Always 200; "obs disabled" is conveyed via Snapshot.Enabled=false, not
// an HTTP error, so the UI's polling loop stays simple.
//
// The status struct itself is nil-safe — if obs wasn't wired into the
// Server, this returns Enabled=false with zero values rather than 500.
func (s *Server) handleObsStatus(w http.ResponseWriter, r *http.Request) {
	snap := s.obs.Snapshot(r.Context())
	writeJSON(w, http.StatusOK, snap)
}

// handleObsLogs proxies a LogQL range query to Loki. Query params:
//
//	query     — LogQL expression. Required.
//	start     — RFC3339 timestamp (or omit for "1h ago")
//	end       — RFC3339 timestamp (or omit for "now")
//	limit     — max entries (default 100, max 5000)
//
// Response is the raw Loki JSON body, passed through. Errors from Loki
// (syntax errors, missing label, etc.) propagate as 502 with the
// underlying message so the UI can surface them to the operator.
func (s *Server) handleObsLogs(w http.ResponseWriter, r *http.Request) {
	logs := s.obs.Logs()
	if logs == nil {
		writeError(w, http.StatusServiceUnavailable,
			"obs.logs: Loki not configured (RASPUTIN_OBS_ENABLED=1 + Loki not disabled)")
		return
	}
	q := r.URL.Query().Get("query")
	if q == "" {
		writeError(w, http.StatusBadRequest, "query parameter required")
		return
	}
	lq := obs.LogsQuery{Query: q}
	if v := r.URL.Query().Get("start"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "start must be RFC3339: "+err.Error())
			return
		}
		lq.Start = t
	}
	if v := r.URL.Query().Get("end"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "end must be RFC3339: "+err.Error())
			return
		}
		lq.End = t
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "limit must be integer: "+err.Error())
			return
		}
		lq.Limit = n
	}
	body, err := logs.QueryRange(r.Context(), lq)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// handleObsSeries returns a chart-shaped {nodeId, metric, points}
// series for the UI's Metrics tab. Query params:
//
//	node    — node id (required)
//	metric  — one of: cpu | mem | mem_bytes | disk | load1 (required)
//	range   — Go duration; default 30m, max 24h
//	step    — Go duration; default range/120, capped [10s, 5m]
//
// All time math is done server-side so the UI doesn't have to think
// about PromQL or VM's quirks (latencyOffset, label naming, etc.).
// Returns 503 if obs is off, 400 if params are bad, 502 if VM errors.
func (s *Server) handleObsSeries(w http.ResponseWriter, r *http.Request) {
	series := s.obs.Series()
	if series == nil {
		writeError(w, http.StatusServiceUnavailable,
			"obs.series: VictoriaMetrics not configured (RASPUTIN_OBS_ENABLED=1)")
		return
	}
	q := r.URL.Query()
	node := q.Get("node")
	if node == "" {
		writeError(w, http.StatusBadRequest, "node parameter required")
		return
	}
	metric := obs.SeriesKey(q.Get("metric"))
	if metric == "" {
		writeError(w, http.StatusBadRequest, "metric parameter required")
		return
	}
	sq := obs.SeriesQuery{NodeID: node, Metric: metric}
	if v := q.Get("range"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "range must be Go duration: "+err.Error())
			return
		}
		if d > maxSeriesRange {
			d = maxSeriesRange
		}
		sq.Range = d
	}
	if v := q.Get("step"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "step must be Go duration: "+err.Error())
			return
		}
		sq.Step = d
	}
	res, err := series.Query(r.Context(), sq)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}
