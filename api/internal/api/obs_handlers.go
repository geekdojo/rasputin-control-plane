package api

import (
	"log"
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

// handleObsStatus returns a snapshot of the obs stack — the operator's
// stored opt-in, the lifecycle state (off/starting/on), whether
// VictoriaMetrics reports healthy, and when the metrics fan-out last
// succeeded / failed. Always 200; "obs is off" is conveyed via
// Snapshot.State, not an HTTP error, so the UI's polling loop stays simple.
//
// The status struct itself is nil-safe — if obs wasn't wired into the
// Server, this returns state=off with zero values rather than 500.
func (s *Server) handleObsStatus(w http.ResponseWriter, r *http.Request) {
	snap := s.obs.Snapshot(r.Context())
	writeJSON(w, http.StatusOK, snap)
}

// POST /api/obs/enable
// Body: none. Authenticated. Submits the obs.enable saga and returns the
// job so the UI can follow it — this is async on purpose: a cold enable
// pulls ~500 MB and outlives any reasonable request timeout.
//
// Session-gated like every other mutating endpoint. There is no admin role
// in this system (the users table has no role column) — a passkey holder
// is an operator, and the tailnet is the boundary.
func (s *Server) handleObsEnable(w http.ResponseWriter, r *http.Request) {
	s.submitObsJob(w, r, "obs.enable")
}

// POST /api/obs/disable
// Body: none. Authenticated. Submits obs.disable — stops the stack but
// keeps its volumes, so re-enabling later returns with history intact.
func (s *Server) handleObsDisable(w http.ResponseWriter, r *http.Request) {
	s.submitObsJob(w, r, "obs.disable")
}

// submitObsJob is the shared body of the two toggle handlers. Returns 503
// when the obs workflows were never registered (the supervisor failed to
// construct at boot) rather than the runner's generic unknown-kind error,
// which reads like a bug rather than a configuration state.
func (s *Server) submitObsJob(w http.ResponseWriter, r *http.Request, kind string) {
	job, err := s.runner.Submit(r.Context(), kind, nil, creator(r))
	if err != nil {
		log.Printf("api/obs: submit %s: %v", kind, err)
		writeError(w, http.StatusServiceUnavailable,
			"observability cannot be changed on this control plane: "+err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

// handleObsLogs proxies a LogQL range query to Loki. Query params:
//
//	query     — Raw LogQL expression. Optional if node/container/grep set.
//	node      — node_id label filter (composed-form shortcut).
//	container — container label filter.
//	grep      — case-insensitive regex line filter; wrapped in `(?i)`.
//	start     — RFC3339 timestamp (or omit for "1h ago")
//	end       — RFC3339 timestamp (or omit for "now")
//	limit     — max entries (default 100, max 5000)
//
// The drawer's Logs tab uses the composed shortcut so the UI never
// has to spell a LogQL selector. Power users can hit /api/obs/logs
// with ?query= directly. Composed wins over raw query when both set.
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
	qv := r.URL.Query()
	lq := obs.LogsQuery{
		Query:     qv.Get("query"),
		NodeID:    qv.Get("node"),
		Container: qv.Get("container"),
		Grep:      qv.Get("grep"),
	}
	if lq.Query == "" && lq.NodeID == "" && lq.Container == "" {
		writeError(w, http.StatusBadRequest,
			"query parameter required (or set node= / container=)")
		return
	}
	if v := qv.Get("start"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "start must be RFC3339: "+err.Error())
			return
		}
		lq.Start = t
	}
	if v := qv.Get("end"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "end must be RFC3339: "+err.Error())
			return
		}
		lq.End = t
	}
	if v := qv.Get("limit"); v != "" {
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

// handleObsContainers returns the cAdvisor-derived container table for
// the NodeDetailDrawer's Containers tab.
//
//	node — node id (required); filters on the node_id label so the drawer
//	       shows that node's containers (Slice 1.2b per-node collectors).
//
// 503 when obs is off, 502 if VM errors. Returns [] (not 404) when no
// containers match — the UI renders that as "no containers visible from
// this node" rather than a hard error.
func (s *Server) handleObsContainers(w http.ResponseWriter, r *http.Request) {
	cc := s.obs.Containers()
	if cc == nil {
		writeError(w, http.StatusServiceUnavailable,
			"obs.containers: VictoriaMetrics not configured (RASPUTIN_OBS_ENABLED=1)")
		return
	}
	node := r.URL.Query().Get("node")
	if node == "" {
		writeError(w, http.StatusBadRequest, "node parameter required")
		return
	}
	rows, err := cc.List(r.Context(), node)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if rows == nil {
		rows = []obs.Container{} // non-null for the UI
	}
	writeJSON(w, http.StatusOK, rows)
}
