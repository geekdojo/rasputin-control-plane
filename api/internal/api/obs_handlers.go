package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
)

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
