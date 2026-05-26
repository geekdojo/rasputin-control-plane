package api

import (
	"net/http"
	"strings"
	"time"
)

// GET /api/metrics/{nodeId}?range=15m|1h|6h|24h&metric=cpu_percent,mem_used_bytes
//
// Returns the per-name series ordered by ts ascending.
func (s *Server) handleGetMetrics(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "node id required")
		return
	}

	window := parseRange(r.URL.Query().Get("range"))
	to := time.Now().UTC()
	from := to.Add(-window)

	var names []string
	if raw := r.URL.Query().Get("metric"); raw != "" && raw != "all" {
		for _, n := range strings.Split(raw, ",") {
			n = strings.TrimSpace(n)
			if n != "" {
				names = append(names, n)
			}
		}
	}

	series, err := s.metrics.Query(r.Context(), id, names, from, to)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, series)
}

// parseRange maps the friendly range names to a duration. Unknown values
// default to 1h — the most common dashboard window.
func parseRange(s string) time.Duration {
	switch s {
	case "5m":
		return 5 * time.Minute
	case "15m":
		return 15 * time.Minute
	case "1h", "":
		return time.Hour
	case "6h":
		return 6 * time.Hour
	case "24h":
		return 24 * time.Hour
	default:
		return time.Hour
	}
}
