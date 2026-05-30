package api

import (
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// GET /api/alerts
//
// Returns the current snapshot of active alerts derived from inventory,
// jobs, apps, and setup state. No query parameters in v0 — the caller
// renders / filters. The shape is stable across future "real" alert
// subsystem work (rules engine + persisted ack/dismiss) so the UI doesn't
// need to change when that lands.
func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	out, err := s.alerts.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if out == nil {
		out = []proto.Alert{}
	}
	writeJSON(w, http.StatusOK, out)
}
