package api

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// GET /api/alerts
//
// Returns the current snapshot of active alerts derived from inventory,
// jobs, apps, and setup state — plus, when the rules engine is wired,
// every non-dismissed persisted alert from vmalert. The shape is
// stable across the v0 → Slice 1.5 transition: ack/dismiss flags now
// carry meaningful values for Source=rule entries; aggregator-derived
// alerts continue to ignore them.
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

// POST /api/alerts/{id}/ack
func (s *Server) handleAlertAck(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id required")
		return
	}
	a, err := s.alerts.Ack(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "alert not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// POST /api/alerts/{id}/dismiss
func (s *Server) handleAlertDismiss(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id required")
		return
	}
	a, err := s.alerts.Dismiss(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "alert not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a)
}
