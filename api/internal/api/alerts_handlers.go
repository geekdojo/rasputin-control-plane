package api

import (
	"database/sql"
	"errors"
	"io"
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

// POST /api/alerts/webhook
//
// Receives Alertmanager-v2-format payloads from vmalert (configured with
// -notifier.url=http://api:8080/api/alerts/webhook). Auth: the route is
// session-protected, BUT vmalert can't carry a session cookie. The
// production deployment pattern is to bind the api to a host the
// vmalert container can reach (host.docker.internal:8080) and protect
// with the optional shared secret in the X-Webhook-Secret header when
// RASPUTIN_ALERTS_WEBHOOK_SECRET is set. Without the secret env, anyone
// who can POST to the api can fire spurious alerts — fine for a
// dev/single-user homelab, documented as the production gate.
//
// Returns {"ingested": N} on success.
func (s *Server) handleAlertWebhook(w http.ResponseWriter, r *http.Request) {
	if expected := s.alertsWebhookSecret; expected != "" {
		if got := r.Header.Get("X-Webhook-Secret"); got != expected {
			writeError(w, http.StatusUnauthorized, "alerts webhook: bad secret")
			return
		}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	n, err := s.alerts.IngestWebhook(r.Context(), body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"ingested": n})
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
