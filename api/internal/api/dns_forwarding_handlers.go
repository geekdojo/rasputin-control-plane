package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
)

// dnsForwardingResponse is the settings view: the operator's choice plus the
// effective upstream the forwarder actually resolved to (AA-11, ADR-0004 §10).
type dnsForwardingResponse struct {
	Enabled           bool   `json:"enabled"`
	Upstream          string `json:"upstream"`          // operator-configured ("" = auto)
	EffectiveUpstream string `json:"effectiveUpstream"` // what the forwarder uses now
	FellBack          bool   `json:"fellBack"`          // effective is the public default
}

// applyAndFill re-applies the persisted setting to the running nameserver (a
// no-op idempotent reconcile when unchanged) and fills the effective upstream +
// fellBack into resp. When the nameserver isn't running (RASPUTIN_DNS=off) the
// applier is nil and the effective fields stay empty.
func (s *Server) applyAndFill(r *http.Request, resp *dnsForwardingResponse) error {
	if s.applyDNSForwarding == nil {
		return nil
	}
	eff, fell, err := s.applyDNSForwarding(r.Context())
	if err != nil {
		return err
	}
	resp.EffectiveUpstream, resp.FellBack = eff, fell
	return nil
}

// GET /api/settings/dns-forwarding
func (s *Server) handleGetDNSForwarding(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.setup.GetDNSForwarding(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := dnsForwardingResponse{Enabled: cfg.Enabled, Upstream: cfg.Upstream}
	if err := s.applyAndFill(r, &resp); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/settings/dns-forwarding — Body: { "enabled": bool, "upstream": "ip[:port]" | "" }
func (s *Server) handleSetDNSForwarding(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled  bool   `json:"enabled"`
		Upstream string `json:"upstream"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	cfg, err := s.setup.SetDNSForwarding(r.Context(), setup.DNSForwarding{Enabled: req.Enabled, Upstream: req.Upstream})
	if err != nil {
		if errors.Is(err, setup.ErrInvalidUpstream) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := dnsForwardingResponse{Enabled: cfg.Enabled, Upstream: cfg.Upstream}
	if err := s.applyAndFill(r, &resp); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
