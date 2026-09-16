package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls"
)

// Bus TLS (geekdojo/geekdojo-brain#448). GET is the whole picture: the mode,
// the live pin, and the fact require waits for (every node reporting
// busTls=true, no plaintext connection open) with the reasons it is not yet
// true. PUT moves the ladder; see bustls.Service.SetMode for what each move
// does, including the api restart a plaintext flip needs.

// SetBusTLS wires the bus TLS service. nil (the bus key did not load) makes
// both endpoints answer 503 and leaves the pin out of minted tokens.
func (s *Server) SetBusTLS(svc *bustls.Service) { s.busTLS = svc }

const busTLSUnavailable = "bus TLS is unavailable on this controlplane: the bus key did not load (see the api log); the bus is running plaintext-only"

func (s *Server) handleGetBusTLS(w http.ResponseWriter, r *http.Request) {
	if s.busTLS == nil {
		writeError(w, http.StatusServiceUnavailable, busTLSUnavailable)
		return
	}
	st, err := s.busTLS.Status(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handlePutBusTLS(w http.ResponseWriter, r *http.Request) {
	if s.busTLS == nil {
		writeError(w, http.StatusServiceUnavailable, busTLSUnavailable)
		return
	}
	var req struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	mode, err := bustls.ParseMode(req.Mode)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	st, err := s.busTLS.SetMode(r.Context(), mode)
	var notReady *bustls.NotReadyError
	switch {
	case errors.As(err, &notReady):
		// The refusal carries the picture, so the caller sees exactly which
		// nodes and connections are in the way without a second request.
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "status": st})
	case errors.Is(err, bustls.ErrModePinned):
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "status": st})
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
	default:
		writeJSON(w, http.StatusOK, st)
	}
}

// busPin is the live pin for a minted seed, "" when bus TLS is unavailable.
func (s *Server) busPin() string {
	if s.busTLS == nil {
		return ""
	}
	return s.busTLS.Pin()
}
