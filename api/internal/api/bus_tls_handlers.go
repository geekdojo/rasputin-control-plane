package api

import (
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls"
)

// Bus TLS (geekdojo/geekdojo-brain#448). GET is read-only: the rung the api has
// reached, the live pin, and — when it has not reached require — exactly which
// facts hold the next rung back. There is no PUT: the api moves the ladder
// itself on those facts (bustls.Service).

// SetBusTLS wires the bus TLS service. nil (the bus key did not load) makes
// GET /api/bus/tls answer 503 and leaves the pin out of minted tokens.
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

// busPin is the live pin for a minted seed, "" when bus TLS is unavailable.
func (s *Server) busPin() string {
	if s.busTLS == nil {
		return ""
	}
	return s.busTLS.Pin()
}
