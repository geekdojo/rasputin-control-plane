package api

import (
	"log/slog"
	"net/http"
)

// Bus TLS (geekdojo/geekdojo-brain#448, #517). The bus accepts only TLS, and
// GET /api/bus/tls answers the one live fact about it: the pin a seed carries.

// BusState is what the api needs from the bus TLS state: the live pin, and
// when there is none, which file failed and why. bustls.State satisfies it.
type BusState interface {
	Pin() (pin string, ok bool)
	Fault() (file string, err error)
}

// busUnavailableMessage is the safe message a client sees when the bus has no
// key. The cause — the file and the error — goes only to the log, under the
// response's correlation id.
const busUnavailableMessage = "the node bus is unavailable on this controlplane: its bus key or certificate could not be used (see the api log)"

// busPinBody is GET /api/bus/tls's answer.
type busPinBody struct {
	Pin string `json:"pin"`
}

func (s *Server) handleGetBusTLS(w http.ResponseWriter, r *http.Request) {
	pin, ok := s.bus.Pin()
	if !ok {
		s.writeBusUnavailable(w, r, busUnavailableMessage)
		return
	}
	writeJSON(w, http.StatusOK, busPinBody{Pin: pin})
}

// writeBusUnavailable answers 503 bus_unavailable with msg, and logs the
// bus's fault under the response's correlation id.
func (s *Server) writeBusUnavailable(w http.ResponseWriter, r *http.Request, msg string) {
	file, err := s.bus.Fault()
	cause := ""
	if err != nil {
		cause = err.Error()
	}
	s.writeCodedError(w, r, http.StatusServiceUnavailable, codeBusUnavailable, msg,
		slog.String("file", file), slog.String("err", cause))
}
