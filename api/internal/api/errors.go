package api

import (
	"log/slog"
	"net/http"
)

// Typed error codes a client can branch on. They follow Human System's error
// codes (api/internal/http/errors.go), the interim reference ARCH-COMMON names
// until the Geekdojo common library (geekdojo/geekdojo-brain#668) exists.
const (
	// codeBusUnavailable: the node bus has no usable key or certificate, so
	// there is no pin to serve and no seed to mint.
	codeBusUnavailable = "bus_unavailable"
	// codeNodeAdmissionUnconfigured: the node listener has no admission gate,
	// so it admits nobody.
	codeNodeAdmissionUnconfigured = "node_admission_unconfigured"
	// codeNodeKeyRequired: the request was not made with a registered node
	// key (or, where allowed, a mesh-chain leaf).
	codeNodeKeyRequired = "node_key_required"
	// codeNodeNotAdmitted: the key's node is no longer a member.
	codeNodeNotAdmitted = "node_not_admitted"
	// codeNodeKeyPurpose: the node presented a key this route is not for.
	codeNodeKeyPurpose = "node_key_wrong_purpose"
)

// codedError is the body of a coded error. "error" stays a plain string, as
// every other response here has it, because the UI reads body.error as one
// (ui/lib/api.ts); code and correlationId sit beside it.
type codedError struct {
	Error         string `json:"error"`
	Code          string `json:"code"`
	CorrelationID string `json:"correlationId"`
}

// writeCodedError answers status with a stable code, a safe message and a
// correlation id, and logs a WARN record under that id carrying the route, the
// code and cause — the internal detail, which never reaches the client.
//
// The route is the pattern the request matched ("GET /api/bus/tls"), never
// the path the client sent, so nothing a caller types reaches the log.
func (s *Server) writeCodedError(w http.ResponseWriter, r *http.Request, status int, code, msg string, cause ...slog.Attr) {
	id := s.newCorrelationID()
	attrs := append([]slog.Attr{
		slog.String("correlation_id", id),
		slog.String("route", r.Pattern),
		slog.String("code", code),
	}, cause...)
	s.log.LogAttrs(r.Context(), slog.LevelWarn, "api: request refused", attrs...)
	writeJSON(w, status, codedError{Error: msg, Code: code, CorrelationID: id})
}
