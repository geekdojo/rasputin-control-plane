package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
)

// A signed-in person adds a passkey, a security key, an authenticator app or
// recovery codes to their own account (geekdojo/geekdojo-brain#1150,
// Identity 4.16): POST /api/me/sign-in-methods answers where the browser
// goes for the fresh sign-in that runs it. The person is the caller's
// principal alone; the body names no account.

const (
	codeUnknownMethod = "unknown_method"
	codeClockNotSet   = "clock_not_set"

	msgInvalidMethodBody = "The request body must be a JSON object with one string field, method."
	msgUnknownMethod     = "Choose a passkey, a security key, an authenticator app or recovery codes."
	msgClockNotSet       = "Authenticator apps can be added once Rasputin's clock is set. Add a passkey or security key now, or try again later."
	msgMethodNotReady    = "The sign-in service isn't ready, so nothing was started. Try again."

	// methodBodyLimit bounds the body: one short string field.
	methodBodyLimit = 1 << 10
)

// POST /api/me/sign-in-methods
// Body: {"method": "passkey"|"security_key"|"authenticator_app"|"recovery_codes"}.
// Answers 200 {"next": "/api/auth/signin?action=…"}.
func (s *Server) handleAddSignInMethod(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Method *string `json:"method"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, methodBodyLimit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.Method == nil {
		// The decoder's own text can quote the body, so only a fixed cause
		// is logged.
		s.writeCodedError(w, r, http.StatusBadRequest, codeInvalidRequest, msgInvalidMethodBody, slog.String("cause", "body"))
		return
	}
	m, err := auth.ParseMethod(*req.Method)
	if err != nil {
		s.writeCodedError(w, r, http.StatusBadRequest, codeUnknownMethod, msgUnknownMethod, slog.String("cause", "unknown_method"))
		return
	}
	next, err := s.auth.PrepareMethod(w, r, m)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]string{"next": next})
	case errors.Is(err, auth.ErrClockNotSet):
		s.writeCodedError(w, r, http.StatusConflict, codeClockNotSet, msgClockNotSet, slog.String("cause", "authenticator_app"))
	default:
		s.writeCodedError(w, r, http.StatusServiceUnavailable, codeIdentityNotReady, msgMethodNotReady, slog.String("cause", "no_signin"))
	}
}
