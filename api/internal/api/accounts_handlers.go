package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The administrator's password reset (geekdojo/geekdojo-brain#992,
// Identity 4.10): POST /api/accounts/{id}/reset-password checks the request
// and holds the password through a fresh sign-in; the job is submitted only
// when the administrator comes back from it (accounts.ResetAction), so a
// request never followed by a fresh sign-in leaves no job (C24).

const (
	codeAccountNotFound          = "account_not_found"
	codePasswordRefused          = "password_refused"
	codePasswordCheckUnavailable = "password_check_unavailable"
	codeIdentityNotReady         = "identity_not_ready"

	msgAccountNotFound          = "That account doesn't exist."
	msgPasswordCheckUnavailable = "Rasputin can't check passwords right now, so the reset wasn't started."
	msgIdentityNotReady         = "The sign-in service isn't ready, so the reset wasn't started. Try again."
	msgInvalidPassword          = "The request body must be a JSON object with a string field, password, and be no larger than 8 KiB."
)

// resetChecker decides a reset request (*accounts.Resetter).
type resetChecker interface {
	Check(ctx context.Context, by authz.Submitter, target string, pw secret.Value) error
}

// SetResetter installs the reset's check, under keycloak only; until then
// the route answers 503 identity_not_ready.
func (s *Server) SetResetter(rs resetChecker) { s.resetter = rs }

// POST /api/accounts/{id}/reset-password
// Body: {"password": "…"}. Answers 200 {"next": "/api/auth/signin?action=…"},
// where the browser goes for the fresh sign-in.
func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	if s.resetter == nil {
		s.writeCodedError(w, r, http.StatusServiceUnavailable, codeIdentityNotReady, msgIdentityNotReady, slog.String("cause", "unwired"))
		return
	}
	target := r.PathValue("id")
	var req struct {
		Password *string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, operatorSecretBodyLimit)).Decode(&req); err != nil || req.Password == nil {
		// The decoder's own text can quote the body, which holds the
		// password, so only a fixed cause is logged.
		s.writeCodedError(w, r, http.StatusBadRequest, codeInvalidRequest, msgInvalidPassword, slog.String("cause", bodyCause(err)))
		return
	}
	pw := secret.New([]byte(*req.Password))
	err := s.resetter.Check(r.Context(), submitter(r), target, pw)
	var refused *accounts.PasswordRefused
	switch {
	case err == nil:
	case s.refusedSubmit(w, r, accounts.ResetKind, err):
	case errors.Is(err, accounts.ErrAccountNotFound):
		s.writeCodedError(w, r, http.StatusNotFound, codeAccountNotFound, msgAccountNotFound)
	case errors.As(err, &refused):
		s.writeCodedError(w, r, http.StatusBadRequest, codePasswordRefused, refused.Sentence, slog.String("rule", refused.Rule))
	case errors.Is(err, accounts.ErrPasswordCheckUnavailable):
		s.writeCodedError(w, r, http.StatusServiceUnavailable, codePasswordCheckUnavailable, msgPasswordCheckUnavailable)
	default:
		// The identity error names the account in its path, so only a
		// fixed cause is logged; the identity client logged the call.
		s.writeCodedError(w, r, http.StatusServiceUnavailable, codeIdentityNotReady, msgIdentityNotReady, slog.String("cause", "identity"))
	}
	if err != nil {
		pw.Destroy()
		return
	}
	next, err := s.auth.PrepareAction(w, r, accounts.ResetKind, &accounts.ResetPayload{Target: target, Password: pw})
	if err != nil {
		s.writeCodedError(w, r, http.StatusServiceUnavailable, codeIdentityNotReady, msgIdentityNotReady, slog.String("cause", "no_signin"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"next": next})
}
