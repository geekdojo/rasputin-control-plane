package auth

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth/idtoken"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The back-channel logout route (geekdojo/geekdojo-brain#989; register row
// C74; OIDC Back-Channel Logout 1.0): the identity service posts a signed
// logout token here when a person's identity session ends, and every console
// session signed in under that session's sid ends with it.

// maxLogoutForm bounds the route's form body; a logout token is about a
// kilobyte.
const maxLogoutForm = 64 << 10

// handleBackchannel serves POST /api/identity/backchannel/{client}: 200
// once the sid's sessions have ended; 404 for a client the table does not
// hold; 400 with one WARN for a token refused; 500 with one ERROR for a
// store failure.
func (s *Service) handleBackchannel(w http.ResponseWriter, r *http.Request) {
	si := s.signin()
	client := r.PathValue("client")
	if si == nil || client != si.d.ClientID {
		writeErr(w, http.StatusNotFound, "There is no such client.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLogoutForm)
	if err := r.ParseForm(); err != nil || len(r.PostForm["logout_token"]) != 1 || r.PostForm.Get("logout_token") == "" {
		si.backchannelRefused(r, "form")
		writeErr(w, http.StatusBadRequest, "The request carries no single logout token.")
		return
	}
	raw := secret.New([]byte(r.PostForm.Get("logout_token")))
	defer raw.Destroy()
	sid, err := si.d.Verifier.LogoutToken(r.Context(), raw)
	if err != nil {
		reason := "token"
		if errors.Is(err, idtoken.ErrUnavailable) {
			reason = "keys_unavailable"
		}
		si.backchannelRefused(r, reason)
		writeErr(w, http.StatusBadRequest, "The logout token was refused.")
		return
	}
	n, err := s.sessions.EndBySID(r.Context(), sid)
	if err != nil {
		si.log.LogAttrs(r.Context(), slog.LevelError, "A back-channel logout could not end its console sessions.",
			slog.String("event", "backchannel.store_failed"), slog.String("client", client), slog.String("err", err.Error()))
		writeErr(w, http.StatusInternalServerError, "The console sessions could not be ended.")
		return
	}
	si.log.LogAttrs(r.Context(), slog.LevelInfo, "A back-channel logout ended console sessions.",
		slog.String("event", "backchannel.ended"), slog.String("client", client), slog.Int64("sessions", n))
	w.WriteHeader(http.StatusOK)
}

// backchannelRefused writes the one WARN record of a refused logout.
func (s *SignIn) backchannelRefused(r *http.Request, reason string) {
	s.log.LogAttrs(r.Context(), slog.LevelWarn, "A back-channel logout was refused.",
		slog.String("event", "backchannel.refused"), slog.String("reason", reason))
}
