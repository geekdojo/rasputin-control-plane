package api

import (
	"context"
	"log/slog"
	"net/http"
)

// How many people are waiting for access (geekdojo/geekdojo-brain#990): the
// count the home door's sign-up cap reads, for an administrator. The
// Accounts page's copy that shows it is Identity 6.2's.

const (
	codeWaitingUnavailable = "waiting_unavailable"
	msgWaitingUnavailable  = "Rasputin can't count the people waiting for access right now. Try again."
	msgWaitingNotReady     = "The sign-in service isn't set up, so Rasputin can't count the people waiting for access."
)

// WaitingCounter counts the accounts waiting for access (*accounts.Waiting).
type WaitingCounter interface {
	Count(ctx context.Context) (int, error)
}

// SetWaiting installs the count, under keycloak only; until then the route
// answers 503 identity_not_ready.
func (s *Server) SetWaiting(w WaitingCounter) { s.waiting = w }

// GET /api/accounts/waiting — {"waiting": N}.
func (s *Server) handleWaiting(w http.ResponseWriter, r *http.Request) {
	if s.waiting == nil {
		s.writeCodedError(w, r, http.StatusServiceUnavailable, codeIdentityNotReady, msgWaitingNotReady, slog.String("cause", "unwired"))
		return
	}
	n, err := s.waiting.Count(r.Context())
	if err != nil {
		// The identity error names accounts in its path, so only a fixed
		// cause is logged.
		s.writeCodedError(w, r, http.StatusInternalServerError, codeWaitingUnavailable, msgWaitingUnavailable, slog.String("cause", "count"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"waiting": n})
}
