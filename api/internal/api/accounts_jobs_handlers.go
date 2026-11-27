package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// Every account change (geekdojo/geekdojo-brain#994, Identity 4.12):
// POST /api/accounts/jobs takes {kind, spec, value?}. The service decides
// the request (accounts.Requests): it answers a fresh sign-in's start for
// a change that needs one, and submits nothing then; otherwise it submits
// the job, its value held beside it.

const (
	codeUnknownAccountChange = "unknown_kind"

	msgUnknownAccountChange = "That isn't an account change Rasputin knows."
	msgInvalidAccountChange = "The request must be a JSON object with a kind, a spec the kind takes and, for a kind that takes one, a valid value, and be no larger than 8 KiB."
	msgAccountsNotReady     = "The sign-in service isn't ready, so the change wasn't started. Try again."
)

// AccountRequester decides an account change request (*accounts.Requests).
type AccountRequester interface {
	Request(ctx context.Context, by authz.Submitter, sid string, in accounts.RequestInput) (accounts.Answer, error)
}

// SetAccountRequests installs the account changes, under keycloak only;
// until then POST /api/accounts/jobs answers 503 identity_not_ready.
func (s *Server) SetAccountRequests(rq AccountRequester) { s.accountRequests = rq }

// POST /api/accounts/jobs
// Body: {"kind": "accounts.<kind>", "spec": {...}, "value": "..."}.
// Answers 200 {"next": "/api/auth/signin?action=<kind>"} when the change
// needs a fresh sign-in, else 202 {"job": "<id>"}.
func (s *Server) handleAccountJob(w http.ResponseWriter, r *http.Request) {
	if s.accountRequests == nil {
		s.writeCodedError(w, r, http.StatusServiceUnavailable, codeIdentityNotReady, msgAccountsNotReady, slog.String("cause", "unwired"))
		return
	}
	var req struct {
		Kind  string          `json:"kind"`
		Spec  json.RawMessage `json:"spec"`
		Value *string         `json:"value"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, operatorSecretBodyLimit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.Kind == "" {
		// The decoder's own text can quote the body, which may hold the
		// value, so only a fixed cause is logged.
		cause := bodyCause(err)
		if err == nil {
			cause = "kind_missing"
		}
		s.writeCodedError(w, r, http.StatusBadRequest, codeInvalidRequest, msgInvalidAccountChange, slog.String("cause", cause))
		return
	}
	in := accounts.RequestInput{Kind: req.Kind, Spec: req.Spec}
	if req.Value != nil {
		in.Value, in.HasValue = secret.New([]byte(*req.Value)), true
	}
	p, _ := auth.PrincipalFrom(r.Context())
	ans, err := s.accountRequests.Request(r.Context(), submitter(r), p.Session.SID, in)
	var bad *accounts.InvalidRequest
	switch {
	case err == nil:
	case s.refusedSubmit(w, r, req.Kind, err):
		return
	case errors.Is(err, accounts.ErrUnknownRequest):
		s.writeCodedError(w, r, http.StatusNotFound, codeUnknownAccountChange, msgUnknownAccountChange, slog.String("kind", req.Kind))
		return
	case errors.As(err, &bad):
		s.writeCodedError(w, r, http.StatusBadRequest, codeInvalidRequest, msgInvalidAccountChange,
			slog.String("kind", req.Kind), slog.String("cause", bad.Cause))
		return
	default:
		// The identity error names the account in its path, so only a
		// fixed cause is logged.
		s.writeCodedError(w, r, http.StatusServiceUnavailable, codeIdentityNotReady, msgAccountsNotReady,
			slog.String("kind", req.Kind), slog.String("cause", "submit"))
		return
	}
	if ans.Fresh != nil {
		next, err := s.auth.PrepareAction(w, r, ans.Fresh.Kind, ans.Fresh)
		if err != nil {
			s.writeCodedError(w, r, http.StatusServiceUnavailable, codeIdentityNotReady, msgAccountsNotReady,
				slog.String("kind", req.Kind), slog.String("cause", "no_signin"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"next": next})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job": ans.Job.ID})
}
