package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
)

// Restore-before-first-boot — the api surface of design/storage.md §4.5's
// restore, phase 1 (#291).
//
//	GET  /api/restore/candidates   disks beside this controlplane carrying a
//	                               backup set, with their generations
//	POST /api/restore              prepare a restore, then restart onto it
//	GET  /api/backup/restores      the record of restores this cluster came
//	                               back from (authenticated)
//
// # The gate: first-run only
//
// The first two routes are UNAUTHENTICATED, because they have to be: a
// re-flashed controlplane has no users, so there is no session to require.
// What gates them instead is the fact that decides whether a box is at
// first-run at all — whether any operator exists. The moment a passkey is
// registered, both routes answer 409 and stay closed for the life of the
// installation. That is the same posture, on the same window, as the
// first-user registration race iam.md §3.1 accepts: on a fresh box on a
// private LAN, whoever reaches it first is the operator. The restore adds
// nothing to that window and closes with it.
//
// Within the window, what the route can do is bounded by custody: it will
// only unpack an archive whose key the caller supplied, and only a key that
// derives the public key the disk's own marker carries. Somebody who can
// reach a fresh box AND has plugged their own disk into it AND holds its
// custody secret can restore their own cluster's identity onto it — which is
// the operator, doing the thing this exists for.
//
// # The key, in this handler
//
// It arrives base64url in the body, is decoded into one slice, is handed to
// PrepareRestore, and is zeroed in a deferred call on every path out. It is
// not logged, not echoed, not in the report, and the request body is decoded
// with DisallowUnknownFields so nothing else can ride along into anything.

// restoreRequest is the body of POST /api/restore.
type restoreRequest struct {
	PartUUID     string `json:"partUuid"`
	GenerationID string `json:"generationId"`
	KeyID        string `json:"keyId"`
	// PrivateKey is the unwrapped X25519 private key, base64url of 32 bytes.
	// Transits once, over TLS, for this one restore.
	PrivateKey string `json:"privateKey"`
}

// restoreResponse is POST /api/restore's 202.
type restoreResponse struct {
	Report *storage.RestoreReport `json:"report"`
	// Restarting says the api is about to exit so the unit can start it
	// again onto the restored identity. The UI polls /api/auth/status until
	// hasUsers flips true — the restored database has operators.
	Restarting bool   `json:"restarting"`
	Detail     string `json:"detail"`
}

// maxRestoreBody caps the request body: four short strings.
const maxRestoreBody = 8 << 10

// restoreRestartDelay is how long the handler waits after answering before
// asking the process to exit, so the 202 reaches the browser first.
const restoreRestartDelay = 750 * time.Millisecond

// SetRestore wires the first-run restore surface. restart is what the
// handler calls once a restore is prepared — main.go's "shut down and let the
// unit start us again". Leaving cfg nil keeps the routes answering 503.
func (s *Server) SetRestore(cfg *storage.RestoreConfig, restart func()) {
	s.restore = cfg
	s.restoreRestart = restart
}

// firstRunOpen reports whether the restore surface is open: no operator
// exists yet. Any error reading the answer closes the surface.
func (s *Server) firstRunOpen(r *http.Request) (bool, error) {
	if s.setup == nil {
		return false, errors.New("setup service is not wired")
	}
	st, err := s.setup.GetState(r.Context())
	if err != nil {
		return false, err
	}
	return !st.HasUsers, nil
}

const restoreClosed = "restore is offered only before the first operator is registered; this installation already has one. Re-flash the controlplane to restore onto a fresh partition"

// GET /api/restore/candidates
func (s *Server) handleListRestoreCandidates(w http.ResponseWriter, r *http.Request) {
	if s.restore == nil {
		writeError(w, http.StatusServiceUnavailable, "restore is not configured on this api")
		return
	}
	open, err := s.firstRunOpen(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !open {
		writeError(w, http.StatusConflict, restoreClosed)
		return
	}
	resp, err := storage.ListRestoreCandidates(r.Context(), *s.restore)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/restore
func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	if s.restore == nil {
		writeError(w, http.StatusServiceUnavailable, "restore is not configured on this api")
		return
	}
	open, err := s.firstRunOpen(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !open {
		writeError(w, http.StatusConflict, restoreClosed)
		return
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxRestoreBody))
	dec.DisallowUnknownFields()
	var req restoreRequest
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body: "+err.Error())
		return
	}
	// Decoded once, zeroed on every path out of this function. The string
	// form in req cannot be zeroed (Go strings are immutable); it is the one
	// copy this handler cannot scrub, and it is dropped with the request.
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(req.PrivateKey))
	if err != nil {
		writeError(w, http.StatusBadRequest, "privateKey is not unpadded base64url")
		return
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	req.PrivateKey = ""
	if len(key) != 32 {
		writeError(w, http.StatusBadRequest, "privateKey must decode to 32 bytes")
		return
	}

	report, err := storage.PrepareRestore(r.Context(), *s.restore, storage.RestoreRequest{
		PartUUID:     strings.TrimSpace(req.PartUUID),
		GenerationID: strings.TrimSpace(req.GenerationID),
		KeyID:        strings.TrimSpace(req.KeyID),
		PrivateKey:   key,
	})
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrRestoreKeyMismatch):
			writeError(w, http.StatusForbidden, err.Error())
		case errors.Is(err, storage.ErrRestorePending):
			writeError(w, http.StatusConflict, err.Error())
		case errors.Is(err, storage.ErrRestoreArchive):
			writeError(w, http.StatusUnprocessableEntity, err.Error())
		default:
			writeError(w, http.StatusBadGateway, err.Error())
		}
		return
	}
	log.Printf("restore: prepared restore %s from generation %s (key %s, %d identity file(s), %d app volume(s) present and not restored); restarting onto it",
		report.ID, report.GenerationID, report.KeyID, len(report.Restored), len(report.AppVolumesPresent))
	writeJSON(w, http.StatusAccepted, restoreResponse{
		Report:     report,
		Restarting: s.restoreRestart != nil,
		Detail:     "the identity set is staged; the api is restarting to come up on it. Sign in with the passkey you used before once it is back.",
	})
	if s.restoreRestart != nil {
		restart := s.restoreRestart
		go func() {
			time.Sleep(restoreRestartDelay)
			restart()
		}()
	}
}

// GET /api/backup/restores — authenticated: the record of every restore this
// cluster came back from, newest first.
func (s *Server) handleListRestores(w http.ResponseWriter, r *http.Request) {
	if s.backup == nil {
		writeError(w, http.StatusServiceUnavailable, "backups are not configured on this api")
		return
	}
	rows, err := s.backup.ListRestores(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rows == nil {
		rows = []*storage.RestoreReport{}
	}
	writeJSON(w, http.StatusOK, rows)
}
