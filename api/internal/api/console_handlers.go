package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/api/internal/console"
)

// Console root password (geekdojo/geekdojo-brain#587, decision #558).
//
// The operator sets it in the first-run wizard and changes it from Settings;
// a console.root_push job applies it to every node in inventory over that
// node's own lane. Nothing here ever returns the hash — the read shape
// carries the password's id and each node's outcome, and that is all it can
// carry (see api/internal/console).

// SetConsole wires the console root password store. nil leaves the routes
// at 503, the same shape as the other optional subsystems.
func (s *Server) SetConsole(st *console.Store) { s.console = st }

// consoleSetRequest is the body of PUT /api/console/root-password.
type consoleSetRequest struct {
	Password string `json:"password"`
	// Push, default true, submits the console.root_push job for the whole
	// fleet once the password is stored. Set it false to store without
	// pushing (the wizard's "I'll do this when the nodes are up" path).
	Push *bool `json:"push,omitempty"`
}

// consoleSetResponse reports what was stored and the job that is applying
// it. No hash, by construction.
type consoleSetResponse struct {
	HashID string `json:"hashId"`
	JobID  string `json:"jobId,omitempty"`
	// PushError is set when the password was stored but the job that
	// applies it could not be submitted. The password IS saved — the UI
	// says so and offers the Settings action rather than asking the
	// operator to retype it.
	PushError string `json:"pushError,omitempty"`
}

func (s *Server) consoleStore(w http.ResponseWriter) (*console.Store, bool) {
	if s.console == nil {
		writeError(w, http.StatusServiceUnavailable, "the console root password is not configured on this api")
		return nil, false
	}
	return s.console, true
}

// GET /api/console/root-password
// Response: { "set": true, "hashId": "…", "setAt": "…", "nodes": [ … ] }
func (s *Server) handleGetConsoleRootPassword(w http.ResponseWriter, r *http.Request) {
	st, ok := s.consoleStore(w)
	if !ok {
		return
	}
	status, err := st.Status(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// PUT /api/console/root-password
// Body: { "password": "…" }. Stores the HASH of it (the plaintext is never
// persisted) and, unless "push": false, submits the job that applies it to
// every node. 400 on a password the console could not take.
func (s *Server) handlePutConsoleRootPassword(w http.ResponseWriter, r *http.Request) {
	st, ok := s.consoleStore(w)
	if !ok {
		return
	}
	// A password must not end up in a URL or a log, so it arrives in a body
	// and nothing here echoes it. The body is capped: hashing cost grows
	// with the square of the password length.
	var req consoleSetRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	hashID, err := st.SetPassword(r.Context(), req.Password)
	if err != nil {
		if isConsolePasswordRefusal(err) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := consoleSetResponse{HashID: hashID}
	if req.Push == nil || *req.Push {
		j, jerr := s.submitConsolePush(r, console.PushSpec{Reason: "the console root password was set"})
		if jerr != nil {
			// The password IS stored; only the fan-out did not start.
			resp.PushError = jerr.Error()
		} else {
			resp.JobID = j
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/console/root-password/push
// Re-applies the stored password to every node. Re-runnable; this is the
// Settings action. 409 when no password has been set.
func (s *Server) handlePushConsoleRootPassword(w http.ResponseWriter, r *http.Request) {
	st, ok := s.consoleStore(w)
	if !ok {
		return
	}
	hashID, err := st.CurrentHashID(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if hashID == "" {
		writeError(w, http.StatusConflict, console.ErrNoPassword.Error())
		return
	}
	var req struct {
		NodeIDs []string `json:"nodeIds,omitempty"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req)
	}
	j, err := s.submitConsolePush(r, console.PushSpec{NodeIDs: req.NodeIDs, Reason: "requested from Settings"})
	if err != nil {
		writeSubmitError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusAccepted, consoleSetResponse{HashID: hashID, JobID: j})
}

func (s *Server) submitConsolePush(r *http.Request, spec console.PushSpec) (string, error) {
	raw, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	j, err := s.runner.Submit(r.Context(), console.PushKind, raw, creator(r))
	if err != nil {
		return "", err
	}
	return j.ID, nil
}

// isConsolePasswordRefusal reports whether err is the operator's fault (a
// password the console could not take) rather than the api's.
func isConsolePasswordRefusal(err error) bool {
	for _, e := range []error{
		console.ErrPasswordTooShort, console.ErrPasswordTooLong,
		console.ErrPasswordCharacters, console.ErrPasswordNotUTF8,
	} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}
