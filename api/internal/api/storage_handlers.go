package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
)

// Backup-target endpoints — the api surface of design/storage.md §4.8.
//
// Three routes, and the split between them is deliberate:
//
//	GET  /api/backup/candidates   read-only agent RPC, no job
//	GET  /api/backup/targets      the ledger
//	POST /api/backup/targets      submits the backup.target.claim saga
//
// The picker MUST be able to list disks before any job exists — an operator
// cannot choose from a list only a running job could produce — so enumeration
// is a plain RPC from a handler (the precedent is handleBMCProbe). The saga
// enumerates AGAIN at step 2, and that duplication is the point: the picker's
// answer is what the operator confirmed, step 2's is what is true at format
// time, and comparing the two is what closes the window between them.

// GET /api/backup/candidates?nodeId=<id>
//
// Lists every whole disk on a node, protected ones included. Read-only: it
// mutates nothing here or on the agent.
//
// Protected candidates are RETURNED rather than filtered out, on purpose. The
// operator who plugged in one disk and sees two should be told which one is the
// boot medium and why, not handed a list with a silent hole in it.
func (s *Server) handleListBackupCandidates(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.URL.Query().Get("nodeId"))
	if nodeID == "" {
		// Default to the node hosting the api. On an appliance that is where
		// the backup disk almost always is, and it saves the picker a lookup
		// it would only get from another endpoint.
		nodeID = s.selfNodeID
	}
	if nodeID == "" {
		writeError(w, http.StatusBadRequest, "nodeId is required (this api has no self node id to fall back on)")
		return
	}
	ack, err := storage.Enumerate(r.Context(), s.nc, nodeID)
	if err != nil {
		// A refusal is the agent answering, not the api failing — but from
		// HTTP's side both are "the upstream could not give me a list".
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ack)
}

// GET /api/backup/targets
//
// Every claim attempt, newest first — including the failed ones, which is the
// point of keeping them: "the claim you started an hour ago was refused because
// that disk holds the boot partition" is the most useful thing this view says.
//
// Wrapped §4.6 key blobs are not in the response. They are ciphertext, not
// plaintext, but nothing here needs them to render a target, and the narrowest
// surface that works is the right one for anything key-shaped.
func (s *Server) handleListBackupTargets(w http.ResponseWriter, r *http.Request) {
	if s.backup == nil {
		writeError(w, http.StatusServiceUnavailable, "backup targets are not configured on this api")
		return
	}
	rows, err := s.backup.ListTargets(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rows == nil {
		rows = []*storage.BackupTarget{}
	}
	writeJSON(w, http.StatusOK, rows)
}

// claimTargetRequest is the body of POST /api/backup/targets.
//
// A typed request rather than a spec forwarded verbatim, and decoded with
// DisallowUnknownFields. Both halves matter for §4.6: the job spec is persisted
// into the jobs ledger and rendered in the Tasks view, so anything a caller can
// smuggle into it is published. A body carrying a plaintext `dataKey` is
// REFUSED here rather than quietly stored — and there is no field on the spec
// this handler builds that could hold one.
type claimTargetRequest struct {
	NodeID      string `json:"nodeId"`
	DevicePath  string `json:"devicePath"`
	Fingerprint string `json:"fingerprint"`
	Label       string `json:"label,omitempty"`
	Replace     bool   `json:"replace,omitempty"`
	Adopt       bool   `json:"adopt,omitempty"`
	// ArchiveKey carries the ALREADY-WRAPPED §4.6 data key. The key is minted
	// where the passphrase and the recovery code exist — the browser — and the
	// api never sees it in the clear.
	ArchiveKey *storage.ArchiveKey `json:"archiveKey,omitempty"`
}

// maxClaimBody caps the request body. The wrapped blobs are small; a megabyte
// is four orders of magnitude of headroom and still refuses a stream.
const maxClaimBody = 1 << 20

// POST /api/backup/targets
//
// Submits the backup.target.claim saga and returns the job. THIS IS THE CALL
// THAT CAN FORMAT A DISK — every refusal §4.8 defines is evaluated inside the
// saga, in order, before the one destructive step runs.
func (s *Server) handleClaimBackupTarget(w http.ResponseWriter, r *http.Request) {
	if s.backup == nil {
		writeError(w, http.StatusServiceUnavailable, "backup targets are not configured on this api")
		return
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxClaimBody))
	dec.DisallowUnknownFields()
	var req claimTargetRequest
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body: "+err.Error())
		return
	}
	spec := storage.ClaimSpec{
		NodeID:      strings.TrimSpace(req.NodeID),
		DevicePath:  strings.TrimSpace(req.DevicePath),
		Fingerprint: strings.TrimSpace(req.Fingerprint),
		Label:       strings.TrimSpace(req.Label),
		Replace:     req.Replace,
		Adopt:       req.Adopt,
		ArchiveKey:  req.ArchiveKey,
	}
	body, err := json.Marshal(spec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Validated here as well as in step 1 so an operator gets a 400 with the
	// reason instead of a job that exists only to fail.
	if _, err := storage.ParseClaimSpec(body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	j, err := s.runner.Submit(r.Context(), storage.ClaimJobKind, body, creator(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, j)
}
