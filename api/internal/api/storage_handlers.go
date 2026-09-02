package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/proto"
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
//
// Every candidate the agent reported is passed through unchanged, plus one
// api-minted field: `wipeToken`. See backupCandidate.
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
	out := backupCandidatesResponse{
		OK:         ack.OK,
		Backend:    ack.Backend,
		Ts:         ack.Ts,
		Candidates: make([]backupCandidate, 0, len(ack.Candidates)),
	}
	for i := range ack.Candidates {
		c := ack.Candidates[i]
		out.Candidates = append(out.Candidates, backupCandidate{
			StorageCandidate: c,
			WipeToken:        storage.CandidateWipeToken(&c),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// backupCandidate is one candidate as the PICKER sees it: everything the agent
// reported, verbatim, plus the api-minted wipe confirmation token.
//
// The embedded struct is flattened by encoding/json, so the wire shape is the
// agent's StorageCandidate with one extra field — existing readers are
// unaffected.
type backupCandidate struct {
	proto.StorageCandidate
	// WipeToken is the confirmation a caller must echo back in
	// `wipe.token` to claim this disk by DESTROYING the Rasputin backup set it
	// carries (design/storage.md §4.8's "or wiped only on a second, separate
	// choice"). Present ONLY on a candidate that is genuinely eligible for that:
	// never on a protected disk, never on one carrying no backup set.
	//
	// Its absence is the answer, not an omission — a UI has nothing to put in
	// the field, so it has no wipe control to render. The token binds to this
	// disk in this state and is re-derived from live hardware inside the saga,
	// so a stale one is refused rather than applied to a disk nobody looked at.
	WipeToken string `json:"wipeToken,omitempty"`
}

// backupCandidatesResponse mirrors proto.StorageEnumerateAck field for field,
// with the decorated candidate list. A distinct type rather than a mutated ack
// because `wipeToken` is the API's, not the agent's: the agent never mints one
// and there is no field on the wire type that could carry it.
type backupCandidatesResponse struct {
	OK         bool              `json:"ok"`
	Backend    string            `json:"backend"`
	Candidates []backupCandidate `json:"candidates"`
	Ts         time.Time         `json:"ts"`
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
// smuggle into it is published. A body carrying a `privateKey` (or the
// symmetric era's `dataKey`) is REFUSED here rather than quietly stored — and
// there is no field on the spec this handler builds that could hold one. The
// public key IS a declared field, in clear, which is §4.6's amendment of
// 2026-09-02 rather than an exception to this rule.
type claimTargetRequest struct {
	NodeID      string `json:"nodeId"`
	DevicePath  string `json:"devicePath"`
	Fingerprint string `json:"fingerprint"`
	Label       string `json:"label,omitempty"`
	Replace     bool   `json:"replace,omitempty"`
	Adopt       bool   `json:"adopt,omitempty"`
	// Wipe is §4.8's second, separate choice: destroy the Rasputin backup set
	// the chosen disk already carries and claim it fresh. Mutually exclusive
	// with Adopt, and reachable only by echoing back the `wipeToken` that
	// GET /api/backup/candidates published for THIS disk — see
	// storage.WipeConfirmation. Its absence is a refusal, never a default.
	Wipe *storage.WipeConfirmation `json:"wipe,omitempty"`
	// ArchiveKey carries §4.6's keypair: the public half in clear and the
	// private half already wrapped. The keypair is minted where the passphrase
	// and the recovery code exist — the browser — and the api never sees the
	// private half at all.
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
//
// A disk that already carries a Rasputin backup set is refused by default. The
// two ways past that refusal are `adopt` (keep the set) and `wipe` (destroy it,
// and only with the token from GET /api/backup/candidates). Neither is a
// default, and setting both is refused rather than resolved.
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
	if req.Wipe != nil {
		// Rebuilt rather than forwarded, like every other field here: a wipe
		// carries exactly one thing into the job ledger, and it is the token.
		spec.Wipe = &storage.WipeConfirmation{Token: strings.TrimSpace(req.Wipe.Token)}
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
