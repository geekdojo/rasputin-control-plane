package api

import (
	"context"
	"encoding/json"
	"fmt"
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
// Every candidate the agent reported is passed through unchanged, plus the
// api-minted fields: `eligible` / `ineligibleReason` and `wipeToken`. See
// backupCandidate.
//
// A node that cannot hold a target at all (storage.CanHoldTarget — today,
// anything but the controlplane; geekdojo-brain#397) is answered WITHOUT
// asking its agent: 200, `nodeEligible:false` with the reason, and an empty
// list. The rule is consulted before the RPC, not after, because a node that
// cannot hold a target may have no storage backend at all — a compute node
// registers no storage.enumerate responder, and asking it was a NATS
// no-responders error surfacing as a 502 (e3bench 2026-09-08). Listing that
// node's disks anyway is not on offer: nothing on it answers the verb. Should
// a node that cannot hold a target ever answer — a storage-role node with a
// backend, once the ingest can reach a remote mount (§4.1) — that is the
// moment CanHoldTarget widens and the list comes back with it. #302's disk
// claiming is not that moment: it formats and mounts disks, and the ingest is
// what blocks a target off the controlplane.
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
	node, err := s.lookupNode(r.Context(), nodeID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if node == nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("node %s is not registered", nodeID))
		return
	}
	if nodeOK, nodeReason := storage.CanHoldTarget(node, proto.StoragePurposeBackup); !nodeOK {
		writeJSON(w, http.StatusOK, backupCandidatesResponse{
			OK:                   true,
			NodeEligible:         false,
			NodeIneligibleReason: nodeReason,
			Candidates:           []backupCandidate{},
			Ts:                   time.Now().UTC(),
		})
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
		OK:           ack.OK,
		Backend:      ack.Backend,
		Ts:           ack.Ts,
		NodeEligible: true,
		Candidates:   make([]backupCandidate, 0, len(ack.Candidates)),
	}
	for i := range ack.Candidates {
		c := ack.Candidates[i]
		bc := backupCandidate{StorageCandidate: c}
		switch {
		case c.Protected:
			bc.IneligibleReason = c.ProtectedReason
			if bc.IneligibleReason == "" {
				bc.IneligibleReason = "holds the currently-mounted boot or persistent partitions"
			}
		default:
			bc.Eligible = true
			// A wipe token is minted ONLY for a disk that could actually be
			// claimed: a token for a disk on a node that cannot hold a target
			// would be a confirmation for a destruction nothing can follow.
			bc.WipeToken = storage.CandidateWipeToken(&c)
		}
		out.Candidates = append(out.Candidates, bc)
	}
	writeJSON(w, http.StatusOK, out)
}

// lookupNode reads one node from inventory. An api with no inventory wired
// cannot decide whether a node may hold a target, and says so rather than
// guessing in either direction.
func (s *Server) lookupNode(ctx context.Context, nodeID string) (*proto.Node, error) {
	if s.inv == nil {
		return nil, fmt.Errorf("this api is not wired to the node inventory, so it cannot tell whether %s can hold a backup target", nodeID)
	}
	node, err := s.inv.Get(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("inventory: %w", err)
	}
	return node, nil
}

// backupCandidate is one candidate as the PICKER sees it: everything the agent
// reported, verbatim, plus the api-minted wipe confirmation token.
//
// The embedded struct is flattened by encoding/json, so the wire shape is the
// agent's StorageCandidate with one extra field — existing readers are
// unaffected.
type backupCandidate struct {
	proto.StorageCandidate
	// Eligible says whether THIS disk can be claimed as the target right now,
	// and IneligibleReason says why not when it cannot — one vocabulary for
	// every cause. A protected boot medium is ineligible with its
	// protectedReason; every disk on a node that cannot hold a target
	// (storage.CanHoldTarget, #397) is ineligible with the node's reason.
	// `protected` still travels beside them, so a UI can label the boot
	// medium specifically while disabling on `eligible` alone.
	Eligible         bool   `json:"eligible"`
	IneligibleReason string `json:"ineligibleReason,omitempty"`
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
	OK      bool   `json:"ok"`
	Backend string `json:"backend"`
	// NodeEligible / NodeIneligibleReason answer for the NODE, once, so a
	// picker can say "nothing on this node can be a target" above the list.
	// When NodeEligible is false the list IS empty: the node's agent was not
	// asked (see handleListBackupCandidates), and Backend is blank for the
	// same reason.
	NodeEligible         bool              `json:"nodeEligible"`
	NodeIneligibleReason string            `json:"nodeIneligibleReason,omitempty"`
	Candidates           []backupCandidate `json:"candidates"`
	Ts                   time.Time         `json:"ts"`
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
	out := make([]backupTargetRow, 0, len(rows))
	for _, row := range rows {
		tr := backupTargetRow{BackupTarget: row}
		// A row on a node that cannot hold a target is an operator who hit
		// #397's dead end before the picker refused it. The row is NOT
		// altered or released — it may name the only copy of an archive —
		// but it is told, in the same words the run's refusal uses, so the
		// Storage page and the failed run tell one story.
		if node, err := s.lookupNode(r.Context(), row.NodeID); err == nil && node != nil {
			if ok, reason := storage.CanHoldTarget(node, proto.StoragePurposeBackup); !ok {
				tr.NodeIneligibleReason = reason
			}
		}
		out = append(out, tr)
	}
	writeJSON(w, http.StatusOK, out)
}

// backupTargetRow is one ledger row as the Storage page sees it: the row
// verbatim, plus the api's answer to whether its node can hold a target.
// The embedded pointer is flattened by encoding/json, so the wire shape is
// BackupTarget with one optional field — existing readers are unaffected.
type backupTargetRow struct {
	*storage.BackupTarget
	// NodeIneligibleReason is present only when the row's node cannot hold
	// a backup target (storage.CanHoldTarget); absent otherwise.
	NodeIneligibleReason string `json:"nodeIneligibleReason,omitempty"`
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
	// A disk on a node that cannot hold a target is refused HERE, with the
	// same sentence the picker attached to it, before any job exists (#397).
	// Step 1 refuses identically if a spec reaches it some other way; an
	// unregistered node is left for step 1 to name, as before.
	if node, err := s.lookupNode(r.Context(), spec.NodeID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if node != nil {
		if ok, reason := storage.CanHoldTarget(node, proto.StoragePurposeBackup); !ok {
			writeError(w, http.StatusConflict, reason)
			return
		}
	}
	j, err := s.runner.Submit(r.Context(), storage.ClaimJobKind, body, creator(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, j)
}
