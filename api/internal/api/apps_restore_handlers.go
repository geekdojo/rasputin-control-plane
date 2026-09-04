package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Restoring one app's data from a backup generation — the api surface of
// design/storage.md §4.5's restore, phase 2 (geekdojo-brain#291).
//
//	GET  /api/apps/{id}/restore-sources   the generations that hold this
//	                                      app's volumes, with the disk's
//	                                      wrapped key for the browser to open
//	POST /api/apps/{id}/restore           start the restore: custody checked
//	                                      here, then a backup.restore_app job
//	GET  /api/backup/egress/{gen}/{member}
//	                                      the plaintext stream a node fetches
//	                                      on its restore credential
//
// # The key, in this handler
//
// It arrives base64url in the body, is decoded into one slice, is checked
// against the disk's marker BEFORE anything else happens (a wrong secret is
// a 403 with no job in the ledger and nothing stopped), is copied into a
// restore session the saga resolves by id, and is zeroed in a deferred call
// on every path out. It is not logged, not echoed, not in the job spec, and
// the request body is decoded with DisallowUnknownFields so nothing else
// can ride along into the spec.
//
// # The egress route
//
// Deliberately NOT behind the session middleware: its caller is a node's
// agent, and its authentication is the per-member restore credential the
// saga minted. A credential can GET one named member of the one generation
// a restore has open, unsealed, and nothing else. 503 until main wires an
// endpoint, like every other backup route without one.

// appRestoreRequest is the body of POST /api/apps/{id}/restore.
type appRestoreRequest struct {
	PartUUID     string `json:"partUuid"`
	GenerationID string `json:"generationId"`
	KeyID        string `json:"keyId"`
	// PrivateKey is the unwrapped X25519 private key, base64url of 32 bytes.
	// Transits once, over TLS, for this one restore.
	PrivateKey string `json:"privateKey"`
	// Volumes, when set, restricts the restore to these tile volume names.
	Volumes []string `json:"volumes,omitempty"`
}

// appRestoreResponse is POST /api/apps/{id}/restore's 202.
type appRestoreResponse struct {
	Job    *jobs.Job `json:"job"`
	Detail string    `json:"detail"`
}

// maxAppRestoreBody caps the request body: four short strings and a list of
// volume names.
const maxAppRestoreBody = 16 << 10

// SetAppRestore wires the app-volume restore surface: the saga's config
// (for the listing and the custody check) and the egress endpoint. Leaving
// either nil keeps its routes at 503.
func (s *Server) SetAppRestore(cfg *storage.RestoreAppConfig, egress *storage.RestoreEgress) {
	s.appRestore = cfg
	s.restoreEgress = egress
}

// GET /api/apps/{id}/restore-sources
func (s *Server) handleAppRestoreSources(w http.ResponseWriter, r *http.Request) {
	if s.appRestore == nil {
		writeError(w, http.StatusServiceUnavailable, "app-volume restore is not configured on this api")
		return
	}
	app, err := s.apps.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if app == nil {
		writeError(w, http.StatusNotFound, "app not found: a restore puts data into an existing install and never creates one — install the app first")
		return
	}
	out, err := storage.ListAppRestoreSources(r.Context(), *s.appRestore, app)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /api/apps/{id}/restore
func (s *Server) handleAppRestore(w http.ResponseWriter, r *http.Request) {
	if s.appRestore == nil || s.appRestore.Sessions == nil {
		writeError(w, http.StatusServiceUnavailable, "app-volume restore is not configured on this api")
		return
	}
	app, err := s.apps.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if app == nil {
		writeError(w, http.StatusNotFound, "app not found: a restore puts data into an existing install and never creates one — install the app first")
		return
	}
	// The cheap refusals before the body is even read: nothing to stop, and
	// nothing to say a secret for.
	node := strings.TrimSpace(app.TargetNode)
	if node == "" {
		writeError(w, http.StatusConflict, "app "+app.Name+" is not deployed to any node, so there is no agent to put its data back; deploy it first")
		return
	}
	if n, err := s.inv.Get(r.Context(), node); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if n == nil || inventory.ComputeStatus(n.LastSeen) != proto.StatusOnline {
		writeError(w, http.StatusConflict, "node "+node+", which hosts "+app.Name+", is OFFLINE; the restore is refused, not queued — bring the node back and start it again")
		return
	}
	if s.backup != nil {
		running, err := s.backup.ListRunning(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if len(running) > 0 {
			writeError(w, http.StatusConflict, "a backup is running (job "+running[0].JobID+"); a restore reads the target that run is writing to. Wait for it to finish")
			return
		}
	}

	dec := json.NewDecoder(io.LimitReader(r.Body, maxAppRestoreBody))
	dec.DisallowUnknownFields()
	var req appRestoreRequest
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body: "+err.Error())
		return
	}
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
	partUUID, genID, keyID := strings.TrimSpace(req.PartUUID), strings.TrimSpace(req.GenerationID), strings.TrimSpace(req.KeyID)
	if !proto.BackupValidGenerationID(genID) {
		writeError(w, http.StatusBadRequest, "generationId is not a generation id")
		return
	}
	// Custody, against the disk, before a job exists. A wrong key is a 403
	// and nothing in the ledger; the saga checks again with the lent copy.
	if _, _, err := storage.CheckRestoreCustody(r.Context(), *s.appRestore, partUUID, keyID, key); err != nil {
		switch {
		case errors.Is(err, storage.ErrRestoreKeyMismatch):
			writeError(w, http.StatusForbidden, err.Error())
		case errors.Is(err, storage.ErrRestoreArchive):
			writeError(w, http.StatusUnprocessableEntity, err.Error())
		default:
			writeError(w, http.StatusBadGateway, err.Error())
		}
		return
	}
	sessionID, err := s.appRestore.Sessions.Open(key)
	if err != nil {
		if errors.Is(err, storage.ErrRestoreActive) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	spec, err := json.Marshal(storage.RestoreAppSpec{
		AppID: app.ID, PartUUID: partUUID, GenerationID: genID, KeyID: keyID, SessionID: sessionID, Volumes: req.Volumes,
	})
	if err != nil {
		s.appRestore.Sessions.Close(sessionID)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	j, err := s.runner.Submit(r.Context(), storage.RestoreAppJobKind, spec, creator(r))
	if err != nil {
		s.appRestore.Sessions.Close(sessionID)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.appRestore.Sessions.Bind(sessionID, j.ID); err != nil {
		// The job is queued and will refuse at step 1 for want of a bound
		// session; the key is dropped here.
		s.appRestore.Sessions.Close(sessionID)
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	// Nothing request-derived in this line: the job id is minted by the api.
	// The app, the node and the generation are in the job's spec and its
	// first step's log lines, where they are rendered quoted.
	log.Printf("restore: an app-volume restore from a backup generation was submitted as job %s", j.ID)
	writeJSON(w, http.StatusAccepted, appRestoreResponse{
		Job:    j,
		Detail: "the restore is running as a job; the app is stopped while each volume is swapped and the previous contents are kept beside it on " + node,
	})
}

// GET /api/backup/egress/{generation}/{member} — the restore stream. The
// whole handler lives in storage beside Unseal.
func (s *Server) handleRestoreEgress(w http.ResponseWriter, r *http.Request) {
	if s.restoreEgress == nil {
		writeError(w, http.StatusServiceUnavailable, "app-volume restore is not configured on this api")
		return
	}
	s.restoreEgress.ServeHTTP(w, r)
}
