package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/updater"
)

// maxBundleSize is the upper bound the api accepts for a single bundle
// upload. 1 GiB is generous; RAUC bundles for Rasputin are 200-600 MB.
const maxBundleSize = 1 << 30

// GET /api/bundles
func (s *Server) handleListBundles(w http.ResponseWriter, r *http.Request) {
	bs, err := s.updater.ListBundles(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if bs == nil {
		bs = []*updater.Bundle{}
	}
	resp := struct {
		TrustConfigured bool               `json:"trustConfigured"`
		Bundles         []*updater.Bundle  `json:"bundles"`
	}{
		TrustConfigured: s.updaterVerifier.TrustConfigured(),
		Bundles:         bs,
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/bundles
// Body: raw bundle bytes. The api parses the manifest, verifies the
// signature, and stores the file at <bundleDir>/<sha256>. Returns the
// Bundle row.
//
// We accept the bundle as the request body directly (not multipart) so
// curl uploads are trivial: `curl --data-binary @bundle.raspbundle ...`.
func (s *Server) handleUploadBundle(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > maxBundleSize {
		writeError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("bundle too large: %d > %d", r.ContentLength, maxBundleSize))
		return
	}
	tmpDir := filepath.Join(s.bundleDir, ".tmp")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, "create tmp dir: "+err.Error())
		return
	}
	tmp, err := os.CreateTemp(tmpDir, "upload-*.bin")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "create tmp: "+err.Error())
		return
	}
	tmpPath := tmp.Name()
	defer func() {
		// Cleanup on early return; rename below makes this a no-op on success.
		_ = os.Remove(tmpPath)
	}()

	h := sha256.New()
	mw := io.MultiWriter(tmp, h)
	limited := io.LimitReader(r.Body, maxBundleSize+1)
	n, err := io.Copy(mw, limited)
	if err != nil {
		tmp.Close()
		writeError(w, http.StatusInternalServerError, "write tmp: "+err.Error())
		return
	}
	if err := tmp.Close(); err != nil {
		writeError(w, http.StatusInternalServerError, "close tmp: "+err.Error())
		return
	}
	if n > maxBundleSize {
		writeError(w, http.StatusRequestEntityTooLarge, "bundle exceeded size limit")
		return
	}
	shaHex := hex.EncodeToString(h.Sum(nil))

	// Refuse duplicate uploads — bundle content is hash-keyed.
	if existing, _ := s.updater.GetBundle(r.Context(), shaHex); existing != nil {
		writeError(w, http.StatusConflict, "bundle already exists: "+shaHex)
		return
	}

	// Verify signature + parse manifest.
	manifest, _, err := s.updaterVerifier.VerifyFile(tmpPath)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bundle verification failed: "+err.Error())
		return
	}

	// Move to final location.
	finalPath := filepath.Join(s.bundleDir, shaHex)
	if err := os.Rename(tmpPath, finalPath); err != nil {
		writeError(w, http.StatusInternalServerError, "rename: "+err.Error())
		return
	}

	bundle := &updater.Bundle{
		SHA256:       shaHex,
		Version:      manifest.Version,
		Compatible:   manifest.Compatible,
		Architecture: manifest.Architecture,
		Description:  manifest.Description,
		BuildDate:    manifest.BuildDate,
		SizeBytes:    n,
		SignedBy:     manifest.SignedBy,
		StoragePath:  finalPath,
		UploadedAt:   time.Now().UTC(),
		UploadedBy:   creator(r),
	}
	if err := s.updater.CreateBundle(r.Context(), bundle); err != nil {
		// Don't orphan the file.
		_ = os.Remove(finalPath)
		writeError(w, http.StatusInternalServerError, "persist bundle: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, bundle)
}

// GET /api/bundles/{sha} — agents fetch the binary here. JSON listings are
// at /api/bundles.
func (s *Server) handleGetBundle(w http.ResponseWriter, r *http.Request) {
	sha := r.PathValue("sha")
	if !looksLikeSHA256(sha) {
		writeError(w, http.StatusBadRequest, "invalid sha")
		return
	}
	b, err := s.updater.GetBundle(r.Context(), sha)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if b == nil {
		writeError(w, http.StatusNotFound, "bundle not found")
		return
	}
	f, err := os.Open(b.StoragePath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "open bundle: "+err.Error())
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", b.SizeBytes))
	w.Header().Set("X-Bundle-Version", b.Version)
	w.Header().Set("X-Bundle-Architecture", b.Architecture)
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="rasputin-%s-%s.raspbundle"`, b.Version, b.Architecture))
	http.ServeContent(w, r, b.SHA256, b.UploadedAt, f)
}

// DELETE /api/bundles/{sha}
func (s *Server) handleDeleteBundle(w http.ResponseWriter, r *http.Request) {
	sha := r.PathValue("sha")
	b, err := s.updater.GetBundle(r.Context(), sha)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if b == nil {
		writeError(w, http.StatusNotFound, "bundle not found")
		return
	}
	if err := s.updater.DeleteBundle(r.Context(), sha); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := os.Remove(b.StoragePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		// Bundle row already gone — log but don't fail.
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/updates/system
// Body: { "bundleSha256": "...", "excludeNodes": ["..."] }
// Kicks off a system.update saga that cascades node.update children in a
// safe role-ordered sequence (firewall last). The api's own self-node id
// (RASPUTIN_SELF_NODE_ID) is always excluded.
func (s *Server) handleCreateSystemUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BundleSHA256 string   `json:"bundleSha256"`
		ExcludeNodes []string `json:"excludeNodes,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.BundleSHA256 == "" {
		writeError(w, http.StatusBadRequest, "bundleSha256 is required")
		return
	}
	spec, _ := json.Marshal(req)
	j, err := s.runner.Submit(r.Context(), "system.update", spec, creator(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, j)
}

// POST /api/updates
// Body: { "nodeId": "...", "bundleSha256": "..." }
func (s *Server) handleCreateUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeID       string `json:"nodeId"`
		BundleSHA256 string `json:"bundleSha256"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.NodeID == "" || req.BundleSHA256 == "" {
		writeError(w, http.StatusBadRequest, "nodeId and bundleSha256 are required")
		return
	}
	spec, _ := json.Marshal(req)
	j, err := s.runner.Submit(r.Context(), "node.update", spec, creator(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, j)
}

// GET /api/updates?nodeId=<id>&limit=50 — list update history. Filtered
// by nodeId if given.
func (s *Server) handleListUpdates(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("nodeId")
	limit := atoiOr(r.URL.Query().Get("limit"), 50)
	rows, err := s.updater.ListNodeUpdates(r.Context(), nodeID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rows == nil {
		rows = []*updater.NodeUpdate{}
	}
	writeJSON(w, http.StatusOK, rows)
}

// looksLikeSHA256 reports whether s is exactly 64 lowercase hex chars.
func looksLikeSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range strings.ToLower(s) {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
