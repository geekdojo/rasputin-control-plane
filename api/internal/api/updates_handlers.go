package api

import (
	"context"
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

	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
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
		TrustConfigured bool              `json:"trustConfigured"`
		Bundles         []*updater.Bundle `json:"bundles"`
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
	// Upload verifies the bundle's own signature + parses its manifest (the
	// same gate for any operator-supplied bundle).
	verify := func(tmpPath, sha string) (bundleMeta, error) {
		man, _, err := s.updaterVerifier.VerifyFile(tmpPath)
		if err != nil {
			return bundleMeta{}, err
		}
		return bundleMeta{
			Version: man.Version, Compatible: man.Compatible, Architecture: man.Architecture,
			Description: man.Description, BuildDate: man.BuildDate, SignedBy: man.SignedBy,
		}, nil
	}
	bundle, created, err := s.ingestBundle(r.Context(), r.Body, creator(r), verify)
	if err != nil {
		writeError(w, ingestStatus(err), err.Error())
		return
	}
	if !created {
		// Bundle content is hash-keyed; an upload of an existing one is a dup.
		writeError(w, http.StatusConflict, "bundle already exists: "+bundle.SHA256)
		return
	}
	writeJSON(w, http.StatusCreated, bundle)
}

// bundleMeta is the metadata persisted for an ingested bundle, returned by an
// ingest verify callback.
type bundleMeta struct {
	Version, Compatible, Architecture, Description, BuildDate, SignedBy string
}

// errBundleVerify wraps a verify-callback rejection so ingestStatus can map it
// to 400 (bad bundle) rather than 500 (server fault).
type errBundleVerify struct{ err error }

func (e errBundleVerify) Error() string { return e.err.Error() }

func ingestStatus(err error) int {
	var ve errBundleVerify
	if errors.As(err, &ve) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

// ingestBundle streams src into the bundle store, computing its sha256. The
// verify callback is invoked with the temp path + computed sha BEFORE the file
// is moved into place; it returns the metadata to persist, or an error (wrapped
// as errBundleVerify) to reject the bundle. If a bundle with the same sha
// already exists, ingestBundle returns it with created=false and does not
// re-write or re-verify (idempotent — both upload and pull rely on this).
//
// Shared by handleUploadBundle (operator upload) and handlePullUpdate (pull
// from the public release channel).
func (s *Server) ingestBundle(
	ctx context.Context,
	src io.Reader,
	uploadedBy string,
	verify func(tmpPath, sha string) (bundleMeta, error),
) (b *updater.Bundle, created bool, err error) {
	tmpDir := filepath.Join(s.bundleDir, ".tmp")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return nil, false, fmt.Errorf("create tmp dir: %w", err)
	}
	tmp, err := os.CreateTemp(tmpDir, "ingest-*.bin")
	if err != nil {
		return nil, false, fmt.Errorf("create tmp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op after a successful rename

	h := sha256.New()
	limited := io.LimitReader(src, maxBundleSize+1)
	n, copyErr := io.Copy(io.MultiWriter(tmp, h), limited)
	if copyErr != nil {
		tmp.Close()
		return nil, false, fmt.Errorf("write tmp: %w", copyErr)
	}
	if err := tmp.Close(); err != nil {
		return nil, false, fmt.Errorf("close tmp: %w", err)
	}
	if n > maxBundleSize {
		return nil, false, errBundleVerify{errors.New("bundle exceeded size limit")}
	}
	shaHex := hex.EncodeToString(h.Sum(nil))

	if existing, _ := s.updater.GetBundle(ctx, shaHex); existing != nil {
		return existing, false, nil
	}

	meta, err := verify(tmpPath, shaHex)
	if err != nil {
		return nil, false, errBundleVerify{err}
	}

	finalPath := filepath.Join(s.bundleDir, shaHex)
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return nil, false, fmt.Errorf("rename: %w", err)
	}
	bundle := &updater.Bundle{
		SHA256:       shaHex,
		Version:      meta.Version,
		Compatible:   meta.Compatible,
		Architecture: meta.Architecture,
		Description:  meta.Description,
		BuildDate:    meta.BuildDate,
		SizeBytes:    n,
		SignedBy:     meta.SignedBy,
		StoragePath:  finalPath,
		UploadedAt:   time.Now().UTC(),
		UploadedBy:   uploadedBy,
	}
	if err := s.updater.CreateBundle(ctx, bundle); err != nil {
		_ = os.Remove(finalPath) // don't orphan the file
		return nil, false, fmt.Errorf("persist bundle: %w", err)
	}
	return bundle, true, nil
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

// POST /api/updates/check
// Body (optional): { "channel": "stable" | "dev" }
// Asks the public release channel for the latest version of every component
// and compares against the versions reported by inventory. Returns a
// per-component report (up to date / update available / unknown). No bytes are
// downloaded — only the small release manifests are fetched.
func (s *Server) handleCheckUpdates(w http.ResponseWriter, r *http.Request) {
	if s.releaseSource == nil {
		writeError(w, http.StatusServiceUnavailable, "update channel not configured on this control plane")
		return
	}
	var req struct {
		Channel string `json:"channel,omitempty"`
	}
	// Body is optional; ignore decode errors on an empty body.
	_ = json.NewDecoder(r.Body).Decode(&req)
	channel := req.Channel
	if channel == "" {
		channel = s.releaseChannel
	}

	nodes, err := s.inv.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list nodes: "+err.Error())
		return
	}
	result := releases.Check(r.Context(), s.releaseSource, channel, nodes)

	// Annotate deployable components already staged in the local bundle store
	// so the UI can show "staged" instead of a redundant download button.
	for i := range result.Components {
		c := &result.Components[i]
		if c.BundleSHA256 == "" {
			continue
		}
		if existing, _ := s.updater.GetBundle(r.Context(), c.BundleSHA256); existing != nil {
			c.Staged = true
		}
	}
	writeJSON(w, http.StatusOK, result)
}

// POST /api/updates/pull
// Body: { "component": "os", "channel"?: "stable" | "dev" }
// Downloads the latest deployable bundle for the component from the public
// channel into the local bundle store (verifying the manifest sha256, and the
// signature for mock bundles), so the existing Deploy / Update-all flow can
// distribute it. Only RAUC components are pullable; the firewall is
// display-only. Idempotent: returns 200 with the existing bundle if already
// staged, 201 when freshly pulled.
func (s *Server) handlePullUpdate(w http.ResponseWriter, r *http.Request) {
	if s.releaseSource == nil {
		writeError(w, http.StatusServiceUnavailable, "update channel not configured on this control plane")
		return
	}
	var req struct {
		Component string `json:"component"`
		Channel   string `json:"channel,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	comp, ok := releases.ComponentByID(req.Component)
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown component: "+req.Component)
		return
	}
	if !comp.Deployable || comp.Kind != releases.KindRAUC {
		writeError(w, http.StatusBadRequest, comp.Label+" cannot be pulled (no automated update path)")
		return
	}
	channel := req.Channel
	if channel == "" {
		channel = s.releaseChannel
	}

	info, err := s.releaseSource.LatestFor(r.Context(), comp, channel)
	if err != nil {
		writeError(w, http.StatusBadGateway, "fetch release: "+err.Error())
		return
	}
	if info == nil {
		writeError(w, http.StatusNotFound, "no release for "+comp.ID+" on channel "+channel)
		return
	}
	art, ok := info.Artifact(comp.Compatible)
	if !ok || art.Raucb == "" || art.SHA256 == "" {
		writeError(w, http.StatusBadGateway, "release "+info.Version+" has no deployable artifact for "+comp.Compatible)
		return
	}
	url, ok := info.AssetURL(art.Raucb)
	if !ok {
		writeError(w, http.StatusBadGateway, "release "+info.Version+" has no asset "+art.Raucb)
		return
	}

	rc, err := s.releaseSource.Open(r.Context(), url)
	if err != nil {
		writeError(w, http.StatusBadGateway, "download bundle: "+err.Error())
		return
	}
	defer rc.Close()

	wantSHA := strings.ToLower(art.SHA256)
	verify := func(tmpPath, sha string) (bundleMeta, error) {
		if sha != wantSHA {
			return bundleMeta{}, fmt.Errorf("sha256 mismatch: downloaded %s, manifest says %s", sha, wantSHA)
		}
		meta := bundleMeta{
			Version: info.Version, Compatible: art.Compatible, Architecture: art.Architecture,
			BuildDate: art.BuildDate, SignedBy: art.SignedBy,
			Description: "pulled from " + channel + " channel",
		}
		// Mock bundles (dev/CI) get the full host-side signature gate. Real
		// .raucb bundles are sha-pinned by the signed manifest here and the
		// signature is re-verified by RAUC at install time on the target node
		// (the authoritative gate) — host-side .raucb verify needs the rauc
		// CLI and lands with the real-RAUC-backend work (see updates.md).
		if strings.HasSuffix(art.Raucb, ".raspbundle") {
			man, _, err := s.updaterVerifier.VerifyFile(tmpPath)
			if err != nil {
				return bundleMeta{}, err
			}
			meta.Version, meta.Compatible, meta.Architecture = man.Version, man.Compatible, man.Architecture
			meta.SignedBy, meta.BuildDate = man.SignedBy, man.BuildDate
		}
		return meta, nil
	}

	bundle, created, err := s.ingestBundle(r.Context(), rc, "update-check", verify)
	if err != nil {
		writeError(w, ingestStatus(err), err.Error())
		return
	}
	status := http.StatusCreated
	if !created {
		status = http.StatusOK
	}
	writeJSON(w, status, bundle)
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
