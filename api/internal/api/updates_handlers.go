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
	"github.com/geekdojo/rasputin-control-plane/proto"
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
	// trustMode is additive alongside the original bool: "no root CA" means
	// artifacts are REFUSED, not merely unchecked, and those need different
	// words in front of an operator. The third value the field used to carry,
	// "dev-permissive", is gone with the verifier that had a permissive mode.
	resp := struct {
		TrustConfigured bool              `json:"trustConfigured"`
		TrustMode       string            `json:"trustMode"`
		Bundles         []*updater.Bundle `json:"bundles"`
	}{
		TrustConfigured: s.updaterVerifier.TrustConfigured(),
		TrustMode:       s.updaterVerifier.Mode(),
		Bundles:         bs,
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/bundles — multipart/form-data.
//
// An operator uploads the ARTIFACT and the DETACHED SIGNATURE the release
// publishes beside it, which is the pair a node verifies and the pair the
// pipeline emits. The `.raspbundle` JSON envelope this route used to take is
// retired: it wrapped the payload in a format only the api understood, left
// its own manifest unsigned, and needed a verifier of its own — see the type
// doc on updater.Verifier for why each of those was load-bearing.
//
// Parts, and THE ORDER MATTERS:
//
//	signature     the detached CMS `.sig`, MUST come first
//	version       required — the release version this artifact is
//	architecture  required — arm64 | amd64
//	compatible    required — the hardware compat string
//	description   optional — free text
//	artifact      required, LAST — the artifact bytes
//
// The signature is demanded before the artifact for the reason the agent
// fetches it first (agent/internal/updater/openwrt_ab.go): a missing or
// unusable `.sig` refuses the upload either way, and taking it first means the
// refusal costs a kilobyte instead of a gigabyte.
//
//	curl -b cookies.txt -X POST http://localhost:8080/api/bundles \
//	  -F signature=@artifact.sig -F version=2026.09.3 -F architecture=amd64 \
//	  -F compatible=rasputin-n100 -F artifact=@artifact
//
// The declared metadata is the operator's claim about the artifact and is NOT
// a security control — it never was. The retired envelope carried the same
// fields inside a manifest its signature did not cover, so they were
// attacker-chosen in a bundle that verified; now they are operator-chosen in an
// upload the operator authenticated to make. What the signature decides — that
// these bytes were published by the holder of the offline Rasputin root, under
// a leaf issued to sign releases — is checked before the blob is stored.
func (s *Server) handleUploadBundle(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > maxBundleSize {
		writeError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("bundle too large: %d > %d", r.ContentLength, maxBundleSize))
		return
	}
	// Refuse before reading anything if this api cannot verify at all, so an
	// operator on a box with no trust root is told to fix the installation
	// rather than being told their artifact is bad after uploading it.
	if !s.updaterVerifier.Available() {
		writeError(w, http.StatusServiceUnavailable,
			updater.ErrTrustUnavailable.Error()+": "+s.updaterVerifier.UnavailableReason())
		return
	}

	mr, err := r.MultipartReader()
	if err != nil {
		writeError(w, http.StatusBadRequest,
			"this endpoint takes multipart/form-data with a `signature` part, the `version`, "+
				"`architecture` and `compatible` fields, and the `artifact` part last: "+err.Error())
		return
	}

	var (
		sigDER []byte
		meta   bundleMeta
		bundle *updater.Bundle
		seen   bool
	)
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, "read upload: "+err.Error())
			return
		}
		switch part.FormName() {
		case "signature":
			sigDER, err = readDetachedSignature(part)
			_ = part.Close()
			if err != nil {
				writeError(w, http.StatusBadRequest, "signature part: "+err.Error())
				return
			}
		case "version", "architecture", "compatible", "description":
			val, err := io.ReadAll(io.LimitReader(part, maxUploadFieldBytes+1))
			_ = part.Close()
			if err != nil {
				writeError(w, http.StatusBadRequest, "read "+part.FormName()+": "+err.Error())
				return
			}
			if len(val) > maxUploadFieldBytes {
				writeError(w, http.StatusBadRequest, part.FormName()+" is too long")
				return
			}
			switch part.FormName() {
			case "version":
				meta.Version = strings.TrimSpace(string(val))
			case "architecture":
				meta.Architecture = strings.TrimSpace(string(val))
			case "compatible":
				meta.Compatible = strings.TrimSpace(string(val))
			case "description":
				meta.Description = strings.TrimSpace(string(val))
			}
		case "artifact":
			// Everything the verify callback needs must already be in hand:
			// this part is streamed straight to disk and cannot be rewound.
			if msg := missingUploadField(sigDER, meta); msg != "" {
				_ = part.Close()
				writeError(w, http.StatusBadRequest, msg)
				return
			}
			bundle, err = s.ingestSignedArtifact(r.Context(), part, creator(r), sigDER, meta)
			_ = part.Close()
			if err != nil {
				writeError(w, ingestStatus(err), err.Error())
				return
			}
			seen = true
		default:
			_ = part.Close()
			writeError(w, http.StatusBadRequest, "unexpected part "+part.FormName())
			return
		}
	}
	if !seen {
		writeError(w, http.StatusBadRequest, "the upload carried no `artifact` part")
		return
	}
	writeJSON(w, http.StatusCreated, bundle)
}

// maxUploadFieldBytes bounds one metadata form field. Version strings and
// compat strings are tens of bytes; a kilobyte is room to spare and still
// refuses a field used as a smuggling channel.
const maxUploadFieldBytes = 1 << 10

// readDetachedSignature reads a `.sig` part whole, capped. A real one is
// ~1.6 KiB, so it is never streamed.
func readDetachedSignature(r io.Reader) ([]byte, error) {
	der, err := io.ReadAll(io.LimitReader(r, maxSigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(der) == 0 {
		return nil, errors.New("the signature is empty")
	}
	if len(der) > maxSigBytes {
		return nil, fmt.Errorf("the signature exceeds %d bytes", maxSigBytes)
	}
	return der, nil
}

// missingUploadField names the first required part or field the upload did not
// carry, or "" when all are present. One message per fault, naming the field,
// because "bad request" on a six-part form is not actionable.
func missingUploadField(sigDER []byte, meta bundleMeta) string {
	switch {
	case len(sigDER) == 0:
		return "the `signature` part must be sent BEFORE the `artifact` part; " +
			"nothing was received to verify the artifact against"
	case meta.Version == "":
		return "the `version` field is required"
	case meta.Architecture == "":
		return "the `architecture` field is required"
	case meta.Compatible == "":
		return "the `compatible` field is required"
	}
	return ""
}

// ingestSignedArtifact stores the artifact, but only after its detached
// signature verifies against it. The signature is written to a temp sidecar so
// the verifier reads the same pair of files a node will, then moved next to the
// blob once both are known good.
func (s *Server) ingestSignedArtifact(
	ctx context.Context, src io.Reader, uploadedBy string, sigDER []byte, meta bundleMeta,
) (*updater.Bundle, error) {
	var sigTmp string
	verify := func(tmpPath, sha string) (bundleMeta, error) {
		// The verifier reads the signature off disk, as it does on a node, so
		// the uploaded DER gets a file of its own next to the artifact's temp.
		// Named by CreateTemp rather than built from tmpPath: the two are
		// equivalent here, and a path nobody constructs is a path nobody has
		// to reason about.
		f, err := os.CreateTemp(filepath.Dir(tmpPath), "ingest-sig-*.sig")
		if err != nil {
			return bundleMeta{}, fmt.Errorf("stage signature for verification: %w", err)
		}
		sigTmp = f.Name()
		if _, err := f.Write(sigDER); err != nil {
			_ = f.Close()
			return bundleMeta{}, fmt.Errorf("stage signature for verification: %w", err)
		}
		if err := f.Close(); err != nil {
			return bundleMeta{}, fmt.Errorf("stage signature for verification: %w", err)
		}
		res, err := s.updaterVerifier.VerifyArtifact(tmpPath, sigTmp)
		if err != nil {
			return bundleMeta{}, err
		}
		// SignedBy is the verified leaf's CN — attribution that was CHECKED,
		// not a string copied out of the upload.
		out := meta
		out.SignedBy = res.Signer
		return out, nil
	}
	// sigTmp is only known after the callback has run, so the cleanup is
	// deferred once, here, and reads the variable at return time.
	defer func() {
		if sigTmp != "" {
			_ = os.Remove(sigTmp)
		}
	}()

	bundle, created, err := s.ingestBundle(ctx, src, uploadedBy, verify)
	if err != nil {
		return nil, err
	}
	if !created {
		// Bundle content is hash-keyed; an upload of an existing one is a dup.
		return nil, errBundleConflict{sha: bundle.SHA256}
	}
	// The verified signature goes beside the blob, where the agent fetches it
	// from /api/bundles/{sha}/sig and re-verifies it against the root baked
	// into its own image. Failing to place it fails the upload: a bundle whose
	// signature is missing looks ready and refuses at the last step on the node.
	if err := s.writeBundleSignature(bundle.SHA256, sigDER); err != nil {
		_ = s.updater.DeleteBundle(ctx, bundle.SHA256)
		_ = os.Remove(bundle.StoragePath)
		return nil, fmt.Errorf("stage signature beside the bundle: %w", err)
	}
	return bundle, nil
}

// errBundleConflict is a duplicate upload — the same bytes are already stored.
type errBundleConflict struct{ sha string }

func (e errBundleConflict) Error() string { return "bundle already exists: " + e.sha }

// bundleMeta is the metadata persisted for an ingested bundle, returned by an
// ingest verify callback.
type bundleMeta struct {
	Version, Compatible, Architecture, Description, BuildDate, SignedBy string
}

// errBundleVerify wraps a verify-callback rejection so ingestStatus can map it
// to 400 (bad bundle) rather than 500 (server fault).
type errBundleVerify struct{ err error }

func (e errBundleVerify) Error() string { return e.err.Error() }

// Unwrap so errors.Is reaches the wrapped cause — ingestStatus needs to tell
// updater.ErrTrustUnavailable apart from a bad signature.
func (e errBundleVerify) Unwrap() error { return e.err }

func ingestStatus(err error) int {
	// "this api cannot verify anything" is an installation fault, not a bad
	// upload. 400 would tell the operator to fix their bundle; the bundle is
	// fine and the trust root is missing.
	if errors.Is(err, updater.ErrTrustUnavailable) {
		return http.StatusServiceUnavailable
	}
	var dup errBundleConflict
	if errors.As(err, &dup) {
		return http.StatusConflict
	}
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

// bundleSigPath is where a bundle's detached CMS signature lives: beside the
// content-addressed blob, with `.sig` appended. Deliberately NOT a database
// column — the signature is derived from the release and belongs to the blob,
// so a sibling file means no schema migration and no way for the row and the
// bytes to disagree.
func (s *Server) bundleSigPath(sha string) string {
	return filepath.Join(s.bundleDir, sha+".sig")
}

// maxSigBytes bounds a detached signature. A real one is ~1.6 KiB.
const maxSigBytes = 1 << 20

// stageBundleSignature downloads the detached CMS signature for an already
// staged bundle and writes it beside the blob.
//
// ⚠️ The api does NOT verify the signature it stages, and that is the design
// rather than a gap. In this threat model the control plane is not the trusted
// party — the whole reason #154 exists is that a compromised api could serve
// anything it liked to the node that terminates the WAN. A check performed here
// would be a check performed by the very component the gate is defending
// against. Verification belongs on the device, against the root baked read-only
// into its own image, and that is where it now happens.
func (s *Server) stageBundleSignature(ctx context.Context, sigURL, sha string) error {
	rc, err := s.releaseSource.Open(ctx, sigURL)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer rc.Close()
	der, err := io.ReadAll(io.LimitReader(rc, maxSigBytes+1))
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if len(der) == 0 {
		return errors.New("signature asset is empty")
	}
	if len(der) > maxSigBytes {
		return fmt.Errorf("signature asset exceeds %d bytes", maxSigBytes)
	}
	return s.writeBundleSignature(sha, der)
}

// writeBundleSignature puts a detached signature beside its content-addressed
// blob, atomically. Shared by the pull path and the operator upload so the two
// cannot drift on where a `.sig` lands or on how it gets there.
//
// Write-then-rename: a half-written `.sig` beside a complete blob would fail
// verification on the node and read exactly like tampering.
func (s *Server) writeBundleSignature(sha string, der []byte) error {
	tmp, err := os.CreateTemp(s.bundleDir, "sig-*.tmp")
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after a successful rename
	if _, err := tmp.Write(der); err != nil {
		_ = tmp.Close() // the write already failed; the deferred Remove is the cleanup
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close tmp: %w", err)
	}
	return os.Rename(tmp.Name(), s.bundleSigPath(sha))
}

// GET /api/bundles/{sha}/sig — the detached CMS signature for a bundle. Agents
// fetch this before the artifact itself, so a node pointed at a control plane
// with nothing staged fails in a kilobyte rather than after half a gigabyte.
//
// Unauthenticated, like the blob endpoint beside it, and for a stronger reason:
// these exact bytes are published on the public GitHub release. Withholding
// them would protect nothing and would break the documented manual verification
// path.
func (s *Server) handleGetBundleSig(w http.ResponseWriter, r *http.Request) {
	sha := r.PathValue("sha")
	if !looksLikeSHA256(sha) {
		writeError(w, http.StatusBadRequest, "invalid sha")
		return
	}
	f, err := os.Open(s.bundleSigPath(sha))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// 404 is load-bearing: the agent turns exactly this into
			// "re-pull the release so the .sig is staged with it".
			writeError(w, http.StatusNotFound, "no signature staged for this bundle; re-pull the release")
			return
		}
		writeError(w, http.StatusInternalServerError, "open signature: "+err.Error())
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/pkcs7-signature")
	http.ServeContent(w, r, sha+".sig", time.Time{}, f)
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
	// No extension: the store holds whatever the release publishes — a RAUC
	// `.raucb`, the firewall's bare `.rootfs`, whatever comes next — and the
	// row records none of them. This said `.raspbundle` for every pulled
	// `.raucb` too, which was a filename that described nothing on disk.
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="rasputin-%s-%s"`, b.Version, b.Architecture))
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
	// The detached signature goes with its blob; an orphan .sig would be
	// re-served for a future bundle only if a sha collided, but it would also
	// quietly grow the store forever.
	if err := os.Remove(s.bundleSigPath(sha)); err != nil && !errors.Is(err, os.ErrNotExist) {
		// Same posture as the blob above: best-effort.
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/updates/system
// Body: { "version": "...", "component"?: "os"|"fw", "excludeNodes": ["..."] }
//
//	or: { "bundleSha256": "...", "excludeNodes": ["..."] }
//
// Kicks off a system.update saga that cascades node.update children in a safe
// role-ordered sequence (firewall last). The api's own self-node id
// (RASPUTIN_SELF_NODE_ID) is always excluded.
//
// The VERSION form is what "UPDATE ALL" means: the plan resolves the correct
// per-arch bundle for each node, so a mixed arm64/amd64 cluster updates
// completely rather than updating one arch and bucketing the other under
// `skipped` (ADR-0005 Decision 11). The bundleSha256 form remains for a
// targeted run against one specific artifact.
func (s *Server) handleCreateSystemUpdate(w http.ResponseWriter, r *http.Request) {
	var req proto.SystemUpdateSpec
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if (req.Version == "") == (req.BundleSHA256 == "") {
		writeError(w, http.StatusBadRequest, "exactly one of version or bundleSha256 is required")
		return
	}
	if req.Component != "" {
		if _, ok := releases.ComponentByID(req.Component); !ok {
			writeError(w, http.StatusBadRequest, "unknown component: "+req.Component)
			return
		}
	}
	if req.MaxInFlight != nil {
		if err := req.MaxInFlight.Validate(); err != nil {
			writeError(w, http.StatusBadRequest, "maxInFlight "+err.Error())
			return
		}
	}
	if req.MaxFailures != nil {
		if err := req.MaxFailures.Validate(); err != nil {
			writeError(w, http.StatusBadRequest, "maxFailures "+err.Error())
			return
		}
	}
	if req.CanarySoakSeconds < 0 || req.CanarySoakSeconds > proto.MaxCanarySoakSeconds {
		writeError(w, http.StatusBadRequest, fmt.Sprintf(
			"canarySoakSeconds must be between 0 and %d", proto.MaxCanarySoakSeconds))
		return
	}
	// The rest of the canary rules — is it a target, is it the controlplane,
	// two overrides for one tier — need the plan and are enforced there, where
	// the failure is a job that never touches a node rather than a 400 that
	// duplicates the planner's knowledge of the fleet.
	spec, _ := json.Marshal(req)
	j, err := s.runner.Submit(r.Context(), "system.update", spec, creator(r))
	if err != nil {
		writeSubmitError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusAccepted, j)
}

// POST /api/updates/system/plan
// Same body as POST /api/updates/system, but read-only: it resolves and returns
// the plan the cascade WOULD run (ordered targets, per-arch canary picks,
// reasoned skips) without submitting a job. Powers the pre-flight UI (#95) so
// the operator sees which node carries the canary risk — and can override it or
// the knobs — before committing to the rollout.
func (s *Server) handleSystemUpdatePlan(w http.ResponseWriter, r *http.Request) {
	var req proto.SystemUpdateSpec
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if (req.Version == "") == (req.BundleSHA256 == "") {
		writeError(w, http.StatusBadRequest, "exactly one of version or bundleSha256 is required")
		return
	}
	plan, err := updater.PreviewPlan(r.Context(), s.updater, s.inv, req, updater.SystemUpdateConfig{SelfNodeID: s.selfNodeID})
	if err != nil {
		// A plan resolution error (e.g. an arch not staged) is the operator's
		// to see and fix, not a server fault — 400, with the message.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, plan)
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
	// Validate the target node before starting a saga: the bundle's `compatible`
	// SKU must match what this node expects, or it'll be rejected at install
	// (RAUC's compatible check on the OS; the firewall accepts only its own
	// image). The firewall now updates through the SAME node.update saga as the
	// OS nodes — only the on-agent backend differs (openwrt-ab vs rauc) — so the
	// old "firewall can't be updated here" guard is gone; it just needs the
	// firewall bundle, never an OS bundle (and vice-versa).
	//   - Firewall node  → wants rasputin-fw-n100.
	//   - OS node        → wants ArchCompatible(arch) (amd64/arm64 SKU).
	// Only enforced when we can resolve the expectation — ArchCompatible now
	// answers false for an arch it cannot resolve, empty included, so the
	// separate `!= ""` guard that used to be needed here is gone. This is a
	// single-node deploy the operator asked for explicitly, so an unresolvable
	// arch stays permissive and the on-node compatible check is the backstop;
	// the fleet plan, which nobody aimed at a particular node, skips instead.
	if n, err := s.inv.Get(r.Context(), req.NodeID); err == nil && n != nil {
		var want string
		var known bool
		if n.Role == proto.RoleFirewall {
			want, known = releases.FirewallCompatible, true
		} else {
			want, known = releases.ArchCompatible(n.Architecture)
		}
		if known {
			if b, err := s.updater.GetBundle(r.Context(), req.BundleSHA256); err == nil && b != nil && b.Compatible != want {
				writeError(w, http.StatusBadRequest, fmt.Sprintf(
					"bundle is %s but node %s (%s) needs %s — pick the %s image",
					b.Compatible, req.NodeID, n.Role, want, want))
				return
			}
		}
	}
	spec, _ := json.Marshal(req)
	j, err := s.runner.Submit(r.Context(), "node.update", spec, creator(r))
	if err != nil {
		writeSubmitError(w, http.StatusBadRequest, err)
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

	// Annotate what the local bundle store already holds, PER ARTIFACT. A
	// release is one artifact per arch, so asking only about the component's
	// nominal SKU answered a different question than the one the UI was
	// showing: "the amd64 bundle is here" rendered as "staged" on a cluster
	// with three Pis that had nothing to deploy.
	for i := range result.Components {
		c := &result.Components[i]
		for j := range c.Artifacts {
			a := &c.Artifacts[j]
			if a.BundleSHA256 == "" {
				continue
			}
			if existing, _ := s.updater.GetBundle(r.Context(), a.BundleSHA256); existing != nil {
				a.Staged = true
			}
		}
		c.Staged = componentFullyStaged(c)
	}
	writeJSON(w, http.StatusOK, result)
}

// componentFullyStaged reports whether every artifact this cluster actually
// needs is in the local bundle store. Artifacts no node needs are ignored —
// an all-N100 cluster is fully staged without ever pulling the Pi bundle —
// and a component with no needed artifacts at all falls back to the nominal
// bundle so a fleet that has not reported arch yet still gets a badge.
func componentFullyStaged(c *releases.ComponentStatus) bool {
	needed, staged := 0, 0
	for _, a := range c.Artifacts {
		if a.NeededBy == 0 {
			continue
		}
		needed++
		if a.Staged {
			staged++
		}
	}
	if needed > 0 {
		return staged == needed
	}
	for _, a := range c.Artifacts {
		if a.BundleSHA256 == c.BundleSHA256 {
			return a.Staged
		}
	}
	return false
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
	if !comp.Deployable {
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
	// Stage EVERY deployable artifact in the manifest — one per arch — so a
	// mixed-arch cluster (N100 amd64 + Raspberry Pi arm64) has a bundle for
	// every node. This previously pulled only comp.Compatible (the amd64 SKU),
	// which left arm64 nodes with nothing to deploy and the OTA silently stuck.
	// The deployable asset per artifact is kind-specific (RAUC .raucb vs the
	// firewall's rootfs squashfs) — OTAAsset resolves it.
	var arts []*releases.ManifestArtifact
	for i := range info.Manifest.Artifacts {
		a := &info.Manifest.Artifacts[i]
		if _, _, _, ok := a.OTAAsset(comp.Kind); ok {
			arts = append(arts, a)
		}
	}
	if len(arts) == 0 {
		writeError(w, http.StatusBadGateway, "release "+info.Version+" has no deployable artifact")
		return
	}

	// Every artifact is attempted, and a failure on one does not abandon the
	// others. Fail-fast here left the store holding whichever arches happened
	// to download before the error, with a single error string as the only
	// signal — so a half-staged release looked exactly like a failed one, and
	// re-running the pull was the only way to find out which. The outcome per
	// arch is reported instead, and a partial pull answers 207 so the UI can
	// say WHICH arch is missing.
	res := pullResult{Component: comp.ID, Version: info.Version, Channel: channel}
	var primary *updater.Bundle
	anyCreated := false
	worstStatus := 0
	for _, art := range arts {
		assetName, assetSHA, _, _ := art.OTAAsset(comp.Kind)
		outcome := pullArtifactResult{
			Architecture: art.Architecture, Compatible: art.Compatible, AssetName: assetName,
		}
		fail := func(status int, msg string) {
			outcome.Error = msg
			res.Failed = append(res.Failed, outcome)
			if status > worstStatus {
				worstStatus = status
			}
		}

		url, ok := info.AssetURL(assetName)
		if !ok {
			fail(http.StatusBadGateway, "release "+info.Version+" has no asset "+assetName)
			continue
		}
		rc, err := s.releaseSource.Open(r.Context(), url)
		if err != nil {
			fail(http.StatusBadGateway, "download bundle: "+err.Error())
			continue
		}
		wantSHA := strings.ToLower(assetSHA)
		verify := func(tmpPath, sha string) (bundleMeta, error) {
			if sha != wantSHA {
				return bundleMeta{}, fmt.Errorf("sha256 mismatch: downloaded %s, manifest says %s", sha, wantSHA)
			}
			// Version, compat, arch and signer come from the SIGNED release
			// manifest, and the sha compare above pins these bytes to it. The
			// artifact itself is re-verified where it is installed: RAUC checks
			// the OS bundle's embedded signature against the same baked root,
			// and the firewall verifies the detached `.sig` staged below. The
			// api deliberately does not stand in for either — see
			// stageBundleSignature for why a check here would be performed by
			// the component the gate defends against.
			return bundleMeta{
				Version: info.Version, Compatible: art.Compatible, Architecture: art.Architecture,
				BuildDate: art.BuildDate, SignedBy: art.SignedBy,
				Description: "pulled from " + channel + " channel",
			}, nil
		}
		bundle, created, err := s.ingestBundle(r.Context(), rc, "update-check", verify)
		rc.Close()
		if err != nil {
			fail(ingestStatus(err), err.Error())
			continue
		}
		if created {
			anyCreated = true
		}
		// Stage the detached signature beside the blob. This runs on EVERY
		// pull, not only when the bundle was newly created, so that re-pulling
		// a release backfills the signature for a bundle staged before the api
		// knew to fetch one — which is the migration path for anything already
		// sitting in the store.
		//
		// A firewall artifact without its signature is not deployable (the node
		// fails the update closed), so failing to stage it fails the ARTIFACT.
		// Reporting it as staged would hand the operator a bundle that looks
		// ready and refuses at the last step.
		if sigName, detached := art.OTASigAsset(comp.Kind); detached {
			if sigName == "" {
				fail(http.StatusBadGateway, "release "+info.Version+" publishes no detached signature for "+
					assetName+"; refusing to stage an artifact that cannot be verified on the node")
				continue
			}
			sigURL, ok := info.AssetURL(sigName)
			if !ok {
				fail(http.StatusBadGateway, "release "+info.Version+" has no asset "+sigName)
				continue
			}
			if err := s.stageBundleSignature(r.Context(), sigURL, bundle.SHA256); err != nil {
				fail(http.StatusBadGateway, "stage signature "+sigName+": "+err.Error())
				continue
			}
			outcome.SigAssetName = sigName
		}
		outcome.SHA256, outcome.Created = bundle.SHA256, created
		res.Staged = append(res.Staged, outcome)
		// Bundle is the artifact matching the component's nominal compat; the
		// rest land in the catalog the UI re-lists. Fall back to the first
		// staged bundle.
		if primary == nil || art.Compatible == comp.Compatible {
			primary = bundle
		}
	}
	res.Bundle = primary

	switch {
	case len(res.Staged) == 0:
		// Nothing landed — an ordinary failure, reported with the per-artifact
		// detail rather than only the first error encountered.
		if worstStatus == 0 {
			worstStatus = http.StatusBadGateway
		}
		writeJSON(w, worstStatus, res)
	case len(res.Failed) > 0:
		// THE CASE THIS EXISTS FOR: some arches staged, some did not. Neither
		// a success nor a failure, and it must not be reported as either.
		writeJSON(w, http.StatusMultiStatus, res)
	case anyCreated:
		writeJSON(w, http.StatusCreated, res)
	default:
		writeJSON(w, http.StatusOK, res)
	}
}

// pullArtifactResult is one architecture's outcome from a pull. Named per
// arch rather than per asset because arch is what an operator reasons about
// ("the Pi bundle didn't come down"), and it is what the fleet plan keys on.
type pullArtifactResult struct {
	Architecture string `json:"architecture"`
	Compatible   string `json:"compatible"`
	AssetName    string `json:"assetName"`
	// SigAssetName names the detached signature staged with this artifact.
	// Empty for kinds that carry their signature inside the bundle.
	SigAssetName string `json:"sigAssetName,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	// Created distinguishes a fresh download from an idempotent re-pull.
	Created bool   `json:"created,omitempty"`
	Error   string `json:"error,omitempty"`
}

// pullResult is the reply from POST /api/updates/pull. Staged and Failed
// together always cover every deployable artifact in the release, so the
// caller can tell a complete pull from a partial one without re-checking.
type pullResult struct {
	Component string               `json:"component"`
	Version   string               `json:"version"`
	Channel   string               `json:"channel"`
	Staged    []pullArtifactResult `json:"staged"`
	Failed    []pullArtifactResult `json:"failed,omitempty"`
	// Bundle is the artifact matching the component's nominal SKU, for
	// callers that want a single bundle to deploy from.
	Bundle *updater.Bundle `json:"bundle,omitempty"`
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
