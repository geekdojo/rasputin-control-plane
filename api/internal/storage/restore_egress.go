package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/backupxfer/fsat"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// RestoreEgress is the restore-stream endpoint: GET one member of the
// generation an app restore has open, UNSEALED as it streams, on a restore
// credential. The read side of backupxfer's ingest, and the ONE place a
// sealed volume member is ever opened — which is why it lives here, beside
// Unseal, and not in backupxfer (an agent imports backupxfer; this must
// never run there).
//
// # What it serves, and to whom
//
// A member the saga's step 1 PLANNED, of the generation it ARMED, for the
// job the session is bound to, on a credential minted for exactly that
// member, that node and that job — and nothing else. The credential's
// signature is checked before its content is read; its Use must be
// restore (an upload credential is refused here as a restore one is at the
// ingest); its scope must match the path; its job must own an armed
// session; the member must be one the plan names. Before a byte is
// streamed the sealed file is hashed and compared with the manifest's
// sealedSha256 — a member edited on the platter is refused without the key
// being spent on it. Then the file is unsealed onto the response, chunk by
// authenticated chunk. An unseal failure part-way cannot change the status
// already sent; the connection is aborted, the node sees a cut stream, its
// count and digest refuse it, and the live volume is untouched.
//
// # What the response carries
//
// The plaintext tar, and in headers the manifest's plaintext digest and
// length so the node can check the command and the source agree. The
// credential is never logged — the grant's nonce is.
//
// # One entry
//
// ServeNode is the only entry, on the node listener, for a request the api
// authenticated by the presenting node's registered agent key.
// backupxfer.CheckPresenter decides between the credential and the node that
// presents it — the same rule as the ingest.
type RestoreEgress struct {
	auth     *backupxfer.Authority
	sessions *RestoreSessions
	sem      chan struct{}
	log      *slog.Logger
}

// NewRestoreEgress builds the endpoint over the SAME authority the ingest
// endpoint verifies against, so one key signs both kinds of credential and
// each endpoint refuses the other's by Use. logger is the process logger every
// record goes through; a nil one is a wiring fault and panics here, at
// construction.
func NewRestoreEgress(auth *backupxfer.Authority, sessions *RestoreSessions, logger *slog.Logger) *RestoreEgress {
	if logger == nil {
		panic("storage: NewRestoreEgress needs a logger; nil was passed")
	}
	return &RestoreEgress{auth: auth, sessions: sessions, sem: make(chan struct{}, 1), log: logger}
}

// Mint issues a restore credential for one member of an armed session's
// generation, as a secret.Value the caller destroys (ADR-0009). Refused for a
// job with no armed session or a member the plan does not name — an endpoint
// must not hand out credentials it would refuse. A refusal returns the zero
// Value.
func (e *RestoreEgress) Mint(g backupxfer.Grant, ttl time.Duration) (secret.Value, error) {
	if e == nil || e.auth == nil || e.sessions == nil {
		return secret.Value{}, errors.New("restore egress is not configured")
	}
	if !g.ForRestore() {
		return secret.Value{}, errors.New("the restore endpoint mints restore credentials only")
	}
	if ok, why := e.sessions.MemberPlanned(g.JobID, g.Generation, g.Member, g.NodeID); !ok {
		return secret.Value{}, errors.New(why)
	}
	cred, err := e.auth.Mint(g, ttl)
	if err != nil {
		return secret.Value{}, err
	}
	return secret.New([]byte(cred)), nil
}

// ServeNode streams one member on the node listener. keyOwner is the node
// whose registered agent key the caller authenticated the request with; the
// credential must have been issued to that node. An empty owner is a wiring
// fault in the caller and is refused before a slot is taken: fail closed.
func (e *RestoreEgress) ServeNode(w http.ResponseWriter, r *http.Request, keyOwner string) {
	if strings.TrimSpace(keyOwner) == "" {
		e.log.ErrorContext(r.Context(), "restore egress: the node listener passed no key owner; refusing (an api wiring fault)",
			"code", backupxfer.CodeCredentialInvalid)
		egressRefuse(w, http.StatusInternalServerError, backupxfer.CodeCredentialInvalid, "the api could not tell which node presented this request")
		return
	}
	e.serve(w, r, keyOwner)
}

// serve streams one member for whoever presented it.
func (e *RestoreEgress) serve(w http.ResponseWriter, r *http.Request, keyOwner string) {
	if !fsat.Supported {
		egressRefuse(w, http.StatusNotImplemented, backupxfer.CodeUnsupported, "this build cannot serve restores on this operating system")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		egressRefuse(w, http.StatusMethodNotAllowed, backupxfer.CodeMemberInvalid, "members are GET")
		return
	}
	generation, member, ok := backupxfer.SplitEgressPath(r.URL.Path)
	if !ok {
		egressRefuse(w, http.StatusBadRequest, backupxfer.CodeMemberInvalid, "the path is not <generation>/volumes/<app>/<volume>.rasputin-archive")
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || strings.TrimSpace(token) == "" {
		egressRefuse(w, http.StatusUnauthorized, backupxfer.CodeCredentialInvalid, "no restore credential")
		return
	}
	grant, err := e.auth.Verify(token)
	switch {
	case errors.Is(err, backupxfer.ErrCredentialExpired):
		egressRefuse(w, http.StatusUnauthorized, backupxfer.CodeCredentialExpired, "the restore credential has expired; the restore mints a fresh one per volume")
		return
	case err != nil:
		egressRefuse(w, http.StatusUnauthorized, backupxfer.CodeCredentialInvalid, "the restore credential does not verify")
		return
	}
	if !grant.ForRestore() {
		backupxfer.LogGrant(r.Context(), e.log, slog.LevelWarn, "restore egress: an upload credential was presented to the restore endpoint; refused", grant, keyOwner, "code", backupxfer.CodeCredentialScope)
		egressRefuse(w, http.StatusForbidden, backupxfer.CodeCredentialScope, "that is an upload credential; the restore endpoint takes restore credentials only")
		return
	}
	// Who presents it, before what it is for (the ingest's order).
	if p := backupxfer.CheckPresenter(grant, keyOwner); p != nil {
		backupxfer.LogGrant(r.Context(), e.log, slog.LevelWarn, "restore egress: the credential is not this presenter's to use; refused", grant, keyOwner, "code", p.Code)
		egressRefuse(w, p.Status, p.Code, p.Detail)
		return
	}
	if grant.Generation != generation || grant.Member != member {
		backupxfer.LogGrant(r.Context(), e.log, slog.LevelWarn, "restore egress: the credential is scoped to a different member; refused", grant, keyOwner, "code", backupxfer.CodeCredentialScope,
			"requested_generation", generation, "requested_member", member)
		egressRefuse(w, http.StatusForbidden, backupxfer.CodeCredentialScope, "the credential is scoped to a different member")
		return
	}
	// One locked read answers "is there an armed restore for this job,
	// reading this generation, that plans this member" and hands back a
	// COPY of the key that outlives a session closing mid-stream. Zeroed
	// when this handler returns, whatever happened.
	s, ok := e.sessions.Lookup(grant.JobID, generation, member)
	if !ok {
		egressRefuse(w, http.StatusConflict, backupxfer.CodeNoRestore, "no restore has that generation open with that member in its plan")
		return
	}
	defer s.Release()
	facts := s

	// One stream at a time: the target may be spinning media, and the
	// restore is serial anyway.
	select {
	case e.sem <- struct{}{}:
	case <-r.Context().Done():
		return
	}
	defer func() { <-e.sem }()

	root, err := fsat.OpenRoot(s.MountPath)
	if err != nil {
		egressRefuse(w, http.StatusInternalServerError, backupxfer.CodeReadFailed, err.Error())
		return
	}
	defer func() { _ = root.Close() }()
	gen, err := openGenerationDir(root, generation)
	if err != nil {
		egressRefuse(w, http.StatusNotFound, backupxfer.CodeMemberMissing, "the generation is not on the target: "+err.Error())
		return
	}
	defer func() { _ = gen.Close() }()
	parts := strings.Split(member, "/") // validated: volumes/<app>/<file>
	vols, err := fsat.OpenDir(gen, parts[0])
	if err != nil {
		egressRefuse(w, http.StatusNotFound, backupxfer.CodeMemberMissing, "the generation holds no volumes directory")
		return
	}
	defer func() { _ = vols.Close() }()
	appDir, err := fsat.OpenDir(vols, parts[1])
	if err != nil {
		egressRefuse(w, http.StatusNotFound, backupxfer.CodeMemberMissing, "the generation holds no member for that app")
		return
	}
	defer func() { _ = appDir.Close() }()
	f, err := fsat.OpenFile(appDir, parts[2])
	if err != nil {
		egressRefuse(w, http.StatusNotFound, backupxfer.CodeMemberMissing, "the generation holds no such member")
		return
	}
	defer func() { _ = f.Close() }()

	// The sealed digest first, over the whole file, before the key is spent
	// on it: what the manifest recorded is what must be on the platter.
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		egressRefuse(w, http.StatusInternalServerError, backupxfer.CodeReadFailed, err.Error())
		return
	}
	got := hex.EncodeToString(h.Sum(nil))
	if facts.SealedSHA256 != "" && (!strings.EqualFold(got, facts.SealedSHA256) || (facts.SealedBytes != 0 && byteCount(n) != facts.SealedBytes)) {
		// Not bad input: the stored backup is not the one the manifest
		// vouches for, so this restore cannot complete from it.
		backupxfer.LogGrant(r.Context(), e.log, slog.LevelError, "restore egress: the member on the target does not match its manifest; refused", grant, keyOwner, "code", backupxfer.CodeDigestMismatch,
			"target_sha256", proto.ShortFingerprint(got), "target_bytes", n,
			"manifest_sha256", proto.ShortFingerprint(facts.SealedSHA256), "manifest_bytes", facts.SealedBytes)
		egressRefuse(w, http.StatusUnprocessableEntity, backupxfer.CodeDigestMismatch, "the member on the target is not the one the manifest recorded; it is not served")
		return
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		egressRefuse(w, http.StatusInternalServerError, backupxfer.CodeReadFailed, err.Error())
		return
	}

	w.Header().Set("Content-Type", backupxfer.EgressContentType)
	w.Header().Set(backupxfer.HeaderPlaintextDigest, facts.PlaintextSHA256)
	w.Header().Set(backupxfer.HeaderPlaintextBytes, strconv.FormatUint(facts.PlaintextBytes, 10))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	backupxfer.LogGrant(r.Context(), e.log, slog.LevelDebug, "restore egress: streaming a member", grant, keyOwner, "sealed_bytes", n)
	res, err := Unseal(&flushWriter{w: w, rc: http.NewResponseController(w)}, f, s.Key().Reveal())
	if err != nil {
		// The status is gone. Abort the connection so the node sees a cut
		// stream — which its byte count and digest then refuse — rather
		// than a clean EOF on a truncated tar.
		backupxfer.LogGrant(r.Context(), e.log, slog.LevelError, "restore egress: the stream was aborted mid-member", grant, keyOwner, "sealed_bytes", n, "error", err.Error())
		panic(http.ErrAbortHandler)
	}
	backupxfer.LogGrant(r.Context(), e.log, slog.LevelInfo, "restore egress: member streamed", grant, keyOwner, "sealed_bytes", n, "sealed_sha256", proto.ShortFingerprint(got),
		"plaintext_bytes", res.PlaintextBytes)
}

// flushWriter flushes after every chunk so the node's idle deadline sees
// progress on a slow disk.
type flushWriter struct {
	w  io.Writer
	rc *http.ResponseController
}

func (f *flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if err == nil {
		_ = f.rc.Flush()
	}
	return n, err
}

func egressRefuse(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(backupxfer.Problem{Code: code, Detail: detail})
}
