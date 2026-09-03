package backupxfer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Ingest is the endpoint a destination URI resolves to today: an http.Handler
// the api mounts, that lands sealed members on the claimed target.
//
// # One generation open at a time
//
// The api opens a generation at the start of a run's fan-out (Open) and
// closes it when the run ends (Close, or Abandon on failure). While it is
// open, the endpoint accepts members for it and nothing else: a credential
// for any other generation — including a perfectly valid one from a run that
// already finished — is refused with CodeNoGeneration. That is the second
// half of "reuse after the run is refused", and it is stateless in the sense
// that matters: the only state is which generation is open, which the api
// has to know anyway.
//
// # Where the bytes go, and how the path is built
//
// Open is given the generations directory under the mount the CO-LOCATED
// agent reported in its preflight ack (never a path the api derived, never a
// path another node named), and creates `.partial-<generation>` beneath it
// through openat. Every member is then written beneath THAT directory, one
// no-follow component at a time: volumes/, the app directory, a temporary
// file, and finally a rename to the member's name. A member name is validated
// by shape before any of it. The write verb later adds the identity archive
// and the manifest to the same directory and renames it to `<generation>`,
// which is the commit; a run that fails leaves `.partial-*`, which prune and
// the listing skip and Abandon removes.
//
// # Backpressure
//
// A semaphore on inbound uploads. A request takes a slot AFTER its credential
// is verified and BEFORE its body is read — which, with Expect: 100-continue
// on the client, is before the client sends a byte. The slot is released when
// the handler returns, which is when the connection closes, including when
// the client dies mid-body. Connection lifetime is the lease. No grant, no
// TTL, no renewal.
type Ingest struct {
	auth *Authority
	sem  chan struct{}
	now  func() time.Time
	logf func(format string, args ...any)

	mu       sync.Mutex
	gen      *openGeneration
	landed   map[string]*Receipt
	inflight map[string]bool
}

type openGeneration struct {
	id    string
	jobID string
	// gensDir is the generations directory; dir is the partial generation
	// directory beneath it, as an absolute path for logging and for Abandon.
	gensDir string
	dir     string
}

// DefaultConcurrency is the inbound-upload semaphore's size. One: §4.7's
// point is seek thrash on spinning media, the fan-out is serial anyway, and a
// wider default would only ever be exercised by a build that parallelises
// nodes — which should widen it deliberately.
const DefaultConcurrency = 1

// New builds the endpoint. concurrency <= 0 means DefaultConcurrency.
func New(auth *Authority, concurrency int) *Ingest {
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}
	return &Ingest{
		auth: auth,
		sem:  make(chan struct{}, concurrency),
		now:  time.Now,
		logf: log.Printf,
	}
}

// Authority is the credential minter the endpoint verifies against. The api's
// fan-out mints through it so a credential is verifiable by exactly one
// endpoint.
func (i *Ingest) Authority() *Authority { return i.auth }

// Mint issues a credential for one member of the OPEN generation. Refused
// when no generation is open, or the grant names another one — an endpoint
// must not hand out credentials it would refuse.
func (i *Ingest) Mint(g Grant, ttl time.Duration) (string, error) {
	i.mu.Lock()
	gen := i.gen
	i.mu.Unlock()
	if gen == nil || gen.id != g.Generation || gen.jobID != g.JobID {
		return "", fmt.Errorf("backupxfer: no generation %s is open for run %s", g.Generation, g.JobID)
	}
	return i.auth.Mint(g, ttl)
}

// Open creates `.partial-<generationID>` under gensDir and makes it the
// generation the endpoint accepts members for. gensDir must be absolute and
// clean; it is created if absent.
func (i *Ingest) Open(gensDir, generationID, jobID string) (string, error) {
	if !ingestSupported {
		return "", errUnsupportedOS
	}
	if !filepath.IsAbs(gensDir) || filepath.Clean(gensDir) != gensDir {
		return "", fmt.Errorf("backupxfer: %q is not an absolute, clean generations directory", gensDir)
	}
	if !proto.BackupValidGenerationID(generationID) {
		return "", fmt.Errorf("backupxfer: %q is not a usable generation id", generationID)
	}
	if strings.TrimSpace(jobID) == "" {
		return "", errors.New("backupxfer: a generation is opened by a run")
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.gen != nil {
		return "", fmt.Errorf("backupxfer: generation %s (run %s) is still open; one at a time", i.gen.id, i.gen.jobID)
	}
	if err := os.MkdirAll(gensDir, 0o700); err != nil {
		return "", err
	}
	root, err := openRootDir(gensDir)
	if err != nil {
		return "", err
	}
	defer func() { _ = root.Close() }()
	partial := proto.BackupPartialDirName(generationID)
	d, err := mkdirOpen(root, partial)
	if err != nil {
		return "", err
	}
	_ = d.Close()
	i.gen = &openGeneration{id: generationID, jobID: jobID, gensDir: gensDir, dir: filepath.Join(gensDir, partial)}
	i.landed = map[string]*Receipt{}
	i.inflight = map[string]bool{}
	return i.gen.dir, nil
}

// Close stops accepting members for generationID. The directory is left for
// the write verb to commit. A no-op when that generation is not the open one.
func (i *Ingest) Close(generationID string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.gen != nil && i.gen.id == generationID {
		i.gen = nil
	}
}

// Abandon closes the generation AND removes its partial directory — the
// terminal path of a run that did not reach the write. Removes only a
// directory named `.partial-<generationID>` that is still a real directory
// under the generations directory it was opened in.
func (i *Ingest) Abandon(generationID string) error {
	i.mu.Lock()
	gen := i.gen
	if gen != nil && gen.id == generationID {
		i.gen = nil
	}
	i.mu.Unlock()
	if gen == nil || gen.id != generationID {
		return nil
	}
	st, err := os.Lstat(gen.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // the write verb committed it, or nothing was ever landed
		}
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("backupxfer: %s is not a directory; not removing it", gen.dir)
	}
	return os.RemoveAll(gen.dir)
}

// Landed returns the endpoint's own record of a member of the open
// generation. THIS is what the api's fan-out consults after every transfer,
// whatever the agent's ack said: an ack can be lost on the bus, and a member
// that landed is a member that landed.
func (i *Ingest) Landed(generationID, member string) (*Receipt, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.gen == nil || i.gen.id != generationID {
		return nil, false
	}
	r, ok := i.landed[member]
	return r, ok
}

// OpenGeneration reports which generation is open, for a log line.
func (i *Ingest) OpenGeneration() (generationID, jobID string, open bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.gen == nil {
		return "", "", false
	}
	return i.gen.id, i.gen.jobID, true
}

// ServeHTTP lands one member.
func (i *Ingest) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !ingestSupported {
		refuse(w, http.StatusNotImplemented, CodeUnsupported, "this build cannot ingest on this operating system")
		return
	}
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", http.MethodPut)
		refuse(w, http.StatusMethodNotAllowed, CodeMemberInvalid, "members are PUT")
		return
	}
	generation, member, ok := SplitIngestPath(r.URL.Path)
	if !ok {
		refuse(w, http.StatusBadRequest, CodeMemberInvalid, "the path is not <generation>/volumes/<app>/<volume>.rasputin-archive")
		return
	}
	// The credential, before anything else is looked at. Verify checks the
	// signature before it decodes the grant, so a forged token is refused
	// without its content being interpreted.
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || strings.TrimSpace(token) == "" {
		refuse(w, http.StatusUnauthorized, CodeCredentialInvalid, "no upload credential")
		return
	}
	grant, err := i.auth.Verify(token)
	switch {
	case errors.Is(err, ErrCredentialExpired):
		refuse(w, http.StatusUnauthorized, CodeCredentialExpired, "the upload credential has expired; the run mints a fresh one per attempt")
		return
	case err != nil:
		refuse(w, http.StatusUnauthorized, CodeCredentialInvalid, "the upload credential does not verify")
		return
	}
	if grant.Generation != generation || grant.Member != member {
		// Valid, and not for this. A credential names one member, and this
		// is where "cannot upload a second volume on the first volume's
		// credential" is enforced.
		i.logf("backup ingest: credential %s for %s/%s presented for %s/%s by node %s — refused",
			grant.ID(), grant.Generation, grant.Member, generation, member, grant.NodeID)
		refuse(w, http.StatusForbidden, CodeCredentialScope, "the credential is scoped to a different member")
		return
	}

	i.mu.Lock()
	gen := i.gen
	if gen == nil || gen.id != generation || gen.jobID != grant.JobID {
		i.mu.Unlock()
		refuse(w, http.StatusConflict, CodeNoGeneration, "no backup run has that generation open for ingest")
		return
	}
	if _, done := i.landed[member]; done || i.inflight[member] {
		i.mu.Unlock()
		refuse(w, http.StatusConflict, CodeMemberExists, "that member has already landed (or is landing); members are never overwritten")
		return
	}
	i.inflight[member] = true
	i.mu.Unlock()
	defer func() {
		i.mu.Lock()
		delete(i.inflight, member)
		i.mu.Unlock()
	}()

	// The slot. Taken before the body is read, so with Expect: 100-continue
	// the client has sent nothing yet; released when this handler returns,
	// which is when the connection goes.
	select {
	case i.sem <- struct{}{}:
	case <-r.Context().Done():
		return // the client left the queue
	}
	defer func() { <-i.sem }()

	rc, status, code, detail := i.land(r, gen, grant, member)
	if rc == nil {
		i.logf("backup ingest: %s/%s from node %s (grant %s) refused: %s — %s", generation, member, grant.NodeID, grant.ID(), code, detail)
		refuse(w, status, code, detail)
		return
	}
	i.mu.Lock()
	i.landed[member] = rc
	i.mu.Unlock()
	i.logf("backup ingest: landed %s/%s from node %s: %d sealed bytes, sha256 %s", generation, member, grant.NodeID, rc.SealedBytes, short(rc.SealedDigest))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(rc)
}

// land streams the body onto the target beneath the open generation.
func (i *Ingest) land(r *http.Request, gen *openGeneration, grant Grant, member string) (rc *Receipt, status int, code, detail string) {
	parts := strings.Split(member, "/") // validated: volumes/<app>/<file>
	root, err := openRootDir(gen.gensDir)
	if err != nil {
		return nil, http.StatusInternalServerError, CodeWriteFailed, err.Error()
	}
	defer func() { _ = root.Close() }()
	genDir, err := openDirNoFollow(root, proto.BackupPartialDirName(gen.id))
	if err != nil {
		return nil, http.StatusInternalServerError, CodeWriteFailed, err.Error()
	}
	defer func() { _ = genDir.Close() }()
	volsDir, err := mkdirOpen(genDir, parts[0])
	if err != nil {
		return nil, http.StatusInternalServerError, CodeWriteFailed, err.Error()
	}
	defer func() { _ = volsDir.Close() }()
	appDir, err := mkdirOpen(volsDir, parts[1])
	if err != nil {
		return nil, http.StatusInternalServerError, CodeWriteFailed, err.Error()
	}
	defer func() { _ = appDir.Close() }()
	name := parts[2]
	if exists, err := existsAt(appDir, name); err != nil {
		return nil, http.StatusInternalServerError, CodeWriteFailed, err.Error()
	} else if exists {
		return nil, http.StatusConflict, CodeMemberExists, "a member of that name is already on the target; members are never overwritten"
	}
	tmpName := ".upload-" + name
	// A stale temp from an attempt that died is unlinked, never adopted.
	if err := unlinkAt(appDir, tmpName); err != nil {
		return nil, http.StatusInternalServerError, CodeWriteFailed, err.Error()
	}
	f, err := createExclusive(appDir, tmpName)
	if err != nil {
		return nil, http.StatusInternalServerError, CodeWriteFailed, err.Error()
	}
	committed := false
	defer func() {
		_ = f.Close()
		if !committed {
			// Whatever happened, no partial member is visible and no
			// temp is left: a disconnect mid-body leaves nothing.
			_ = unlinkAt(appDir, tmpName)
		}
	}()

	// The first read of the body is what sends 100 Continue. Everything
	// above happened before the client sent a byte.
	body := r.Body
	header, prefix, err := ReadHeader(body)
	if err != nil {
		return nil, http.StatusUnsupportedMediaType, CodeNotAnArchive, err.Error()
	}
	digest := sha256.New()
	out := io.MultiWriter(f, digest)
	if _, err := out.Write(prefix); err != nil {
		return nil, http.StatusInsufficientStorage, CodeWriteFailed, err.Error()
	}
	n, err := io.CopyBuffer(out, body, make([]byte, 256<<10))
	if err != nil {
		// A read error is the client going away; a write error is the
		// disk. Either way the temp is unlinked by the defer.
		return nil, http.StatusInsufficientStorage, CodeWriteFailed, fmt.Sprintf("the upload did not complete: %v", err)
	}
	total := byteCount(int64(len(prefix))) + byteCount(n)

	// The trailer is readable only after the body has been consumed to EOF.
	wantDigest := strings.ToLower(strings.TrimSpace(r.Trailer.Get(TrailerSealedDigest)))
	wantSize, perr := strconv.ParseUint(strings.TrimSpace(r.Trailer.Get(TrailerSealedBytes)), 10, 64)
	if wantDigest == "" || perr != nil {
		return nil, http.StatusUnprocessableEntity, CodeDigestMismatch, "the upload ended without declaring the sealed digest and length"
	}
	got := hex.EncodeToString(digest.Sum(nil))
	if got != wantDigest || total != wantSize {
		return nil, http.StatusUnprocessableEntity, CodeDigestMismatch,
			fmt.Sprintf("the node declared sha256 %s over %d bytes and %d bytes arrived hashing to %s; the member was discarded",
				short(wantDigest), wantSize, total, short(got))
	}
	if err := f.Sync(); err != nil {
		return nil, http.StatusInsufficientStorage, CodeWriteFailed, err.Error()
	}
	// Re-checked at the last moment: the in-flight map serialises this
	// handler per member, but a file placed by hand between the first
	// check and now must still not be overwritten.
	if exists, err := existsAt(appDir, name); err != nil || exists {
		return nil, http.StatusConflict, CodeMemberExists, "a member of that name appeared on the target while this one was landing; not overwriting it"
	}
	if err := renameAt(appDir, tmpName, name); err != nil {
		return nil, http.StatusInsufficientStorage, CodeWriteFailed, err.Error()
	}
	committed = true
	_ = appDir.Sync()

	plainBytes, _ := strconv.ParseUint(strings.TrimSpace(r.Header.Get(HeaderPlaintextBytes)), 10, 64)
	return &Receipt{
		Generation:         gen.id,
		Member:             member,
		NodeID:             grant.NodeID,
		SealedDigest:       got,
		SealedBytes:        total,
		PlaintextDigest:    strings.ToLower(strings.TrimSpace(r.Header.Get(HeaderPlaintextDigest))),
		PlaintextBytes:     plainBytes,
		KeyID:              header.KeyID,
		Scope:              header.Scope,
		EphemeralPublicKey: header.EphemeralPublicKey,
		LandedAt:           i.now().UTC(),
		GrantID:            grant.ID(),
	}, http.StatusCreated, "", ""
}

func refuse(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Problem{Code: code, Detail: detail})
}

func short(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}
