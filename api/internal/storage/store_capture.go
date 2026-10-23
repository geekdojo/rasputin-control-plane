package storage

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
)

// The secret store in the identity archive (geekdojo/geekdojo-brain#765,
// ADR-0010 S15 parts 1, 3 and 6).
//
// # The capture
//
// Step 3b, snapshot_store, runs straight after the database snapshot and
// inside the capture lock the run already holds (#830): readiness, the seal
// fragment's key id, the store's version, then quiesce, stop, a cold copy of
// the data directory into one staged tar, start, and a wait for the store to
// answer 200 before the quiesce is released. The staged tar holds the data
// and the version member only (F-765-04): the seal files and the store CA are
// read live at assemble, still under the lock, so no self-contained,
// decryptable copy of the store ever sits in the staging root.
//
// # Why one tar and not a staged directory
//
// CleanStaging, the sweep every terminal path and every run's start rely on,
// removes only regular files directly under the staging root. A staged
// directory would outlive a crash.

// Archive paths of the store's members.
const (
	storeDataArchivePrefix   = "store/data/"
	storeSealKeyArchivePath  = "store/seal-key"
	storeSealHCLArchivePath  = "store/seal.hcl"
	storeVersionArchivePath  = "store/openbao-version"
	storeCAKeyArchivePath    = "trust/" + tlsca.StoreKeyFile
	storeCACertArchivePath   = "trust/" + tlsca.StoreCertFile
	storeUnitArchivePrefix   = "store/"
	storeSealKeyFileName     = "seal-key"
	storeSealFragmentName    = "seal.hcl"
	storeCaptureStagingKind  = "store"
	storeAppliedMarkerName   = "applied"
	storeCaptureStepName     = "snapshot_store"
	storeCaptureStepTimeout  = 20 * time.Minute
	storeCaptureVersionLimit = 256
)

// The member notes the manifest and the restore report carry.
const (
	storeDataNote    = "the secret store's data, a cold copy taken with the store stopped — every secret the cluster's apps were given"
	storeSealKeyNote = "the secret store's seal key — without it the restored store data cannot be unsealed"
	storeSealHCLNote = "the secret store's seal fragment — it names the seal key's id, which the restored store unseals under"
	storeVersionNote = "the secret store release that wrote the data, so a restore can refuse data a newer release wrote"
	storeCAKeyNote   = "the secret store CA's PRIVATE key — the store trusts only leaves it issued, so the api's login works again after a restore"
	storeCACertNote  = "the secret store CA certificate"
)

// SecretStore is what the backup asks of the running secret store
// (ARCH-ISP). main's storeBackupControl implements it over the readiness
// monitor, the store client, the seal files and systemctl.
type SecretStore interface {
	// Readiness reports whether the store can be captured: "" when it is
	// ready, else the clause after "The secret store" that says why not.
	Readiness(ctx context.Context) (notReady string, err error)
	// SealKeyID is the key id the seal fragment names; it refuses a fragment
	// that is not Clean.
	SealKeyID() (string, error)
	// Version is the running store's release, from sys/health.
	Version(ctx context.Context) (string, error)
	// Stop stops the store and Start starts it again; ctx carries the job id
	// (jobs.ContextWithJobID) for their log records.
	Stop(ctx context.Context) error
	Start(ctx context.Context) error
	// WaitReady returns once the store answers 200 unsealed, or its bound's
	// error.
	WaitReady(ctx context.Context) error
	// Quiesce holds the store quiesced for the backup jobID, so a watcher
	// reads "paused for a backup", not "unreachable", until release.
	Quiesce(jobID string) (release func())
}

// runStoreCaptureResult is snapshot_store's result: counts, the version and
// the key id, and nothing key-shaped.
type runStoreCaptureResult struct {
	StagingName string `json:"stagingName"`
	Files       int    `json:"files"`
	SizeBytes   uint64 `json:"sizeBytes"`
	Version     string `json:"version"`
	KeyID       string `json:"keyId"`
}

// The capture's refusals. Each is a sentence the job records and the
// job-failed alert carries; the cause goes to the job feed, never a path or
// the store's own text into the sentence (ERR-MESSAGE).
const (
	errStoreCaptureNoArchive       = "so this backup captured nothing and wrote nothing: an archive without the secret store cannot be restored."
	errStoreReadinessUnknown       = sentenceError("The secret store's readiness could not be read, " + errStoreCaptureNoArchive + " Run the backup again once the store is ready.")
	errStoreSealUnknown            = sentenceError("The secret store's seal key id could not be read, " + errStoreCaptureNoArchive + " The api log names the defect.")
	errStoreVersionUnknown         = sentenceError("The secret store's version could not be read, " + errStoreCaptureNoArchive + " Run the backup again once the store is ready.")
	errStoreStopFailed             = sentenceError("The secret store could not be stopped for its copy, " + errStoreCaptureNoArchive + " The store was started again; the job feed names the cause.")
	errStoreCopyFailed             = sentenceError("The secret store's data could not be copied, " + errStoreCaptureNoArchive + " The store was started again; the job feed names the cause.")
	errStoreStartFailed            = sentenceError("The secret store did not come back after its copy, so this backup wrote nothing. The store's own unit keeps restarting it, and the secret store alert says when it is back.")
	errStoreCaptureMissing         = sentenceError("This backup has no copy of the secret store, so it wrote nothing: an archive without the secret store cannot be restored. Run the backup again.")
	errStoreCaptureKeyIDChanged    = sentenceError("The secret store's seal key changed between its copy and the archive, so this backup wrote nothing. Run the backup again.")
	errStoreCaptureNotConfigured   = sentenceError("This api captures the secret store but knows no store data directory, so this backup wrote nothing. The api's configuration names it.")
	errStoreCaptureSealUnreadable  = sentenceError("The secret store's seal files could not be read for the archive, so this backup wrote nothing. The api log names the defect.")
	errStoreCaptureStoreCAMissing  = sentenceError("The secret store CA could not be read for the archive, so this backup wrote nothing. The api log names the defect.")
	errStoreCaptureUnexpectedEntry = "the staged secret store copy holds %q, which is not a store member"
)

// storeNotReady is the refusal for a store whose readiness names a state.
func storeNotReady(clause string) error {
	return sentenceError("The secret store " + clause + ", " + errStoreCaptureNoArchive + " Run the backup again once the store is ready.")
}

// runSnapshotStore is step 3b. It fails closed: every refusal before the
// stop leaves the store alone, and every failure after it starts the store
// again and releases the quiesce (S15 part 3).
func runSnapshotStore(cfg RunConfig) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		tgt, err := priorRunTarget(sc)
		if err != nil {
			return nil, err
		}
		// The database snapshot comes first (S15 part 2): an entry the store
		// holds is written before the row that names it, so a row in the
		// snapshot always has its entry in the copy taken after it.
		var snap runSnapshotResult
		if err := priorResult(sc, "snapshot_db", &snap); err != nil {
			return nil, err
		}
		if strings.TrimSpace(cfg.Sources.StoreDataDir) == "" {
			return nil, errStoreCaptureNotConfigured
		}
		st := cfg.SecretStore
		notReady, err := st.Readiness(sc.Ctx)
		if err != nil {
			sc.Log("error", fmt.Sprintf("secret store readiness unreadable: %v", err))
			return nil, errStoreReadinessUnknown
		}
		if notReady != "" {
			return nil, storeNotReady(notReady)
		}
		keyID, err := st.SealKeyID()
		if err != nil {
			sc.Log("error", fmt.Sprintf("secret store seal key id unreadable: %v", err))
			return nil, errStoreSealUnknown
		}
		version, err := st.Version(sc.Ctx)
		if err != nil || strings.TrimSpace(version) == "" || len(version) > storeCaptureVersionLimit {
			sc.Log("error", fmt.Sprintf("secret store version unreadable: %v", err))
			return nil, errStoreVersionUnknown
		}
		name := stagingName(tgt.GenerationID, storeCaptureStagingKind)
		dst, err := stagedPath(sc, name)
		if err != nil {
			return nil, err
		}
		// coldCopy has put a failure's cause in the job feed; the stage picks
		// the sentence.
		files, size, stage, _ := coldCopy(sc, st, dst, cfg.Sources.StoreDataDir, version)
		switch stage {
		case coldCopyStop:
			return nil, errStoreStopFailed
		case coldCopyCopy:
			return nil, errStoreCopyFailed
		case coldCopyStart, coldCopyReady:
			return nil, errStoreStartFailed
		}
		sc.Log("info", fmt.Sprintf("secret store started and ready: version %s, seal key %s", version, keyID))
		return json.Marshal(runStoreCaptureResult{
			StagingName: name, Files: files, SizeBytes: byteCount(size), Version: version, KeyID: keyID,
		})
	}
}

// coldCopyStage is the stage of coldCopy that failed; "" when none did.
type coldCopyStage string

// The stages of coldCopy.
const (
	coldCopyStop  coldCopyStage = "stop"
	coldCopyCopy  coldCopyStage = "copy"
	coldCopyStart coldCopyStage = "start"
	coldCopyReady coldCopyStage = "ready"
)

// coldCopy is the stop-copy-start sequence the backup's snapshot_store and
// the OS update's pre-update copy share (geekdojo/geekdojo-brain#765, #800):
// quiesce the store for sc's job, stop it, write the cold copy of dataDir to
// dst, start it, and wait for it to answer 200 before the quiesce is
// released. It fails closed: a failure after the stop starts the store again
// (once, when the start itself was not what failed), and every failure
// removes dst. It returns the data file count and bytes copied, or the stage
// that failed with its cause; each caller maps the stage to its own sentence.
func coldCopy(sc *jobs.StepCtx, st SecretStore, dst, dataDir, version string) (int, int64, coldCopyStage, error) {
	ctx := jobs.ContextWithJobID(sc.Ctx, sc.JobID)
	release := st.Quiesce(sc.JobID)
	defer release()
	if err := st.Stop(ctx); err != nil {
		sc.Log("error", fmt.Sprintf("stopping the secret store failed: %v", err))
		startAfterFailure(ctx, sc, st)
		return 0, 0, coldCopyStop, err
	}
	sc.Log("info", "secret store stopped for its cold copy")
	files, size, cerr := stageStoreCapture(dst, dataDir, version)
	if cerr != nil {
		_ = os.Remove(dst)
		sc.Log("error", fmt.Sprintf("copying the secret store's data failed: %v", cerr))
		startAfterFailure(ctx, sc, st)
		return 0, 0, coldCopyCopy, cerr
	}
	sc.Log("info", fmt.Sprintf("copied %d secret store file(s) (%s)", files, humanBytes(byteCount(size))))
	if err := st.Start(ctx); err != nil {
		_ = os.Remove(dst)
		sc.Log("error", fmt.Sprintf("starting the secret store after its copy failed: %v", err))
		return 0, 0, coldCopyStart, err
	}
	// The quiesce is held until the store answers 200: the unit's
	// READY=1 comes before unseal (T24).
	if err := st.WaitReady(ctx); err != nil {
		_ = os.Remove(dst)
		sc.Log("error", fmt.Sprintf("the secret store did not answer ready after its copy: %v", err))
		return 0, 0, coldCopyReady, err
	}
	return files, size, "", nil
}

// startAfterFailure starts the store once after a failure that followed (or
// was) the stop. Its own failure is logged and otherwise left to the unit's
// Restart=always: the step already fails with the first error.
func startAfterFailure(ctx context.Context, sc *jobs.StepCtx, st SecretStore) {
	if err := st.Start(ctx); err != nil {
		sc.Log("error", fmt.Sprintf("starting the secret store again failed: %v", err))
	}
}

// stageStoreCapture writes the cold copy to dst, created exclusively 0600.
func stageStoreCapture(dst, dataDir, version string) (int, int64, error) {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return 0, 0, err
	}
	files, size, werr := writeStoreCapture(f, dataDir, version)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); cerr != nil && werr == nil {
		werr = cerr
	}
	return files, size, werr
}

// writeStoreCapture writes the store's cold copy to w as a tar: every
// regular file under dataDir as store/data/<rel>, sorted, then
// store/openbao-version holding exactly version. It refuses a non-regular
// file, a name a restore would refuse, and an empty data directory, rather
// than write a copy that cannot be put back. It returns the data file count
// and the bytes copied.
func writeStoreCapture(w io.Writer, dataDir, version string) (int, int64, error) {
	type file struct{ abs, arc string }
	var found []file
	err := filepath.WalkDir(dataDir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file, and a store copy holds only regular files", p)
		}
		rel, err := filepath.Rel(dataDir, p)
		if err != nil {
			return err
		}
		arc := path.Join(strings.TrimSuffix(storeDataArchivePrefix, "/"), filepath.ToSlash(rel))
		if err := validateRestorePath(arc); err != nil {
			return fmt.Errorf("a restore could not put back %s: %w", p, err)
		}
		found = append(found, file{abs: p, arc: arc})
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	if len(found) == 0 {
		return 0, 0, fmt.Errorf("the store data directory %s holds no file", dataDir)
	}
	sort.Slice(found, func(i, j int) bool { return found[i].arc < found[j].arc })
	tw := tar.NewWriter(w)
	now := time.Now().UTC()
	var total int64
	for _, f := range found {
		info, err := os.Lstat(f.abs)
		if err != nil {
			return 0, 0, err
		}
		if err := writeTarFile(tw, f.arc, f.abs, info.Size(), now); err != nil {
			return 0, 0, err
		}
		total += info.Size()
	}
	if err := writeTarBytes(tw, storeVersionArchivePath, []byte(version), now); err != nil {
		return 0, 0, err
	}
	if err := tw.Close(); err != nil {
		return 0, 0, err
	}
	return len(found), total, nil
}

// storeCaptureMember is one entry of a staged store tar, hashed in assemble's
// first pass.
type storeCaptureMember struct {
	arc    string
	size   int64
	sha256 string
}

// readStoreCapture hashes every entry of the staged store tar at p, refusing
// anything but the data and version members.
func readStoreCapture(p string) ([]storeCaptureMember, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	tr := tar.NewReader(f)
	var out []storeCaptureMember
	seenVersion := false
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		name := hdr.Name
		if hdr.Typeflag != tar.TypeReg || validateRestorePath(name) != nil ||
			(name != storeVersionArchivePath && !strings.HasPrefix(name, storeDataArchivePrefix)) {
			return nil, fmt.Errorf(errStoreCaptureUnexpectedEntry, name)
		}
		seenVersion = seenVersion || name == storeVersionArchivePath
		sum, n, err := hashReader(tr)
		if err != nil {
			return nil, err
		}
		if n != hdr.Size {
			return nil, fmt.Errorf("%s: read %d of %d bytes", name, n, hdr.Size)
		}
		out = append(out, storeCaptureMember{arc: name, size: n, sha256: sum})
	}
	if !seenVersion || len(out) < 2 {
		return nil, errors.New("the staged secret store copy has no data or no version member")
	}
	return out, nil
}

// storeLiveMembers are the seal files and the store CA, read live at
// assemble under the capture lock, in archive order.
func storeLiveMembers(src IdentitySources) []trustFile {
	return []trustFile{
		{abs: filepath.Join(src.SealDir, storeSealKeyFileName), arc: storeSealKeyArchivePath, note: storeSealKeyNote},
		{abs: filepath.Join(src.SealDir, storeSealFragmentName), arc: storeSealHCLArchivePath, note: storeSealHCLNote},
		{abs: filepath.Join(src.TrustDir, tlsca.StoreKeyFile), arc: storeCAKeyArchivePath, note: storeCAKeyNote},
		{abs: filepath.Join(src.TrustDir, tlsca.StoreCertFile), arc: storeCACertArchivePath, note: storeCACertNote},
	}
}

// storeIdentityBytes is the store's share of MeasureIdentitySet: the data
// tree, the seal files and the store CA. Zero when no store data directory
// is configured.
func storeIdentityBytes(src IdentitySources) uint64 {
	if strings.TrimSpace(src.StoreDataDir) == "" {
		return 0
	}
	total := treeBytes(src.StoreDataDir)
	for _, f := range storeLiveMembers(src) {
		if info, err := os.Stat(f.abs); err == nil && info.Mode().IsRegular() {
			total += byteCount(info.Size())
		}
	}
	return total
}

// treeBytes sums the regular files under dir; an unreadable subtree counts
// zero, as MeasureIdentitySet's other terms do.
func treeBytes(dir string) uint64 {
	var total uint64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // an unreadable subtree contributes zero, it does not fail an estimate
		}
		if info, ierr := d.Info(); ierr == nil && info.Mode().IsRegular() {
			total += byteCount(info.Size())
		}
		return nil
	})
	return total
}
