package quiesce

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/docker"
	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/backupxfer/fsat"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The restore verb: put one app volume back from the plaintext stream the
// api serves, with the app quiesced and the live volume replaced in one
// move. design/storage.md §4.5's restore, phase 2 (geekdojo-brain#291); the
// inverse of the stage verb, and it holds the same two contracts.
//
// # The order is the safety property, in reverse
//
//  1. every shape check and class gate, before anything is touched;
//  2. the volume resolved (an app not deployed on this node is refused —
//     nothing is invented), and the free-space guard applied beside it;
//  3. the stream fetched on its credential and unpacked into a STAGING
//     DIRECTORY BESIDE THE VOLUME, never into it, through backupxfer.Unpack's
//     fsat discipline, with the app still running — the download is the slow
//     part, and §4.7's whole argument is that an app should not be down for
//     a network transfer;
//  4. the stream's length and sha256 checked against what the manifest
//     recorded — a mismatch removes the staging tree and refuses, and the
//     live volume has not been touched;
//  5. for a running app: the §4.7 guard ARMED, then the app stopped;
//  6. the live tree and the staged tree EXCHANGED in one rename, the previous
//     contents left beside the volume under a name the ack reports, never
//     deleted here;
//  7. the guard released — in a defer, so it also runs on failure, on a
//     panic and on a cancelled context — and its verdict written into the
//     ack.
//
// A failure anywhere before step 6 leaves the live volume byte-for-byte as
// it was; a failure at step 6 leaves it as it was too, because the exchange
// is one syscall. The app's restart never depends on the api, the source,
// or the outcome: the guard is the same one the stage verb arms, with the
// same marker the boot sweep honours.
//
// # What is kept, and for how long
//
// The previous contents move aside as `.rasputin-replaced-<volume>-<ts>`
// beside the volume. One per volume: a second restore of the same volume
// removes the older one before it swaps. That bounds the disk this keeps at
// one extra copy of each restored volume, and it is deliberately NOT swept
// at boot — it is the operator's way back from a restore they regret, and
// a sweep that removed it silently would be the thing this verb exists to
// prevent from the other side. A staging tree a dying process left behind
// IS swept at boot, through a record written beside the armed-stop markers.

// Directory names beside a volume. Both dot-prefixed so nothing that lists
// a volume's parent by name mistakes them for volumes.
const (
	restoreStagingPrefix  = ".rasputin-restore-"
	restoreReplacedPrefix = ".rasputin-replaced-"
)

// restoreRecordDirName is the directory under the agent's state dir where
// in-flight restore staging trees are recorded, so the next start can sweep
// one a dying process left beside a volume.
const restoreRecordDirName = "restore-staging"

// RestoreRecordDir is where in-flight restore staging is recorded, and the
// one place that is decided.
func RestoreRecordDir(stateDir string) string { return filepath.Join(stateDir, restoreRecordDirName) }

// SetRestoreRecordDir points the stager at RestoreRecordDir(stateDir). Set
// by main; a stager without one refuses every restore rather than staging a
// tree nothing would sweep.
func (s *Stager) SetRestoreRecordDir(dir string) { s.restoreRecordDir = dir }

// restoreRecord is what is written for one staging tree. Identifiers and a
// path on this node; nothing else.
type restoreRecord struct {
	Staging   string    `json:"staging"`
	AppID     string    `json:"appId"`
	Volume    string    `json:"volume"`
	RestoreID string    `json:"restoreId,omitempty"`
	StartedAt time.Time `json:"startedAt"`
}

// The restore refusals, as sentinel errors so the ack's code is derived from
// the error rather than matched on its text.
var (
	// ErrClassNotRestored is a class that cannot be in a generation.
	ErrClassNotRestored = errors.New("quiesce: volumes of that class are never restored")
	// ErrSourceRefused is the source saying no.
	ErrSourceRefused = errors.New("quiesce: the source refused the fetch")
	// ErrTransferFailed is a stream that did not arrive whole.
	ErrTransferFailed = errors.New("quiesce: the stream did not arrive whole")
	// ErrArchiveInvalid is a tar this verb will not put into a volume.
	ErrArchiveInvalid = errors.New("quiesce: the volume tar was refused")
	// ErrDigestMismatch is a stream whose bytes are not the manifest's.
	ErrDigestMismatch = errors.New("quiesce: the stream does not match what the manifest recorded")
	// ErrSwapFailed is the exchange failing with the app stopped.
	ErrSwapFailed = errors.New("quiesce: the live volume could not be exchanged for the staged tree")
)

// fetcher resolves a source's fetcher. Seam for tests.
func (s *Stager) fetcher(source string) (backupxfer.Fetcher, error) {
	if s.fetcherFor != nil {
		return s.fetcherFor(source)
	}
	return backupxfer.FetcherFor(source, backupxfer.HTTPOptions{CABundlePath: s.caBundlePath})
}

// RestoreVolume carries out one BackupRestoreVolumeCmd. It ALWAYS returns
// an ack — a refusal is an ack with OK false and a code — because the
// restart facts have to reach the api on every path.
func (s *Stager) RestoreVolume(ctx context.Context, cmd proto.BackupRestoreVolumeCmd) (ack *proto.BackupRestoreVolumeAck) {
	ack = &proto.BackupRestoreVolumeAck{
		AppID: cmd.AppID, Volume: cmd.Volume, Member: cmd.Member,
		// True until something is stopped.
		AppRestored: true,
	}
	defer func() {
		if r := recover(); r != nil {
			s.logf("rasputin-agent: restore: PANIC restoring %s/%s: %v", cmd.AppID, cmd.Volume, r)
			s.failRestore(ack, fmt.Errorf("panic while restoring: %v", r))
		}
	}()

	if err := validateRestore(s.restoreRecordDir, cmd); err != nil {
		return s.failRestore(ack, err)
	}
	switch cmd.Class {
	case tileschema.BackupCache:
		return s.failRestore(ack, fmt.Errorf("%w: %q is class cache, which §4.2 never captures, so no generation can hold it — a command naming it is a caller bug", ErrClassNotRestored, cmd.Volume))
	case tileschema.BackupBulk:
		return s.failRestore(ack, fmt.Errorf("%w: %q is class bulk, which §4.7 never stages, so no generation of this transport holds it", ErrClassNotRestored, cmd.Volume))
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	volRoot, err := s.rt.ResolveVolume(ctx, cmd.AppID, cmd.Volume)
	if err != nil {
		if errors.Is(err, docker.ErrVolumeNotFound) {
			return s.failRestore(ack, fmt.Errorf("%w: %v — the app is not deployed on this node, or its stack never created that volume; install it first, nothing is invented here", ErrVolumeNotFound, err))
		}
		return s.failRestore(ack, err)
	}
	volRoot = filepath.Clean(volRoot)
	parent, base := filepath.Dir(volRoot), filepath.Base(volRoot)
	if parent == volRoot || base == "" || base == "/" || base == "." {
		return s.failRestore(ack, fmt.Errorf("the runtime resolved %q as the volume root, which has no parent to stage beside", volRoot))
	}
	// A staging tree left beside this volume by a run that died is removed
	// before this one is sized; a replaced copy is left where it is until
	// the moment this run has something to put in its place.
	s.removeStale(parent, restoreStagingPrefix+base+"-")

	if err := s.guardRestoreSpace(parent, cmd.PlaintextBytes); err != nil {
		return s.failRestore(ack, err)
	}

	staging := filepath.Join(parent, restoreStagingPrefix+base+"-"+randomHex(6))
	if err := os.Mkdir(staging, 0o700); err != nil {
		return s.failRestore(ack, fmt.Errorf("create staging directory beside the volume: %w", err))
	}
	record, err := s.writeRestoreRecord(restoreRecord{Staging: staging, AppID: cmd.AppID, Volume: cmd.Volume, RestoreID: cmd.RestoreID, StartedAt: time.Now().UTC()})
	if err != nil {
		_ = os.RemoveAll(staging)
		return s.failRestore(ack, fmt.Errorf("record the staging tree so a crash can be swept: %w", err))
	}
	swapped := false
	defer func() {
		if !swapped {
			_ = os.RemoveAll(staging)
		}
		_ = os.Remove(record)
	}()

	// ----- fetch and unpack, with the app still running ------------------
	res, err := s.fetchAndUnpack(ctx, cmd, staging)
	if err != nil {
		return s.failRestore(ack, err)
	}
	ack.ReceivedBytes = res.StreamBytes
	ack.Digest = res.Digest
	ack.FileCount = res.Files
	ack.DirCount = res.Dirs
	ack.UnpackedBytes = res.Bytes
	ack.OwnershipApplied = res.OwnershipApplied
	if res.StreamBytes != cmd.PlaintextBytes || !strings.EqualFold(res.Digest, cmd.PlaintextDigest) {
		return s.failRestore(ack, fmt.Errorf("%w: %d bytes arrived hashing to %s; the manifest recorded %d bytes hashing to %s. The live volume was not touched",
			ErrDigestMismatch, res.StreamBytes, short(res.Digest), cmd.PlaintextBytes, short(cmd.PlaintextDigest)))
	}
	// The staged tree takes the live root's own mode and ownership, so the
	// container finds its data directory exactly as permissive as it was —
	// the tar has no entry for the root itself.
	if err := copyRootMeta(volRoot, staging, res.OwnershipApplied); err != nil {
		return s.failRestore(ack, fmt.Errorf("apply the volume root's mode and owner to the staged tree: %w", err))
	}

	// ----- stop, swap, start -----------------------------------------------
	running, err := s.rt.AppRunning(ctx, cmd.AppID)
	if err != nil {
		return s.failRestore(ack, fmt.Errorf("app %s: %w", cmd.AppID, err))
	}
	ack.WasRunning = running
	if running {
		g, err := s.arm(cmd.AppID, cmd.AppName, "restore:"+cmd.Volume)
		if err != nil {
			return s.failRestore(ack, fmt.Errorf("%w: could not arm the restart guard, so the app was not stopped and the volume was not touched: %v", ErrQuiesceFailed, err))
		}
		ack.Stopped = true
		ack.StoppedAt = time.Now().UTC()
		defer func() {
			out := g.Release()
			ack.AppRestored = out.restored
			ack.RestoredBy = out.by
			ack.RestoreDetail = out.detail
			if out.restored {
				ack.RestartedAt = out.at
				ack.DowntimeMillis = out.at.Sub(ack.StoppedAt).Milliseconds()
			}
			if g.Fired() && swapped {
				// The deadline started the app before the swap was released.
				// The swap is one syscall, so the data is whole; the app may
				// have opened its volume across it. Said, not hidden.
				ack.RestoreDetail = strings.TrimSpace(out.detail + "; the watchdog started the app before this verb released it, across the swap — restart the app if it misbehaves")
			}
		}()
		s.logf("rasputin-agent: restore: STOPPING app %s (%s) to replace volume %s", cmd.AppID, cmd.AppName, cmd.Volume)
		if err := s.rt.StopApp(ctx, cmd.AppID, proto.BackupStopGraceSeconds); err != nil {
			return s.failRestore(ack, fmt.Errorf("%w: stop app %s: %v — the volume was not touched", ErrQuiesceFailed, cmd.AppID, err))
		}
	}

	// One previous copy per volume: the older one goes before the new one
	// is made, so a second restore never leaves two.
	s.removeStale(parent, restoreReplacedPrefix+base+"-")
	replaced := filepath.Join(parent, restoreReplacedPrefix+base+"-"+time.Now().UTC().Format("20060102T150405Z"))
	if err := s.swap(volRoot, staging); err != nil {
		return s.failRestore(ack, fmt.Errorf("%w: %v — the live volume is as it was and the staged tree is removed", ErrSwapFailed, err))
	}
	swapped = true
	ack.Replaced = true
	// The staging path now holds the PREVIOUS contents. Moved aside under a
	// name that says what it is; if that rename fails the data stays under
	// the staging name and the ack names that instead — it is never removed.
	if err := os.Rename(staging, replaced); err != nil {
		s.logf("rasputin-agent: restore: previous contents of %s/%s stay at %s: rename to %s failed: %v", cmd.AppID, cmd.Volume, staging, replaced, err)
		ack.PreviousKept = staging
	} else {
		ack.PreviousKept = replaced
	}
	_ = syncDir(parent)
	ack.OK = true
	return ack
}

// fetchAndUnpack streams the member into staging through the fsat unpack,
// classifying what went wrong by where it went wrong.
func (s *Stager) fetchAndUnpack(ctx context.Context, cmd proto.BackupRestoreVolumeCmd, staging string) (*backupxfer.UnpackResult, error) {
	f, err := s.fetcher(cmd.Source)
	if err != nil {
		if errors.Is(err, backupxfer.ErrUnsupportedDestination) {
			return nil, fmt.Errorf("%w: %v", ErrSourceRefused, err)
		}
		return nil, err
	}
	stream, err := f.Get(ctx, backupxfer.GetRequest{Source: cmd.Source, Generation: cmd.GenerationID, Member: cmd.Member, Credential: cmd.Credential})
	if err != nil {
		var refused *backupxfer.RefusedError
		if errors.As(err, &refused) {
			// The endpoint's error carries its code and never the
			// credential (backupxfer redacts on its side); wrapped so the
			// ack can name the code.
			return nil, fmt.Errorf("%w (%s): %w", ErrSourceRefused, refused.Problem.Code, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrTransferFailed, redactCredential(err, cmd.Credential))
	}
	defer func() { _ = stream.Body.Close() }()
	if stream.DeclaredBytes != 0 && stream.DeclaredBytes != cmd.PlaintextBytes {
		return nil, fmt.Errorf("%w: the source declares %d bytes and the command carries %d from the manifest; refusing to read a stream the two disagree about", ErrDigestMismatch, stream.DeclaredBytes, cmd.PlaintextBytes)
	}
	root, err := fsat.OpenRoot(staging)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	// One byte past the manifest's length: an over-long stream is detected
	// by count rather than read to the end of whatever it is.
	res, err := backupxfer.Unpack(root, io.LimitReader(stream.Body, int64(cmd.PlaintextBytes)+1), backupxfer.UnpackBounds{
		MaxBytes:       cmd.PlaintextBytes,
		ApplyOwnership: os.Geteuid() == 0,
	})
	if err != nil {
		switch {
		case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.ErrClosedPipe):
			// The stream ended inside a member: the source went away.
			return nil, fmt.Errorf("%w: the stream ended before the member was complete: %v", ErrTransferFailed, redactCredential(err, cmd.Credential))
		case errors.Is(err, backupxfer.ErrUnpackRefused):
			return nil, fmt.Errorf("%w: %v", ErrArchiveInvalid, err)
		}
		return nil, err
	}
	return res, nil
}

// guardRestoreSpace is §4.7's free-space guard on the restore side: the
// staged tree plus the reserve must fit beside the volume, before a byte is
// fetched. The previous contents are kept, so the volume's filesystem ends
// up holding both — which is what the unpacked size is charged against.
func (s *Stager) guardRestoreSpace(parent string, need uint64) error {
	free, err := s.freeBytes(parent)
	if err != nil {
		return fmt.Errorf("free space beside the volume (%s): %w", parent, err)
	}
	total := need + proto.BackupStagingReserveBytes
	if total < need || free < total {
		return fmt.Errorf("%w: %s has %s free; restoring this volume needs about %s (the %s tar unpacked beside the live volume, which is kept) while leaving the %s reserve. Nothing was fetched and the app was not stopped",
			ErrInsufficientSpace, parent, humanBytes(free), humanBytes(total), humanBytes(need), humanBytes(proto.BackupStagingReserveBytes))
	}
	return nil
}

// removeStale removes every entry in parent whose name starts with prefix —
// a staging tree from a run that died, or the previous restore's kept copy
// when a new one is about to be made.
func (s *Stager) removeStale(parent, prefix string) {
	ents, err := os.ReadDir(parent)
	if err != nil {
		return
	}
	for _, e := range ents {
		if e.IsDir() && strings.HasPrefix(e.Name(), prefix) {
			p := filepath.Join(parent, e.Name())
			if err := os.RemoveAll(p); err != nil {
				s.logf("rasputin-agent: restore: could not remove %s: %v", p, err)
			}
		}
	}
}

// copyRootMeta gives dst the mode and (when this process may) the owner of
// src — the live volume root — so the container finds its data directory as
// it was.
func copyRootMeta(src, dst string, chown bool) error {
	st, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := os.Chmod(dst, st.Mode().Perm()); err != nil {
		return err
	}
	if !chown {
		return nil
	}
	uid, gid, ok := ownerOf(st)
	if !ok {
		return nil
	}
	return os.Chown(dst, uid, gid)
}

// writeRestoreRecord records the staging tree for the boot sweep.
func (s *Stager) writeRestoreRecord(r restoreRecord) (string, error) {
	if err := os.MkdirAll(s.restoreRecordDir, 0o700); err != nil {
		return "", err
	}
	body, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	path := filepath.Join(s.restoreRecordDir, randomHex(8)+".json")
	if err := writeFileSync(path, body); err != nil {
		return "", err
	}
	return path, nil
}

// SweepRestoreStaging removes every staging tree a previous agent process
// recorded and did not live to remove or swap — §4.7's "cleanup on boot",
// for the reverse direction. A record whose tree is gone is just removed. A
// replaced copy (`.rasputin-replaced-*`) is never touched here. Called at
// agent start; returns how many trees were removed.
func (s *Stager) SweepRestoreStaging() int {
	ents, err := os.ReadDir(s.restoreRecordDir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.restoreRecordDir, e.Name())
		raw, err := os.ReadFile(path) //nolint:gosec // G304: a record this agent wrote under its own state dir, listed by name
		if err != nil {
			continue
		}
		var r restoreRecord
		if err := json.Unmarshal(raw, &r); err != nil || !strings.HasPrefix(filepath.Base(r.Staging), restoreStagingPrefix) {
			// Not something this package wrote, or not a staging tree by
			// name: left alone rather than removed.
			s.logf("rasputin-agent: restore: ignoring unreadable staging record %s", path)
			continue
		}
		if st, err := os.Lstat(r.Staging); err == nil && st.IsDir() {
			s.logf("rasputin-agent: restore: removing staging tree %s left by a restore of %s/%s that did not finish", r.Staging, r.AppID, r.Volume)
			if err := os.RemoveAll(r.Staging); err != nil {
				s.logf("rasputin-agent: restore: could not remove %s: %v", r.Staging, err)
				continue
			}
			n++
		}
		_ = os.Remove(path)
	}
	return n
}

// swap exchanges the live volume root and the staged tree. Seam for tests;
// the production implementation is per platform (swap_*.go).
func (s *Stager) swap(live, staging string) error {
	if s.swapFn != nil {
		return s.swapFn(live, staging)
	}
	return exchangeDirs(live, staging)
}

func (s *Stager) failRestore(ack *proto.BackupRestoreVolumeAck, err error) *proto.BackupRestoreVolumeAck {
	ack.OK = false
	ack.Replaced = false
	ack.Refusal = restoreRefusalFor(err)
	var refused *backupxfer.RefusedError
	if errors.As(err, &refused) {
		ack.SourceCode = refused.Problem.Code
	}
	ack.Detail = err.Error()
	return ack
}

// restoreRefusalFor maps a restore error onto the wire code. The stage
// verb's mapping first, then the restore's own.
func restoreRefusalFor(err error) proto.StorageRefusal {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrClassNotRestored):
		return proto.BackupRefusalClassNotRestored
	case errors.Is(err, ErrSourceRefused):
		return proto.BackupRefusalSourceRefused
	case errors.Is(err, ErrTransferFailed):
		return proto.BackupRefusalTransferFailed
	case errors.Is(err, ErrArchiveInvalid):
		return proto.BackupRefusalArchiveInvalid
	case errors.Is(err, ErrDigestMismatch):
		return proto.BackupRefusalDigestMismatch
	case errors.Is(err, ErrSwapFailed):
		return proto.BackupRefusalSwapFailed
	}
	return refusalFor(err)
}

func validateRestore(recordDir string, cmd proto.BackupRestoreVolumeCmd) error {
	if strings.TrimSpace(recordDir) == "" {
		return fmt.Errorf("%w: this agent has no restore record directory configured, so a staging tree it left could never be swept", ErrBadName)
	}
	if strings.TrimSpace(cmd.AppID) == "" {
		return fmt.Errorf("%w: the command names no app", ErrBadName)
	}
	if strings.TrimSpace(cmd.Volume) == "" {
		return fmt.Errorf("%w: the command names no volume", ErrBadName)
	}
	if strings.TrimSpace(cmd.Source) == "" {
		return fmt.Errorf("%w: the command names no source", ErrBadName)
	}
	if strings.TrimSpace(cmd.Credential) == "" {
		return fmt.Errorf("%w: the command carries no restore credential", ErrBadName)
	}
	if !proto.BackupValidGenerationID(cmd.GenerationID) {
		return fmt.Errorf("%w: %q is not a usable generation id", ErrBadName, cmd.GenerationID)
	}
	if !proto.BackupValidMemberPath(cmd.Member) {
		return fmt.Errorf("%w: %q is not a member path", ErrBadName, cmd.Member)
	}
	if cmd.Class != "" && !tileschema.ValidBackupClass[cmd.Class] {
		return fmt.Errorf("%w: backup class %q is not one of %s", ErrBadName, cmd.Class, strings.Join(tileschema.BackupClasses, "|"))
	}
	if d := strings.TrimSpace(cmd.PlaintextDigest); len(d) != 64 || !isHex(d) {
		return fmt.Errorf("%w: the command carries no usable manifest digest for the plaintext, and a stream nothing can verify is not restored", ErrBadName)
	}
	if cmd.PlaintextBytes == 0 {
		return fmt.Errorf("%w: the command carries no manifest length for the plaintext, and an unbounded stream is not restored", ErrBadName)
	}
	return nil
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

func short(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(b)
}
