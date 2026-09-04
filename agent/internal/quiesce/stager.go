package quiesce

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/disk"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/docker"
	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// Stager owns the staging root and the marker directory, and runs one volume
// at a time.
type Stager struct {
	rt          Runtime
	stagingRoot string
	markerDir   string
	// mu serialises Stage: §4.7's peak-usage argument holds only if one
	// volume is staged at a time.
	mu sync.Mutex

	// The seams. Each has a production default set by New; tests replace
	// them to make a disk look full, a deadline short, or a copy die.
	freeBytes        func(dir string) (uint64, error)
	watchdogDeadline time.Duration
	restartBackoff   []time.Duration
	releaseWait      time.Duration
	afterFile        func(rel string) error
	logf             func(format string, args ...any)
	// caBundlePath and transportFor are the transfer verb's seams: the
	// mesh CA the HTTP transport trusts, and a test's replacement for the
	// transport itself.
	caBundlePath string
	transportFor func(destination string) (backupxfer.Transport, error)
	// The restore verb's seams (restore.go): the fetcher for a source, the
	// directory in-flight staging trees are recorded in for the boot sweep,
	// and the atomic exchange itself.
	fetcherFor       func(source string) (backupxfer.Fetcher, error)
	restoreRecordDir string
	swapFn           func(live, staging string) error
}

// New builds a Stager over the runtime. stagingRoot is the agent's one
// staging root (storage.StagingRoot) and markerDir is MarkerDir(stateDir).
func New(rt Runtime, stagingRoot, markerDir string) *Stager {
	return &Stager{
		rt:          rt,
		stagingRoot: stagingRoot,
		markerDir:   markerDir,
		freeBytes: func(dir string) (uint64, error) {
			du, err := disk.Usage(dir)
			if err != nil {
				return 0, err
			}
			return du.Free, nil
		},
		// The request context is bounded by BackupStageWork and cancels the
		// copy first; the deadline is the backstop for a driver stuck in
		// something that does not honour the context.
		watchdogDeadline: proto.BackupStageWork + time.Minute,
		restartBackoff:   defaultRestartBackoff,
		releaseWait:      defaultReleaseWait,
		logf:             log.Printf,
	}
}

// Stage carries out one BackupStageVolumeCmd. It ALWAYS returns an ack — a
// refusal is an ack with OK false and a refusal code, never a bare error —
// because the restart facts have to reach the api on every path, and a bare
// error would drop them.
//
// The order is the safety property:
//
//  1. every shape check, class gate and strategy gate, before anything is
//     touched;
//  2. the volume resolved and measured, and the free-space guard applied,
//     before anything is written;
//  3. for `stop`: the guard ARMED, then the app stopped;
//  4. the copy;
//  5. the guard released — in a defer, so it also runs on failure, on a
//     panic and on a cancelled context — and its verdict written into the
//     ack.
func (s *Stager) Stage(ctx context.Context, cmd proto.BackupStageVolumeCmd) (ack *proto.BackupStageVolumeAck) {
	ack = &proto.BackupStageVolumeAck{
		AppID: cmd.AppID, Volume: cmd.Volume, StagingName: cmd.StagingName,
		ServiceInterrupting: cmd.Quiesce == tileschema.QuiesceStop,
		// True until something is stopped: an app that was never touched is
		// in the state it was found in.
		AppRestored: true,
	}
	// Registered FIRST so it runs LAST: the guard's deferred release has
	// already restarted the app by the time a panic reaches here, and the
	// ack it wrote into is the one returned.
	defer func() {
		if r := recover(); r != nil {
			s.logf("rasputin-agent: quiesce: PANIC staging %s/%s: %v", cmd.AppID, cmd.Volume, r)
			s.fail(ack, fmt.Errorf("panic while staging: %v", r))
		}
	}()

	if err := validate(s.stagingRoot, cmd); err != nil {
		return s.fail(ack, err)
	}
	switch cmd.Class {
	case tileschema.BackupCache:
		return s.fail(ack, fmt.Errorf("%w: %q is class cache, which §4.2 never copies — a command naming it is a caller bug", ErrClassNotStaged, cmd.Volume))
	case tileschema.BackupBulk:
		return s.fail(ack, fmt.Errorf("%w: %q is class bulk, which §4.7 streams direct and never stages (geekdojo-brain#295); a media library cannot be staged on a node whose boot medium is smaller than it", ErrClassNotStaged, cmd.Volume))
	}
	switch cmd.Quiesce {
	case tileschema.QuiescePostgres, tileschema.QuiesceMySQL:
		return s.fail(ack, fmt.Errorf("%w: volume %q of app %s declares quiesce %q, which is declared in the schema but not implemented in this build — no shipped tile uses it, and a driver nothing exercises is not built (geekdojo-brain#294); this volume was NOT copied",
			ErrUnsupported, cmd.Volume, cmd.AppID, cmd.Quiesce))
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	dst := filepath.Join(s.stagingRoot, cmd.StagingName)
	if _, err := os.Lstat(dst); err == nil {
		return s.fail(ack, fmt.Errorf("%w: %s", ErrStagingExists, dst))
	}
	volRoot, err := s.rt.ResolveVolume(ctx, cmd.AppID, cmd.Volume)
	if err != nil {
		if errors.Is(err, docker.ErrVolumeNotFound) {
			return s.fail(ack, fmt.Errorf("%w: %v", ErrVolumeNotFound, err))
		}
		return s.fail(ack, err)
	}
	// A scratch dir left by a run that died is removed before it can be
	// sized, captured or collide with this run's snapshots.
	_ = os.RemoveAll(filepath.Join(volRoot, scratchDirName))

	running, err := s.rt.AppRunning(ctx, cmd.AppID)
	if err != nil {
		return s.fail(ack, fmt.Errorf("app %s: %w", cmd.AppID, err))
	}
	ack.WasRunning = running

	findDBs := cmd.Quiesce == tileschema.QuiesceSQLite && running
	p, err := measure(volRoot, findDBs)
	if err != nil {
		return s.fail(ack, fmt.Errorf("measure %s: %w", volRoot, err))
	}
	if err := s.guardSpace(p); err != nil {
		return s.fail(ack, err)
	}

	subst := map[string]string{}
	skip := map[string]bool{}
	switch {
	case cmd.Quiesce == tileschema.QuiesceStop && running:
		g, err := s.arm(cmd.AppID, cmd.AppName, cmd.StagingName)
		if err != nil {
			// No marker, no stop: a stop this process could not record is one
			// a crash would make permanent.
			return s.fail(ack, fmt.Errorf("%w: could not arm the restart guard, so the app was not stopped: %v", ErrQuiesceFailed, err))
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
			if g.Fired() && ack.OK {
				// The copy finished, but the app came back partway through
				// it. What is on disk is not clean-shutdown consistent and
				// must not be reported as such.
				_ = os.Remove(dst)
				s.fail(ack, ErrWatchdogFired)
			}
		}()
		s.logf("rasputin-agent: quiesce: STOPPING app %s (%s) to stage volume %s", cmd.AppID, cmd.AppName, cmd.Volume)
		if err := s.rt.StopApp(ctx, cmd.AppID, proto.BackupStopGraceSeconds); err != nil {
			return s.fail(ack, fmt.Errorf("%w: stop app %s: %v", ErrQuiesceFailed, cmd.AppID, err))
		}
		ack.Consistency = proto.BackupConsistencyCleanShutdown
		ack.Window = "none: the app was stopped for the copy and every file agrees with every other"

	case cmd.Quiesce == tileschema.QuiesceSQLite && running:
		scratch := filepath.Join(volRoot, scratchDirName)
		defer func() { _ = os.RemoveAll(scratch) }()
		for _, dbRel := range p.dbs {
			if err := ctx.Err(); err != nil {
				return s.fail(ack, err)
			}
			tool, err := s.rt.SnapshotSQLite(ctx, cmd.AppID, cmd.Volume, dbRel, scratchRel(dbRel))
			if err != nil {
				return s.fail(ack, fmt.Errorf("%w: snapshot %s: %v", ErrQuiesceFailed, dbRel, err))
			}
			ack.SnapshotTool = tool
			subst[dbRel] = scratchRel(dbRel)
			for _, sc := range sidecarsOf(dbRel) {
				skip[sc] = true
			}
		}
		ack.Databases = append([]string{}, p.dbs...)
		ack.Consistency = proto.BackupConsistencySnapshotPlusLive
		ack.Window = fmt.Sprintf("%d database(s) are point-in-time snapshots taken through the running app; every other file was copied live, so a non-database file rewritten during the copy may be torn, and the databases and the rest of the volume can disagree by the length of the copy", len(p.dbs))

	default:
		if running {
			ack.Consistency = proto.BackupConsistencyLiveCopy
			ack.Window = "the whole copy: the app was running, so a file rewritten during the copy may be torn and files may disagree with each other"
		} else {
			ack.Consistency = proto.BackupConsistencyCleanShutdown
			ack.Window = "none: the app was not running, so nothing wrote the volume during the copy; it was not started afterwards"
		}
	}

	res, err := writeTar(ctx, volRoot, dst, subst, skip, s.afterFile)
	if err != nil {
		return s.fail(ack, fmt.Errorf("copy %s: %w", cmd.Volume, err))
	}
	ack.OK = true
	ack.StagedPath = dst
	ack.SizeBytes = res.size
	ack.Digest = res.digest
	ack.FileCount = res.files
	ack.PlaintextBytes = res.plain
	return ack
}

// guardSpace is §4.7's source-side free-space check: the volume, plus its
// snapshots when the sqlite driver will make some, plus the reserve, must fit
// under the staging root. Refused with both numbers, before anything is
// written.
func (s *Stager) guardSpace(p plan) error {
	free, err := s.freeBytes(s.stagingRoot)
	if err != nil {
		return fmt.Errorf("free space under %s: %w", s.stagingRoot, err)
	}
	need := p.bytes + p.dbBytes
	if need < p.bytes { // overflow: never satisfiable
		return fmt.Errorf("%w: the volume's size does not fit in a 64-bit count", ErrInsufficientSpace)
	}
	total := need + proto.BackupStagingReserveBytes
	if total < need || free < total {
		return fmt.Errorf("%w: %s has %s free; staging this volume needs about %s (a %s volume%s) while leaving the %s reserve. Nothing was written and the app was not stopped",
			ErrInsufficientSpace, s.stagingRoot, humanBytes(free), humanBytes(total), humanBytes(p.bytes),
			snapshotClause(p), humanBytes(proto.BackupStagingReserveBytes))
	}
	return nil
}

func snapshotClause(p plan) string {
	if p.dbBytes == 0 {
		return ""
	}
	return fmt.Sprintf(" plus %s of database snapshots", humanBytes(p.dbBytes))
}

// fail marks the ack refused. The restart facts already on it are kept.
func (s *Stager) fail(ack *proto.BackupStageVolumeAck, err error) *proto.BackupStageVolumeAck {
	ack.OK = false
	ack.Refusal = refusalFor(err)
	ack.Detail = err.Error()
	// A partially written stage never survives a refusal.
	ack.StagedPath, ack.SizeBytes, ack.Digest = "", 0, ""
	return ack
}

func validate(root string, cmd proto.BackupStageVolumeCmd) error {
	if strings.TrimSpace(root) == "" {
		return fmt.Errorf("%w: this agent has no staging root configured", ErrBadName)
	}
	if strings.TrimSpace(cmd.AppID) == "" {
		return fmt.Errorf("%w: the command names no app", ErrBadName)
	}
	if strings.TrimSpace(cmd.Volume) == "" {
		return fmt.Errorf("%w: the command names no volume", ErrBadName)
	}
	if !proto.BackupValidStagingName(cmd.StagingName) {
		// By SHAPE, never sanitised: the same predicate the write verb applies.
		return fmt.Errorf("%w: %q is not a plain file name", ErrBadName, cmd.StagingName)
	}
	if !tileschema.ValidBackupClass[cmd.Class] {
		return fmt.Errorf("%w: backup class %q is not one of %s", ErrBadName, cmd.Class, strings.Join(tileschema.BackupClasses, "|"))
	}
	if !tileschema.ValidQuiesce[cmd.Quiesce] {
		return fmt.Errorf("%w: quiesce strategy %q is not one of %s", ErrBadName, cmd.Quiesce, strings.Join(tileschema.QuiesceStrategies, "|"))
	}
	return nil
}

// Unstage removes one staged file by name. Only a regular file directly under
// the root, found by a validated name; a missing file is a success with
// Existed false so a retried command after a lost ack converges.
func (s *Stager) Unstage(cmd proto.BackupUnstageCmd) *proto.BackupUnstageAck {
	ack := &proto.BackupUnstageAck{StagingName: cmd.StagingName}
	if strings.TrimSpace(s.stagingRoot) == "" {
		ack.Refusal, ack.Detail = proto.BackupRefusalStagingMissing, "this agent has no staging root configured"
		return ack
	}
	if !proto.BackupValidStagingName(cmd.StagingName) {
		ack.Refusal, ack.Detail = proto.BackupRefusalStagingMissing, fmt.Sprintf("%q is not a plain file name", cmd.StagingName)
		return ack
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := filepath.Join(s.stagingRoot, cmd.StagingName)
	info, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		ack.OK = true
		return ack
	}
	if err != nil {
		ack.Refusal, ack.Detail = proto.StorageRefusalBackendError, err.Error()
		return ack
	}
	if !info.Mode().IsRegular() {
		ack.Refusal, ack.Detail = proto.StorageRefusalBackendError, fmt.Sprintf("%s is not a regular file; this verb removes only what the stage verb wrote", p)
		return ack
	}
	if err := os.Remove(p); err != nil {
		ack.Refusal, ack.Detail = proto.StorageRefusalBackendError, err.Error()
		return ack
	}
	ack.OK, ack.Existed, ack.FreedBytes = true, true, byteCount(info.Size())
	return ack
}

// humanBytes renders a size for an operator-facing refusal.
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}
