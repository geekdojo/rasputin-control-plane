package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// §4.7's staging path, and the source-side free-space guard that goes with it.
//
// # The problem this file exists for
//
// A backup.run assembles its archive on `/var/lib/rasputin` — the controlplane's
// single writable partition, the one §5's budget table is about, and the one
// with a real 100%-full incident on record (a 135 MB staged OS bundle filled
// the pre-growpart partition, 2026-06-21). §4.7 names the failure mode in one
// sentence: THE JOB THAT FILLS THE DISK IT IS PROTECTING. Everything below is
// aimed at that one sentence.
//
// # What is guarded, and how much
//
// A run materialises up to three things under the staging directory:
//
//	1. the `VACUUM INTO` snapshot of rasputin.db          ~ db size
//	2. one staged app-volume copy, from the agent          ~ largest volume
//	3. the fan-out's tar of the captured volumes           ~ volume total
//	4. the assembled tar (snapshot + identity + volumes)   ~ identity + volumes
//	5. the sealed archive                                  ~ identity + volumes
//
// (1) is deleted as soon as (4) is built, (2) as soon as it is copied into (3),
// (3) as soon as (4) has taken its members, and (4) as soon as (5) is sealed —
// so the true peak is lower. The guard sizes for the pessimistic case anyway,
// because an estimate that is optimistic about a disk-full failure is not a
// guard. So: peak ≈ dbSize + 2 × (identitySize + volumeSize) + largestVolume.
//
// The volume terms are ZERO until the fan-out has staged something, and that is
// not a gap in the estimate — it is the fact. A volume's size cannot be known
// before it is staged, so the fan-out re-runs this guard before EVERY stage
// with what it has measured, and records the volumes it refuses rather than
// taking the partition down.
//
// The reserve it must leave behind is StagingReserveBytes, and the number is
// not arbitrary: it is VictoriaMetrics' `-storage.minFreeDiskSpaceBytes=2GB`
// from §5. Below that VM stops accepting samples and the metrics store goes
// blind. §5 accepted that as a deliberate backstop against a wedged SQLite DB;
// it did not accept the weekly backup job as the thing that trips it. Refusing
// above the same line means a backup can never be the cause of an observability
// outage, and the operator gets a job failure naming both numbers instead.
//
// # What this is NOT, and what is left to #393
//
// This is the minimum that stops THIS job filling the disk. It is not the
// general facility #393 describes: there is no shared preflight every stager
// calls, no integration with the 85% DiskAlmostFull vmalert rule, no bound on
// Loki (which §5 records as having no free-space guard at all), and no
// cross-subsystem accounting of what else might stage concurrently. A second
// stager running at the same moment can still take the partition below the
// reserve between this check and the write — the check is a snapshot, not a
// lease. #393 is where a real reservation belongs.

// # Where the staging directory is, and why that is not decided here
//
// It used to be. This file resolved <dataDir>/backup-staging and the agent
// resolved <stateDir>/backup-staging, and the comment on each said the shared
// RASPUTIN_BACKUP_STAGING_DIR was what kept them pointed at one directory. That
// variable is set nowhere on the shipping image, so the default — the only
// configuration that ships — had the api sealing to
// /var/lib/rasputin/backup-staging and the agent looking in
// /var/lib/rasputin/agent-state/backup-staging. A 105 MB archive was built and
// refused, every run (e3bench 2026-09-02).
//
// So there is no api-side derivation any more. The agent owns the root — it is
// the containment boundary for the verb that reads it, and a boundary the
// caller names is not one — and reports it in BackupPreflightAck.StagingRoot,
// step 2, before this file's guard sizes anything. The functions below take the
// directory as an argument and never invent it. See the agent's StagingRoot.
//
// The directory is still excluded from the archive by construction: assemble
// walks an explicit list of identity files and never a directory tree that
// could contain this one. An archive that contains the previous archive is a
// straightforward way to fill a disk.

// StagingReserveBytes is the free space that must REMAIN on the staging
// partition after a run's estimated peak. See the file comment: it is §5's
// VictoriaMetrics reservation, so a backup cannot be the thing that blinds the
// metrics store.
//
// Derived from proto rather than typed here, because the agent applies the
// same reserve to its own staging root when it stages an app volume (#294):
// one number, so the two halves of §4.7's guard cannot drift.
const StagingReserveBytes uint64 = proto.BackupStagingReserveBytes // 2 GiB

// EnsureStagingDir creates the staging directory 0700. Owner-only because what
// passes through it is, for the seconds before it is sealed, a plaintext copy
// of every secret in the cluster.
func EnsureStagingDir(dir string) error { return os.MkdirAll(dir, 0o700) }

// CleanStaging removes orphaned staged files — §4.7's third discipline,
// "cleanup on failure and on boot". An orphaned staging file after a crash or a
// power cut is a permanent disk leak with no owner and no alert.
//
// Only regular files directly under the root: anything else was not put there
// by this package, and removing it is not this function's business.
func CleanStaging(dir string) (removed int, freed int64) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err == nil {
			removed++
			freed += info.Size()
		}
	}
	return removed, freed
}

// ErrStagingFull is the source-side refusal: this run's estimated peak would
// take the staging partition below StagingReserveBytes.
var ErrStagingFull = errors.New("storage: not enough free space to stage a backup archive")

// StagingBudget is the arithmetic of one run's peak, kept as a value so the
// numbers can be put in a log line and a step result rather than only in a
// comparison.
type StagingBudget struct {
	// DBBytes is the live rasputin.db's size — the floor on the snapshot.
	DBBytes uint64 `json:"dbBytes"`
	// IdentityBytes is the whole §4.5 identity set: the database plus the trust
	// directory plus Headscale state.
	IdentityBytes uint64 `json:"identityBytes"`
	// VolumeBytes is the app-volume data captured so far — the staged tars the
	// fan-out has already taken — and LargestVolumeBytes the biggest single one
	// of them.
	//
	// Both are zero at the top of a run, and they are not a guess that has not
	// been made yet: a volume's size is unknowable until it has been staged, so
	// the fan-out re-sizes before EVERY stage with what it has measured, and
	// refuses the rest rather than filling the disk. LargestVolumeBytes is
	// §4.7's peak term — the one staged copy that exists on the agent's root
	// alongside everything the api is holding.
	VolumeBytes        uint64 `json:"volumeBytes"`
	LargestVolumeBytes uint64 `json:"largestVolumeBytes"`
	// PeakBytes is the pessimistic simultaneous residency — see the file
	// comment for why it does not model the deletes.
	PeakBytes uint64 `json:"peakBytes"`
	// FreeBytes is what the staging partition had when this was computed.
	FreeBytes uint64 `json:"freeBytes"`
	// ReserveBytes is StagingReserveBytes, echoed so a refusal explains itself
	// without the reader having to know the constant.
	ReserveBytes uint64 `json:"reserveBytes"`
}

// Sufficient reports whether the run may proceed.
func (b StagingBudget) Sufficient() bool {
	need := b.PeakBytes + b.ReserveBytes
	if need < b.PeakBytes { // overflow: treat as never satisfiable
		return false
	}
	return b.FreeBytes >= need
}

// Explain renders the refusal an operator reads. Both numbers, always: "not
// enough space" is not actionable and "3.1 GiB free, needs 4.4 GiB" is.
func (b StagingBudget) Explain(dir string) string {
	return fmt.Sprintf("%s has %s free; staging this backup needs about %s (a %s identity set plus %s of app-volume data, "+
		"assembled and then sealed, alongside a staged copy of the largest single volume at %s) "+
		"while leaving the %s reserve that keeps the metrics store writable. Nothing was written, and the previous "+
		"generations on the backup target are untouched",
		dir, humanBytes(b.FreeBytes), humanBytes(b.PeakBytes+b.ReserveBytes),
		humanBytes(b.IdentityBytes), humanBytes(b.VolumeBytes), humanBytes(b.LargestVolumeBytes),
		humanBytes(b.ReserveBytes))
}

// PlanStaging sizes a run and checks the staging partition against it.
//
// identityBytes is the measured size of the §4.5 set and dbBytes the live
// database's size within it. volumeBytes is the app-volume data captured so far
// and largestVolumeBytes the biggest single volume among it — both zero before
// the fan-out has staged anything, and both re-supplied before every subsequent
// stage, because that is the only moment either number exists.
func PlanStaging(dir string, dbBytes, identityBytes, volumeBytes, largestVolumeBytes uint64) (StagingBudget, error) {
	free, err := FreeBytes(dir)
	if err != nil {
		return StagingBudget{}, err
	}
	b := StagingBudget{
		DBBytes:            dbBytes,
		IdentityBytes:      identityBytes,
		VolumeBytes:        volumeBytes,
		LargestVolumeBytes: largestVolumeBytes,
		// The payload is assembled once and sealed once, so it is resident
		// twice; the largest single staged volume is resident alongside both
		// for the length of one copy. See the file comment for why the deletes
		// are not modelled.
		PeakBytes:    dbBytes + 2*(identityBytes+volumeBytes) + largestVolumeBytes,
		FreeBytes:    free,
		ReserveBytes: StagingReserveBytes,
	}
	if !b.Sufficient() {
		return b, fmt.Errorf("%w: %s", ErrStagingFull, b.Explain(dir))
	}
	return b, nil
}

// SnapshotDB writes a consistent copy of the live database to dst with SQLite's
// `VACUUM INTO`, and returns its size.
//
// NEVER a file copy. The api is writing to this database continuously — jobs,
// events, the metrics ring — and `cp rasputin.db` on a WAL-mode database
// produces a file whose contents are a torn mixture of committed and
// uncommitted pages, with the -wal and -shm it needed left behind. It restores
// as corruption, and it does so silently, on restore day. `VACUUM INTO` runs
// inside a read transaction and writes a fully-formed, defragmented database
// that opens on its own with nothing beside it.
//
// It also compacts: the output is the live data without free pages, so it is
// usually smaller than the source. PlanStaging sizes from the SOURCE anyway,
// because "usually smaller" is not a guarantee to design a disk-full guard on.
//
// dst must not exist — SQLite refuses to overwrite, which is the behaviour we
// want: a stale snapshot from a crashed run must not be silently adopted as
// this run's.
func SnapshotDB(ctx context.Context, db *sql.DB, dst string) (uint64, error) {
	if db == nil {
		return 0, errors.New("no database handle to snapshot")
	}
	if _, err := os.Stat(dst); err == nil {
		return 0, fmt.Errorf("refusing to snapshot onto %s: it already exists, and adopting a previous run's leftover as this run's database is how a stale backup gets written", dst)
	}
	// Bound parameter rather than string interpolation: the path is ours, but
	// a quoted path assembled by hand is a class of bug this does not need to
	// be exposed to.
	if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, dst); err != nil {
		return 0, fmt.Errorf("VACUUM INTO %s: %w", dst, err)
	}
	info, err := os.Stat(dst)
	if err != nil {
		return 0, fmt.Errorf("snapshot %s: %w", dst, err)
	}
	return byteCount(info.Size()), nil
}

// humanBytes renders a size for an operator-facing message.
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

// byteCount narrows a signed byte count to uint64.
//
// One helper rather than a conversion at each site, and an explicit guard
// rather than a bare cast. A negative length is impossible for a regular file
// or a completed write — but if one ever arrived, a bare `uint64(n)` would turn
// it into roughly eighteen exabytes, and the staging guard's arithmetic would
// then be sizing a run against that number. Clamping to zero keeps a nonsense
// input reading as "nothing", which is the direction the guard's comparison
// fails safely in: a zero contribution can only make the estimate smaller and
// the refusal more likely, never the reverse.
func byteCount(n int64) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

// signedByteCount is byteCount's inverse, guarded the same way and for the same
// reason: a bare int64(n) on a uint64 above MaxInt64 wraps NEGATIVE, and a
// negative byte count in a size total reads as an archive that shrank. Nothing
// in this package can produce a value that large, which is exactly why the
// guard is cheap and the failure it prevents would be baffling.
func signedByteCount(n uint64) int64 {
	if n > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(n)
}

// joinStaging is stagedPath's form for a caller that already holds the root —
// the fan-out, which stages many files under one directory resolved once.
//
// The same two checks, in the same order, immediately before the join: the root
// must be absolute and already clean, and the name must be a single plain file
// name by proto.BackupValidStagingName — the SAME predicate the agent applies to
// what it is sent. Neither half can contribute a traversal, so the result is
// always a direct child of the staging root.
func joinStaging(dir, name string) string {
	if err := checkStagingRoot(dir); err != nil {
		return ""
	}
	if !proto.BackupValidStagingName(name) {
		return ""
	}
	return filepath.Join(dir, name)
}
