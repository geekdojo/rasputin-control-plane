package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The second half of the restore: becoming the restored cluster.
//
// # Why a restart, and why this runs before any store opens
//
// PrepareRestore ran inside an api that had rasputin.db open, a mesh CA
// loaded, an HTTPS leaf minted under that CA and a Headscale supervisor
// pointed at a state directory. Not one of those can be swapped under a
// running process: replacing a SQLite file beneath an open connection is
// corruption, and every subsystem that read the fresh CA at start would keep
// the fresh CA. So the api that prepared the restore does not apply it. It
// exits, the unit restarts it, and the NEW process applies the pending restore
// as its first act — before the bus, before the first OpenStore, before
// EnsureMeshCA — and then boots exactly as it would on any other start, onto
// the restored files.
//
// This is the self-update reconciler's shape (updater.ResumeSelfUpdates): work
// that spans the api's own restart is finished by the next process at
// startup, from durable state, rather than by a fresh Recover() failing it.
// The durable state here is a directory, not a job row, because the job
// ledger is INSIDE the file being replaced.
//
// # What the next start then does for free
//
// EnsureMeshCA loads the restored CA (it only generates when neither file
// exists). MintLeafToDisk re-mints the api's HTTPS leaf because the existing
// leaf no longer verifies against the CA (CheckSignatureFrom) — so the
// operator's device, which trusted the ORIGINAL CA before the re-flash,
// trusts the restored api's HTTPS again. The auth store opens the restored
// users and passkey credentials; the bus-token store opens the restored
// token hashes, so every node's existing join token validates on its next
// connect; the Headscale supervisor comes up on the restored state, so
// enrolled nodes stay enrolled. Nothing re-registers, re-enrolls or
// re-trusts. What the operator MUST still have right is the cluster id the
// box was flashed with (the RP ID passkeys bind to and the mDNS name nodes
// dial) — that lives in node.env, not in the archive, and the candidates
// response reports both so the UI can warn.
//
// # Leaving the partition as it found it
//
// The fresh install's own files are MOVED ASIDE, into restore-replaced-<ts>,
// not deleted, and every rename is recorded so a failure part-way is undone
// in reverse. A failed apply therefore leaves what it found; and a successful
// one leaves the fresh identity recoverable by hand.

// ErrRestoreApplyFailed wraps any failure to swap the restored files into
// place. The swap has been rolled back when this is returned.
var ErrRestoreApplyFailed = errors.New("applying the prepared restore failed; the data directory was left as it was")

// RestoreLayout says where the live identity files are, so the apply moves
// each staged file to the place the running api will read it from. Injected
// from main.go beside the same env variables that decide the paths.
type RestoreLayout struct {
	DataDir      string
	TrustDir     string
	MeshStateDir string
}

// restoreMove is one rename the apply performs, recorded for rollback.
type restoreMove struct{ from, to string }

// ApplyPendingRestore looks for a prepared restore under the data dir and, if
// one is there, swaps its files into place. It returns the report with
// AppliedAt set, and true, when a restore was applied; nil and false when
// there was nothing to do.
//
// MUST be called before any store opens the database, before the mesh CA is
// loaded and before the Headscale supervisor starts. An error is fatal to the
// start: a partition with a pending restore that could not be applied should
// not come up as a fresh cluster and silently offer first-run setup over the
// top of it.
func ApplyPendingRestore(layout RestoreLayout) (*RestoreReport, bool, error) {
	if strings.TrimSpace(layout.DataDir) == "" {
		return nil, false, nil
	}
	pending := filepath.Join(layout.DataDir, restorePendingDirName)
	st, err := os.Lstat(pending)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if !st.IsDir() {
		return nil, false, fmt.Errorf("%w: %s exists and is not a directory", ErrRestoreApplyFailed, pending)
	}
	report, err := readReport(filepath.Join(pending, restoreReportFile))
	if err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrRestoreApplyFailed, err)
	}
	if report.Phase != RestorePhase {
		return nil, false, fmt.Errorf("%w: the pending restore is phase %q; this build applies %q", ErrRestoreApplyFailed, report.Phase, RestorePhase)
	}

	now := time.Now().UTC()
	replaced := filepath.Join(layout.DataDir, restoreReplacedPrefix+now.Format("20060102T150405Z"))
	if err := os.Mkdir(replaced, 0o700); err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrRestoreApplyFailed, err)
	}

	trustDir := layout.TrustDir
	if trustDir == "" {
		trustDir = filepath.Join(layout.DataDir, "trust")
	}
	meshDir := layout.MeshStateDir
	if meshDir == "" {
		meshDir = filepath.Join(layout.DataDir, "mesh")
	}

	// Each staged path and where the live one lives. Only what the report
	// says was restored is moved; a dev archive with no CA leaves the fresh
	// CA in place, and the report says so by omission.
	type target struct {
		staged string // relative to pending
		live   string // absolute
		aside  string // relative to replaced
		isDir  bool
	}
	var targets []target
	restoredHeadscale := false
	for _, e := range report.Restored {
		switch {
		case e.Path == "rasputin.db":
			targets = append(targets, target{staged: "rasputin.db", live: filepath.Join(layout.DataDir, "rasputin.db"), aside: "rasputin.db"})
		case e.Path == "trust/mesh-ca.key":
			targets = append(targets, target{staged: "trust/mesh-ca.key", live: filepath.Join(trustDir, "mesh-ca.key"), aside: "trust/mesh-ca.key"})
		case e.Path == "trust/mesh-ca.pem":
			targets = append(targets, target{staged: "trust/mesh-ca.pem", live: filepath.Join(trustDir, "mesh-ca.pem"), aside: "trust/mesh-ca.pem"})
		case strings.HasPrefix(e.Path, "mesh/headscale/"):
			restoredHeadscale = true
		}
	}
	if restoredHeadscale {
		targets = append(targets, target{staged: "mesh/headscale", live: filepath.Join(meshDir, "headscale"), aside: "mesh/headscale", isDir: true})
	}
	// The mesh CA is a pair; EnsureMeshCA refuses a half. Restore both or
	// neither.
	hasKey, hasPem := false, false
	for _, t := range targets {
		hasKey = hasKey || t.staged == "trust/mesh-ca.key"
		hasPem = hasPem || t.staged == "trust/mesh-ca.pem"
	}
	if hasKey != hasPem {
		return nil, false, fmt.Errorf("%w: the restore holds one half of the mesh CA and not the other", ErrRestoreApplyFailed)
	}

	var done []restoreMove
	undo := func() {
		for i := len(done) - 1; i >= 0; i-- {
			_ = os.Rename(done[i].to, done[i].from)
		}
	}
	move := func(from, to string) error {
		if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
			return err
		}
		if err := os.Rename(from, to); err != nil {
			return err
		}
		done = append(done, restoreMove{from: from, to: to})
		return nil
	}
	for _, t := range targets {
		stagedPath := filepath.Join(pending, t.staged)
		if lst, lerr := os.Lstat(stagedPath); lerr != nil || (t.isDir && !lst.IsDir()) || (!t.isDir && !lst.Mode().IsRegular()) {
			undo()
			return nil, false, fmt.Errorf("%w: staged %s is missing or not a %s", ErrRestoreApplyFailed, t.staged, kindWord(t.isDir))
		}
		// The live file (or tree) moves aside, if it exists. SQLite's
		// sidecars go with the database: a restored snapshot has no WAL, and
		// a stale one from the fresh database must not be replayed into it.
		liveCandidates := []string{t.live}
		if t.staged == "rasputin.db" {
			liveCandidates = append(liveCandidates, t.live+"-wal", t.live+"-shm", t.live+"-journal")
		}
		for _, live := range liveCandidates {
			if _, lerr := os.Lstat(live); lerr == nil {
				aside := filepath.Join(replaced, t.aside+strings.TrimPrefix(live, t.live))
				if err := move(live, aside); err != nil {
					undo()
					return nil, false, fmt.Errorf("%w: move %s aside: %v", ErrRestoreApplyFailed, live, err)
				}
			}
		}
		if err := move(stagedPath, t.live); err != nil {
			undo()
			return nil, false, fmt.Errorf("%w: place %s: %v", ErrRestoreApplyFailed, t.staged, err)
		}
	}
	syncDir(layout.DataDir)
	syncDir(trustDir)
	syncDir(meshDir)

	report.AppliedAt = &now
	applied := filepath.Join(layout.DataDir, restoreAppliedDirName)
	_ = os.RemoveAll(applied)
	if err := os.Rename(pending, applied); err != nil {
		// The files are in place; only the bookkeeping failed. Not worth
		// undoing a restore over — say so and carry on.
		log.Printf("storage: restore applied but the pending directory could not be renamed to %s: %v", applied, err)
	} else if b, merr := json.MarshalIndent(report, "", "  "); merr == nil {
		_ = os.WriteFile(filepath.Join(applied, restoreReportFile), b, 0o600)
	}
	return report, true, nil
}

func kindWord(dir bool) string {
	if dir {
		return "directory"
	}
	return "regular file"
}

func syncDir(path string) {
	d, err := os.Open(path)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// readReport reads a restore.json, bounded.
func readReport(path string) (*RestoreReport, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxManifestBytes))
	if err != nil {
		return nil, err
	}
	var r RestoreReport
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("restore report is not readable JSON: %w", err)
	}
	if strings.TrimSpace(r.ID) == "" || strings.TrimSpace(r.GenerationID) == "" {
		return nil, errors.New("restore report names no id or no generation")
	}
	return &r, nil
}

// RecordAppliedRestore writes the report of an applied restore into the
// restored database and removes the applied directory. Idempotent: a report
// already recorded is not recorded twice, and a start with nothing applied
// does nothing. Called once the storage store is open — which, on the start
// that applied the restore, is the restored database.
func RecordAppliedRestore(ctx context.Context, st *Store, dataDir string) (*RestoreReport, error) {
	if st == nil || strings.TrimSpace(dataDir) == "" {
		return nil, nil
	}
	applied := filepath.Join(dataDir, restoreAppliedDirName)
	report, err := readReport(filepath.Join(applied, restoreReportFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if err := st.RecordRestore(ctx, report); err != nil {
		return nil, err
	}
	if err := os.RemoveAll(applied); err != nil {
		log.Printf("storage: restore %s recorded but %s could not be removed: %v", report.ID, applied, err)
	}
	return report, nil
}

// SweepRestoreStaging removes extraction directories a dying process left
// under the data dir. Called at start, after ApplyPendingRestore.
func SweepRestoreStaging(dataDir string) int {
	ents, err := os.ReadDir(dataDir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range ents {
		if e.IsDir() && strings.HasPrefix(e.Name(), restoreStagingPrefix) {
			if os.RemoveAll(filepath.Join(dataDir, e.Name())) == nil {
				n++
			}
		}
	}
	return n
}
