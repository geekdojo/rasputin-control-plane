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

	"github.com/geekdojo/rasputin-control-plane/api/internal/appsecret"
	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
)

// The second half of the restore: becoming the restored cluster.
//
// # Why a restart, and why this runs before any store opens
//
// PrepareRestore ran inside an api that had rasputin.db open, a controlplane CA
// loaded, an HTTPS leaf minted under that CA and a Headscale supervisor
// pointed at a state directory. Not one of those can be swapped under a
// running process: replacing a SQLite file beneath an open connection is
// corruption, and every subsystem that read the fresh CA at start would keep
// the fresh CA. So the api that prepared the restore does not apply it. It
// exits, the unit restarts it, and the NEW process applies the pending restore
// as its first act — before the bus, before the first OpenStore, before
// tlsca.Ensure — and then boots exactly as it would on any other start, onto
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
// tlsca.Ensure loads the restored CA (it only generates when neither file
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
	// BusDir holds bus.key; <DataDir>/bus when empty.
	BusDir string
}

// restoreMove is one rename the apply performs, recorded for rollback.
type restoreMove struct{ from, to string }

// restoreDirs are the live directories an apply rule resolves its path in,
// with RestoreLayout's defaults already filled in.
type restoreDirs struct{ data, trust, mesh, bus string }

// applyKind is what the apply does with a restored entry.
type applyKind int

const (
	// applyReplace moves the live file aside and the staged file in.
	applyReplace applyKind = iota
	// applyReplaceTree does the same for a whole directory, once, however
	// many of its members the report lists.
	applyReplaceTree
	// applyMerge is not moved into place: it is merged after every move has
	// succeeded.
	applyMerge
	// applyStoreUnit is the secret store's data and seal files, matched by
	// prefix. The api moves none of them: the store unit's root pre-start
	// step does (#766), before the api starts, and leaves
	// restore-pending/store/applied when it has (S15 part 5).
	applyStoreUnit
)

// applyRule is one row of the restore's placement table: an archive path, or
// a directory prefix ending in "/" for a tree, and where its live copy is.
type applyRule struct {
	archive string
	kind    applyKind
	live    func(restoreDirs) string
}

// matches is the one test of whether a rule handles an archive member: exact,
// or by prefix for a tree rule. ApplyPendingRestore and the coverage gate in
// restore_coverage_test.go both match through it.
func (r applyRule) matches(p string) bool {
	if r.kind == applyReplaceTree || r.kind == applyStoreUnit {
		return strings.HasPrefix(p, r.archive)
	}
	return p == r.archive
}

// matchRule returns the first rule that handles path.
func matchRule(rules []applyRule, path string) (applyRule, bool) {
	for _, r := range rules {
		if r.matches(path) {
			return r, true
		}
	}
	return applyRule{}, false
}

// identityApplyRules is where each restored identity-archive member goes. A
// member that no row matches is refused by ApplyPendingRestore, and
// TestEveryIdentityMemberHasARestorePath fails when Assemble writes a member
// that no row (or identityRestorePath) handles. A fresh slice every call, so
// nothing can mutate the table under a running restore.
func identityApplyRules() []applyRule {
	return []applyRule{
		{archive: "rasputin.db", kind: applyReplace, live: func(d restoreDirs) string { return filepath.Join(d.data, "rasputin.db") }},
		{archive: "trust/mesh-ca.key", kind: applyReplace, live: func(d restoreDirs) string { return filepath.Join(d.trust, "mesh-ca.key") }},
		{archive: "trust/mesh-ca.pem", kind: applyReplace, live: func(d restoreDirs) string { return filepath.Join(d.trust, "mesh-ca.pem") }},
		// The restored seed replaces the one this fresh install generated at
		// its first start (#520). Without this row the entry is staged,
		// reported as restored, and then refused — and without the refusal
		// the cluster would come up with a seed that derives a different value
		// for every app secret in it, while each app's data volume still holds
		// the one it was given. There is no way back from that: nothing can
		// re-derive the old values, so the apps' credentials are simply lost.
		// Assemble captures it and this puts it back; the pair is the whole
		// feature, which is why they landed in one change.
		{archive: appSecretSeedArchivePath, kind: applyReplace, live: func(d restoreDirs) string { return filepath.Join(d.trust, appsecret.SeedFileName) }},
		// The restored key replaces the one this fresh install generated, so
		// every node that pinned the original joins again (#448).
		{archive: busKeyArchivePath, kind: applyReplace, live: func(d restoreDirs) string { return filepath.Join(d.bus, "bus.key") }},
		// Put back beside the key, so the restored bus serves the same
		// certificate it served before. If it is absent, or if it does not
		// match the key that landed, EnsureCert re-mints it at the next start.
		{archive: busCertArchivePath, kind: applyReplace, live: func(d restoreDirs) string { return filepath.Join(d.bus, bustls.CertFileName) }},
		// Not moved into place: merged, after every move has succeeded.
		{archive: busTombstonesArchivePath, kind: applyMerge, live: func(d restoreDirs) string { return filepath.Join(d.bus, busauth.TombstoneFileName) }},
		{archive: "mesh/headscale/", kind: applyReplaceTree, live: func(d restoreDirs) string { return filepath.Join(d.mesh, "headscale") }},
		// The store CA, placed by the api with move-aside and rollback like
		// the controlplane CA (#765). The store picks it up through the leaf
		// sweep's re-mint, which restarts the store. #766's hook must not
		// move it.
		{archive: storeCAKeyArchivePath, kind: applyReplace, live: func(d restoreDirs) string { return filepath.Join(d.trust, tlsca.StoreKeyFile) }},
		{archive: storeCACertArchivePath, kind: applyReplace, live: func(d restoreDirs) string { return filepath.Join(d.trust, tlsca.StoreCertFile) }},
		// The store's data, seal key, seal fragment and version member:
		// staged, and applied by the store unit's own start step, never
		// moved by the api.
		{archive: storeUnitArchivePrefix, kind: applyStoreUnit},
	}
}

// caPairs are the identity files that are restored both or neither:
// tlsca.Ensure refuses half a CA.
var caPairs = []struct{ key, cert, name string }{
	{key: "trust/mesh-ca.key", cert: "trust/mesh-ca.pem", name: "controlplane CA"},
	{key: storeCAKeyArchivePath, cert: storeCACertArchivePath, name: "store CA"},
}

// errStoreNotApplied is the start-time refusal when a staged store restore
// was not applied by the store unit's own start step.
const errStoreNotApplied = "the restore staged the secret store, and the store's own start step has not applied it, so this api refuses to start on a fresh store. " +
	"Reboot the control plane to apply it. If this message returns after a reboot, the store's apply step failed: the openbao.service journal names why; restore-pending/ is untouched"

// ApplyPendingRestore looks for a prepared restore under the data dir and, if
// one is there, swaps its files into place. It returns the report with
// AppliedAt set, and true, when a restore was applied; nil and false when
// there was nothing to do.
//
// MUST be called before any store opens the database, before the controlplane CA is
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

	dirs := restoreDirs{data: layout.DataDir, trust: layout.TrustDir, mesh: layout.MeshStateDir, bus: layout.BusDir}
	if dirs.trust == "" {
		dirs.trust = filepath.Join(layout.DataDir, "trust")
	}
	if dirs.mesh == "" {
		dirs.mesh = filepath.Join(layout.DataDir, "mesh")
	}
	if dirs.bus == "" {
		dirs.bus = filepath.Join(layout.DataDir, "bus")
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
	var targets, trees []target
	treeSeen := map[string]bool{}
	var merges []applyRule
	storeStaged := false
	rules := identityApplyRules()
	for _, e := range report.Restored {
		r, ok := matchRule(rules, e.Path)
		if !ok {
			// Refused, not skipped: an entry the report calls restored that
			// nothing puts back would come up as a green restore with the
			// fresh install's file in its place.
			return nil, false, fmt.Errorf("%w: the restore lists %s but this build has no rule to put it back", ErrRestoreApplyFailed, e.Path)
		}
		staged := strings.TrimSuffix(r.archive, "/")
		switch r.kind {
		case applyReplace:
			targets = append(targets, target{staged: staged, live: r.live(dirs), aside: staged})
		case applyReplaceTree:
			// The whole tree moves once, however many members it held.
			if !treeSeen[r.archive] {
				treeSeen[r.archive] = true
				trees = append(trees, target{staged: staged, live: r.live(dirs), aside: staged, isDir: true})
			}
		case applyMerge:
			merges = append(merges, r)
		case applyStoreUnit:
			storeStaged = true
		}
	}
	targets = append(targets, trees...)
	// Each CA is a pair; tlsca.Ensure refuses a half. Restore both or
	// neither.
	for _, pair := range caPairs {
		hasKey, hasPem := false, false
		for _, t := range targets {
			hasKey = hasKey || t.staged == pair.key
			hasPem = hasPem || t.staged == pair.cert
		}
		if hasKey != hasPem {
			return nil, false, fmt.Errorf("%w: the restore holds one half of the %s and not the other", ErrRestoreApplyFailed, pair.name)
		}
	}
	// A staged store restore the store's own start step did not apply is
	// fatal: coming up would put a restored database over a fresh store
	// (S15 part 5).
	if storeStaged {
		marker := filepath.Join(pending, strings.TrimSuffix(storeUnitArchivePrefix, "/"), storeAppliedMarkerName)
		if st, err := os.Lstat(marker); err != nil || !st.Mode().IsRegular() {
			return nil, false, fmt.Errorf("%w: %s", ErrRestoreApplyFailed, errStoreNotApplied)
		}
	}

	// Created only once every entry has a rule and the CA pair is whole, so a
	// refusal above leaves nothing behind.
	now := time.Now().UTC()
	replaced := filepath.Join(layout.DataDir, restoreReplacedPrefix+now.Format("20060102T150405Z"))
	if err := os.Mkdir(replaced, 0o700); err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrRestoreApplyFailed, err)
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
	syncDir(dirs.data)
	syncDir(dirs.trust)
	syncDir(dirs.mesh)
	syncDir(dirs.bus)

	// Revocation tombstones are the one identity file a restore never
	// replaces: the archive's are UNIONED into the live file, which may hold
	// revocations made after the archive was taken. The next start re-applies
	// the whole set to the restored database (busauth.UseTombstoneFile), so
	// restoring an older archive cannot un-revoke a token. A failed merge does
	// not fail the restore: the live file is untouched and still re-applied,
	// and the archive's own revocations are rows in the restored database,
	// which that same start adds back to the file.
	for _, r := range merges {
		live := r.live(dirs)
		if added, err := busauth.MergeTombstoneFiles(live, filepath.Join(pending, r.archive)); err != nil {
			log.Printf("storage: restore: merging the archive's bus-token tombstones into %s: %v — the live tombstones are unchanged and are re-applied at this start", live, err)
		} else if added > 0 {
			log.Printf("storage: restore: merged %d bus-token revocation tombstone(s) from the archive into %s", added, live)
		}
	}

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
