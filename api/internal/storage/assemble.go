package storage

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// §4.5's contents list, assembled — and, just as importantly, §4.5's contents
// list NOT assembled, recorded in writing.
//
// # What goes in
//
//	rasputin.db                 jobs, inventory, users + passkey credentials,
//	                            bus-token store, app declarations, mesh intents
//	<trustDir>/mesh-ca.{key,pem} the per-installation CA — without it every
//	                            operator device's installed trust is orphaned
//	<dataDir>/mesh/headscale/    tailnet identity; nodes stay enrolled
//
// Every one of those is a local file on the controlplane, which is the node
// with the claimed target mounted. That is why this slice is buildable today.
//
// # What goes in from the apps, and what does not
//
// §4.5 also calls for "app volumes classed `critical` or `state`, on any node".
// This build captures those volumes for every app installed ON THE
// CONTROLPLANE NODE — the fan-out step stages each one through the agent
// (proto.BackupStageVolumeCmd, #294), verifies the digest, copies the staged
// tar in, and unstages it before asking for the next. That works without any
// transport because the agent's staging root and the api's are the same
// directory on the same filesystem.
//
// It does NOT capture a volume on any other node. Nothing yet moves a staged
// copy off the node that made it — the per-node streaming path (#295) and the
// ingest endpoint (#296) are unbuilt — so a compute node's app data cannot
// travel. Nor `bulk`, which §4.7 streams direct rather than staging. Every one
// of those is RECORDED, by name, with its reason, in AppVolumeReport.Volumes.
// Silence is the one outcome that is not permitted.
//
// An archive that omits app data is not the backup a user assumes they have — a
// Vaultwarden vault is exactly the thing §4.2 classes `critical`. The defence
// against that misunderstanding is not a release note. It is that the scope is
// in the generation's directory name on the platter, in the sealed header, in
// the clear-text manifest, in the backup_runs row, in the job's own log lines,
// and in the UI — one exported constant behind all six. This file writes four
// of them.

// ManifestVersion is the manifest schema version. Bumped when a field changes
// meaning, so a restore reading a two-year-old generation knows what it has.
const ManifestVersion = 1

// IdentitySources says where on this controlplane the §4.5 identity set lives.
//
// Injected rather than derived from constants so the workflow is testable
// without a /var/lib/rasputin, and so the one place these paths are decided is
// main.go, next to where the same directories are created.
type IdentitySources struct {
	// TrustDir holds mesh-ca.key and mesh-ca.pem.
	TrustDir string
	// MeshStateDir is <dataDir>/mesh; its `headscale` subdirectory is the
	// tailnet state §4.5 lists.
	MeshStateDir string
}

// ManifestEntry is one file captured into an archive.
type ManifestEntry struct {
	// Path is the entry's path INSIDE the archive, which is also where a
	// restore puts it back relative to /var/lib/rasputin.
	Path      string `json:"path"`
	SizeBytes int64  `json:"sizeBytes"`
	// SHA256 is over the file's plaintext, so a restore can verify each member
	// after decrypting the whole. Lower-case hex.
	SHA256 string `json:"sha256"`
	// Note says what this file IS, in an operator's words. A manifest that
	// lists `trust/mesh-ca.key` and does not say it is the per-installation CA
	// is a manifest only its authors can read.
	Note string `json:"note,omitempty"`
}

// Manifest is the honest record of one generation, written in CLEAR TEXT beside
// the sealed archive and again inside it.
//
// The duplication is deliberate: the sidecar is readable by an operator holding
// the disk and no custody secret, and the copy inside the archive cannot be
// edited without breaking every AEAD tag. A restore path trusts the inner one;
// a human reads the outer one.
type Manifest struct {
	ManifestVersion int       `json:"manifestVersion"`
	GenerationID    string    `json:"generationId"`
	JobID           string    `json:"jobId,omitempty"`
	ClusterID       string    `json:"clusterId,omitempty"`
	CreatedAt       time.Time `json:"createdAt"`
	// Scope is the run's REACH — proto.BackupScopeControlplaneLocal for
	// everything this build writes. The single most important field in the
	// file, and the same string that is in the generation's directory name and
	// bound into the sealed header's AEAD additional data.
	Scope string `json:"scope"`
	// Complete is the run's OUTCOME: true only when every classified volume in
	// the cluster is actually in this archive. Separate from Scope because the
	// scope is minted before the fan-out has staged anything and cannot depend
	// on what it found — and stated as a boolean because a reader skimming JSON
	// for reassurance finds one before they find a string to interpret.
	//
	// A `controlplane-local` archive on a cluster whose only apps live on the
	// controlplane is complete. On a cluster with one app on a compute node it
	// is not, and appVolumes.volumes names which.
	Complete bool `json:"complete"`
	// Warning is prose, present on every manifest, and written to be understood
	// by somebody who has never read design/storage.md. It states the BUILD's
	// reach; appVolumes.summary states what this run did.
	Warning string `json:"warning,omitempty"`
	// KeyID names the §4.6 keypair the sealed archive beside this manifest is
	// encrypted to. An identifier — never key material, and there is no field
	// here for any.
	KeyID string `json:"keyId,omitempty"`
	// Entries is what was captured.
	Entries []ManifestEntry `json:"entries"`
	// AppVolumes is the fan-out's own record — every classified volume in the
	// cluster, captured or not, each with its size, digest, consistency,
	// downtime and (when not captured) its reason. Present on every manifest
	// even when it is empty, because a section that vanished when it found
	// nothing would make "no app volumes" and "nobody looked" identical.
	AppVolumes AppVolumeReport `json:"appVolumes"`
	// Excluded is §4.5's exclusion list, restated so a restore does not go
	// looking for observability data it was never given.
	Excluded []string `json:"excluded,omitempty"`
	// AppVolumeBytes is the sum of the CAPTURED volumes' staged tars.
	AppVolumeBytes uint64 `json:"appVolumeBytes"`
	// PlaintextBytes is the whole archive's payload: Entries' sizes plus
	// AppVolumeBytes.
	PlaintextBytes int64 `json:"plaintextBytes"`
}

// AppVolumeReport is the per-node volume fan-out's own record: what it
// captured, what it did not, and — for every one it did not — why, by name.
//
// A type of its own rather than a list of paths, because the whole risk this
// slice carries is somebody reading a generation and assuming their apps are in
// it. `"appVolumes": {"capturedCount": 2, "skippedCount": 1, "volumes": [...]}`
// is an answer. A missing key is not, and neither is a captured list with no
// record of what fell out of it.
type AppVolumeReport struct {
	// Captured is the `app/volume` identifier of every volume that went into
	// the archive, in the order it went in.
	Captured []string `json:"captured"`
	// CapturedCount is len(Captured), stated separately so a reader who skimmed
	// past an array still sees a number.
	CapturedCount int `json:"capturedCount"`
	// SkippedCount is how many CLASSIFIED volumes were not captured. Its
	// counterpart, and it is a peer field rather than a derived one because the
	// two together are the sentence: "two of three".
	SkippedCount int `json:"skippedCount"`
	// NodesConsulted is how many nodes the fan-out actually asked. One at most
	// in this build — the controlplane — and zero when nothing was eligible.
	NodesConsulted int `json:"nodesConsulted"`
	// Volumes is the per-volume record, captured and not, in the order the run
	// considered them. THE honest artefact: every classified volume in the
	// cluster appears exactly once, and one carrying Captured false carries a
	// Reason with it.
	Volumes []VolumeRecord `json:"volumes"`
	// AppsLeftDown names every app that was stopped to take a copy and did not
	// come back. §4.7 says that is worse than a failed backup, so it is a field
	// of its own and not something a reader has to find by scanning Volumes.
	AppsLeftDown []string `json:"appsLeftDown,omitempty"`
	// Reason is the STANDING caveat — what this build can and cannot reach,
	// unchanged from run to run. Summary is what THIS run did.
	Reason  string `json:"reason"`
	Summary string `json:"summary"`
	// BlockedBy is the machine-readable form of what holds the rest back.
	BlockedBy []string `json:"blockedBy,omitempty"`
}

// Complete reports whether every classified volume in the cluster was captured
// — which is what Manifest.Complete means and the only thing that earns it.
//
// It is a scan of the records rather than `SkippedCount == 0` restated, because
// the record list is what an operator can check by hand, and the boolean has to
// be the thing they would arrive at.
func (r AppVolumeReport) Complete() bool {
	for _, v := range r.Volumes {
		if !v.Captured {
			return false
		}
	}
	return true
}

// appVolumeFanOutReason is the STANDING caveat: what a generation from this
// build reaches, in one place, so the manifest, the job log, the api's HTTP
// surface and the UI all say the same words.
//
// It is about the BUILD, not about one run, which is why it says nothing about
// counts. The per-run facts are AppVolumeReport.Summary and Volumes.
const appVolumeFanOutReason = "This archive covers the CONTROLPLANE NODE only (scope `" + proto.BackupScopeControlplaneLocal + "`). " +
	"It contains the control-plane identity set — the database, the mesh CA and Headscale state — plus every volume classed " +
	"`critical` or `state` belonging to an app installed ON THE CONTROLPLANE. " +
	"design/storage.md §4.5 calls for those volumes on ANY node, and app volumes on a compute node are NOT in here: nothing " +
	"yet moves a staged copy off the node that made it (geekdojo/geekdojo-brain#295 per-node streaming, #296 ingest). " +
	"`bulk` volumes stream direct (§4.7) and are not in here either; `cache` volumes are never copied by design. " +
	"Every volume that was not captured is listed by name, with its reason, under `appVolumes.volumes` — and `complete` is " +
	"false whenever that list is not empty. Read it before assuming an app's data is in this archive."

// AppVolumeFanOutReason is the fan-out's standing prose, exported so the api's
// HTTP surface and the UI say the SAME words as the manifest on the platter and
// the warning in the job feed.
//
// One string in one place, deliberately. The risk this slice carries is an
// operator believing a generation contains their app data; six paraphrases of
// the caveat, drifting apart, is how one of them eventually says something
// weaker than the truth.
func AppVolumeFanOutReason() string { return appVolumeFanOutReason }

// summarize renders what THIS run did, in one sentence, for the job feed and
// the manifest.
func summarize(r AppVolumeReport) string {
	if len(r.Volumes) == 0 {
		return "No app on this cluster declares a volume classed `critical`, `state` or `bulk`, so there was no app data to capture."
	}
	if r.Complete() {
		return fmt.Sprintf("Captured %d of %d classified app volume(s) — every one this cluster has.", r.CapturedCount, len(r.Volumes))
	}
	return fmt.Sprintf("Captured %d of %d classified app volume(s); %d were NOT captured and are listed by name with their reason.",
		r.CapturedCount, len(r.Volumes), r.SkippedCount)
}

// NewAppVolumeReport assembles a report from the fan-out's per-volume records.
//
// The counts are derived here, once, rather than incremented at each call site:
// a CapturedCount that disagreed with the records is the exact failure this
// structure exists to make impossible.
func NewAppVolumeReport(records []VolumeRecord, nodesConsulted int) AppVolumeReport {
	r := AppVolumeReport{
		Captured:       []string{},
		Volumes:        records,
		NodesConsulted: nodesConsulted,
		Reason:         appVolumeFanOutReason,
	}
	if r.Volumes == nil {
		r.Volumes = []VolumeRecord{}
	}
	for _, v := range r.Volumes {
		if v.Captured {
			r.Captured = append(r.Captured, v.App+"/"+v.Volume)
			continue
		}
		r.SkippedCount++
		if !v.AppRestored {
			r.AppsLeftDown = append(r.AppsLeftDown, v.App)
		}
	}
	r.CapturedCount = len(r.Captured)
	r.Summary = summarize(r)
	if !r.Complete() {
		// #292 (schema), #293 (classification) and #294 (the agent's staging
		// verb) are NOT here: each shipped, and naming a closed issue would
		// send an operator looking in the wrong place for what holds their app
		// data out of the archive.
		r.BlockedBy = []string{
			"geekdojo/geekdojo-brain#295 per-node streaming (off-node and `bulk` volumes)",
			"geekdojo/geekdojo-brain#296 ingest endpoint (off-node volumes)",
		}
	}
	return r
}

// identityExclusions is §4.5's "Excluded" column, restated in the manifest.
var identityExclusions = []string{
	"app volumes on any node other than the controlplane (see appVolumes — each is listed by name with its reason)",
	"`cache`-class volumes (regenerable index, queue and model caches) — §4.2 says these are never copied, on any node",
	"`bulk`-class volumes — §4.7 streams these direct rather than staging them; each is listed by name under appVolumes",
	"the bundle store (`bundles/`) — re-downloadable",
	"observability data (`vm-data/`, Loki) — re-accumulates",
	"IDS JSONL — bounded and re-accumulates",
	"the backup staging directory itself — an archive containing the previous archive fills disks",
}

// MeasureIdentitySet reports the total size of the §4.5 identity set on disk,
// before anything has been snapshotted.
//
// Used by the staging guard and by the target preflight estimate, so both are
// sized from measurement rather than from a guess. Missing files count zero
// rather than erroring: a mesh-less dev install genuinely has no Headscale
// state, and the estimate is not the place to refuse over it.
func MeasureIdentitySet(src IdentitySources, dbBytes uint64) uint64 {
	total := dbBytes
	for _, f := range trustFiles(src) {
		if info, err := os.Stat(f.abs); err == nil && info.Mode().IsRegular() {
			total += byteCount(info.Size())
		}
	}
	_ = filepath.WalkDir(headscaleDir(src), func(p string, d fs.DirEntry, err error) error {
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

type trustFile struct {
	abs  string
	arc  string
	note string
}

func trustFiles(src IdentitySources) []trustFile {
	if strings.TrimSpace(src.TrustDir) == "" {
		return nil
	}
	return []trustFile{
		{
			abs:  filepath.Join(src.TrustDir, "mesh-ca.key"),
			arc:  "trust/mesh-ca.key",
			note: "the per-installation mesh CA's PRIVATE key — without it every operator device's installed trust is orphaned after a restore",
		},
		{
			abs:  filepath.Join(src.TrustDir, "mesh-ca.pem"),
			arc:  "trust/mesh-ca.pem",
			note: "the per-installation mesh CA certificate",
		},
	}
}

func headscaleDir(src IdentitySources) string {
	if strings.TrimSpace(src.MeshStateDir) == "" {
		return ""
	}
	return filepath.Join(src.MeshStateDir, "headscale")
}

// AssembleOptions is one call to Assemble.
type AssembleOptions struct {
	Sources IdentitySources
	// SnapshotPath is the `VACUUM INTO` output from step 3 — never the live
	// database file. Assemble refuses an empty one rather than producing an
	// archive with no database in it, which would restore as an appliance with
	// no users, no nodes and no apps.
	SnapshotPath string
	GenerationID string
	JobID        string
	ClusterID    string
	KeyID        string
	Now          time.Time
	// AppVolumes is the fan-out step's finished record: every classified volume
	// in the cluster, captured or not, with its reason. Assemble does not run
	// the fan-out — it happened before this call, one volume at a time, because
	// staging a volume STOPS AN APP and that is not something an archive writer
	// should be doing behind its caller.
	AppVolumes AppVolumeReport
	// VolumesTar is the tar of captured volume members the fan-out built, whose
	// members are copied into this archive verbatim. Empty when nothing was
	// captured, and Assemble then produces exactly what it produced before app
	// volumes existed.
	VolumesTar string
	// Scope is the run's scope, minted at step 1 and stamped into the
	// generation id. Passed in rather than read from a constant here so the id
	// on the platter and the scope inside the seal can never be two different
	// decisions.
	Scope string
}

// Assemble writes the identity set plus the manifest to dst as a tar, and
// returns the manifest.
//
// Uncompressed, deliberately. The set is a SQLite database (already compact
// after `VACUUM INTO`), two PEM files and Headscale's state; compression would
// buy little, and it would put a second CPU pass in front of the seal on
// hardware §4.6 already flags as compute-bound. The knob to reach for when
// archives get big is §4.7's staging, not gzip here.
//
// The manifest is the FIRST entry in the tar. That is a real property, not
// aesthetics: a reader streaming a decrypted archive learns the scope, the
// completeness and the whole per-volume record before it has read a single byte
// of payload, so a restore can refuse an archive it was told was complete
// without buffering the lot. It is also why the fan-out runs in its own step
// BEFORE this one — the manifest cannot go first and also describe volumes
// nobody has staged yet.
//
// Layout, and it is the contract the restore side (#291, unbuilt) will read:
//
//	manifest.json                         the record, first
//	rasputin.db                           the §4.5 identity set
//	trust/mesh-ca.{key,pem}
//	mesh/headscale/...
//	app-volumes/<app>/<volume>.tar        one member per captured volume
//
// A per-volume member whose NAME carries the app and the volume, rather than a
// flattened tree: a restore should never have to guess which file belonged to
// which app, and an operator holding a decrypted archive should be able to see
// what they have with `tar tf`.
func Assemble(dst io.Writer, opts AssembleOptions) (*Manifest, error) {
	if strings.TrimSpace(opts.SnapshotPath) == "" {
		return nil, fmt.Errorf("refusing to assemble generation %s: no database snapshot was produced, and an archive without rasputin.db restores as an appliance with no users, no nodes and no apps", opts.GenerationID)
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	// Sources, in archive order. The database first because it is the thing a
	// restore cannot proceed without.
	type member struct {
		abs  string
		arc  string
		note string
		// required marks a file whose absence fails the assembly rather than
		// being recorded as absent.
		required bool
	}
	members := []member{{
		abs:      opts.SnapshotPath,
		arc:      "rasputin.db",
		note:     "consistent snapshot of the control-plane database via SQLite VACUUM INTO — jobs, inventory, users and passkey credentials, the bus-token store, app declarations and mesh intents",
		required: true,
	}}
	for _, f := range trustFiles(opts.Sources) {
		members = append(members, member{abs: f.abs, arc: f.arc, note: f.note})
	}
	hsDir := headscaleDir(opts.Sources)
	if hsDir != "" {
		var found []member
		err := filepath.WalkDir(hsDir, func(p string, d fs.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			if d.IsDir() {
				return nil
			}
			info, ierr := d.Info()
			if ierr != nil || !info.Mode().IsRegular() {
				// Sockets, symlinks and devices are not state a restore can put
				// back; skipping them is correct, and skipping them SILENTLY
				// would not be — the manifest's entry list is the record of what
				// was taken, so what is absent from it is absent from the archive.
				return nil //nolint:nilerr // a non-regular file is skipped, not an assembly failure
			}
			rel, rerr := filepath.Rel(hsDir, p)
			if rerr != nil {
				return rerr
			}
			found = append(found, member{
				abs:  p,
				arc:  path.Join("mesh/headscale", filepath.ToSlash(rel)),
				note: "Headscale state — tailnet identity; nodes stay enrolled after a restore",
			})
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("walk headscale state at %s: %w", hsDir, err)
		}
		sort.Slice(found, func(i, j int) bool { return found[i].arc < found[j].arc })
		members = append(members, found...)
	}

	// The fan-out already ran, one volume at a time, in its own step. What
	// arrives here is its finished record — see AppVolumeReport.
	fanOut := opts.AppVolumes
	if fanOut.Volumes == nil {
		// A caller that ran no fan-out at all gets an empty-but-present
		// section rather than a missing key: "no app volumes" and "nobody
		// looked" must not render identically.
		fanOut = NewAppVolumeReport(nil, 0)
	}
	scope := strings.TrimSpace(opts.Scope)
	if scope == "" {
		scope = proto.BackupScopeControlplaneLocal
	}

	m := &Manifest{
		ManifestVersion: ManifestVersion,
		GenerationID:    opts.GenerationID,
		JobID:           opts.JobID,
		ClusterID:       opts.ClusterID,
		CreatedAt:       now,
		Scope:           scope,
		// Complete is the OUTCOME, and the scope is the REACH. They are
		// separate on purpose: the scope is minted at step 1, before a volume
		// has been staged, so it cannot depend on what the run found. Complete
		// can, and it is true only when every classified volume in the cluster
		// is in this archive.
		Complete:   fanOut.Complete(),
		Warning:    appVolumeFanOutReason,
		KeyID:      opts.KeyID,
		AppVolumes: fanOut,
		Excluded:   identityExclusions,
	}

	// Pass one: hash and size everything, so the manifest that goes in FIRST is
	// already complete. Reading twice is the price of a manifest a streaming
	// reader can trust before it has seen the payload, and the identity set is
	// small enough for that to be the right trade.
	for _, mem := range members {
		info, err := os.Stat(mem.abs)
		if err != nil {
			if mem.required {
				return nil, fmt.Errorf("assemble %s: %w", mem.arc, err)
			}
			// Absent, and that is legitimate: a dev install with no mesh has no
			// CA. It is simply not in Entries, which is the manifest saying so.
			continue
		}
		sum, err := fileSHA256(mem.abs)
		if err != nil {
			return nil, fmt.Errorf("hash %s: %w", mem.arc, err)
		}
		m.Entries = append(m.Entries, ManifestEntry{
			Path: mem.arc, SizeBytes: info.Size(), SHA256: sum, Note: mem.note,
		})
		m.PlaintextBytes += info.Size()
	}
	// The captured volumes' bytes count towards the archive's plaintext size
	// too — an operator comparing `plaintextBytes` with the sealed file's
	// length should not find the app data missing from one side of it.
	for _, v := range m.AppVolumes.Volumes {
		if v.Captured {
			m.AppVolumeBytes += v.SizeBytes
		}
	}
	m.PlaintextBytes += signedByteCount(m.AppVolumeBytes)

	manifestJSON, err := m.JSON()
	if err != nil {
		return nil, err
	}

	tw := tar.NewWriter(dst)
	if err := writeTarBytes(tw, proto.BackupManifestFile, manifestJSON, now); err != nil {
		return nil, err
	}
	for _, e := range m.Entries {
		abs := ""
		for _, mem := range members {
			if mem.arc == e.Path {
				abs = mem.abs
				break
			}
		}
		if abs == "" {
			return nil, fmt.Errorf("internal: no source for manifest entry %s", e.Path)
		}
		if err := writeTarFile(tw, e.Path, abs, e.SizeBytes, now); err != nil {
			return nil, err
		}
	}
	// The captured app volumes, last, copied member-for-member out of the tar
	// the fan-out built.
	//
	// Copied rather than concatenated: a tar IS a concatenation of member
	// blocks, so appending the fan-out's file raw would be cheaper — and it
	// would make this function's output depend on a second file being a valid,
	// trailer-less fragment. A member-by-member copy costs one pass over data
	// already on the same disk and leaves Assemble producing a complete,
	// self-contained tar, which is what every caller and every future restore
	// reads it as.
	if err := copyVolumeMembers(tw, opts.VolumesTar, m.AppVolumes); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return m, nil
}

// JSON renders the manifest for the sidecar and for the tar entry — the same
// bytes in both places, so the clear-text copy an operator reads and the
// authenticated copy inside the archive can never disagree.
func (m *Manifest) JSON() ([]byte, error) {
	// Indented: a human reads the sidecar off a disk with `cat`, and the
	// warning should be legible there without a JSON formatter to hand.
	return json.MarshalIndent(m, "", "  ")
}

func writeTarBytes(tw *tar.Writer, name string, b []byte, now time.Time) error {
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Mode: 0o600, Size: int64(len(b)), ModTime: now, Typeflag: tar.TypeReg,
	}); err != nil {
		return err
	}
	_, err := tw.Write(b)
	return err
}

// writeTarFile copies one file in, refusing if it changed size since it was
// hashed.
//
// The size check matters because the manifest already committed to a digest: a
// file that grew between pass one and pass two would produce an archive whose
// own manifest does not verify, and the discovery would happen on restore day.
// Failing the run instead costs a re-run tonight.
func writeTarFile(tw *tar.Writer, name, abs string, size int64, now time.Time) error {
	f, err := os.Open(abs)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() != size {
		return fmt.Errorf("%s changed size while the archive was being built (%d → %d); refusing to write an archive whose own manifest does not verify",
			name, size, info.Size())
	}
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Mode: 0o600, Size: size, ModTime: now, Typeflag: tar.TypeReg,
	}); err != nil {
		return err
	}
	n, err := io.Copy(tw, io.LimitReader(f, size))
	if err != nil {
		return err
	}
	if n != size {
		return fmt.Errorf("%s: wrote %d of %d bytes", name, n, size)
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
