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
// # What does not, and why it is the loudest thing in this file
//
// §4.5 also calls for "app volumes classed `critical` or `state`, on any node".
// NO VOLUME ANYWHERE CARRIES A CLASS. The tileschema fields that would declare
// one (#292), the catalog classification that would populate them (#293), the
// quiesce drivers that would make a copy safe (#294), the streaming path (#295)
// and the ingest endpoint (#296) are all unbuilt. So the per-node fan-out below
// is DECLARED AND EMPTY: it runs, it enumerates nothing, and it writes down
// that it enumerated nothing and why.
//
// An archive that omits app data is not the backup a user assumes they have — a
// Vaultwarden vault is exactly the thing §4.2 classes `critical`, and it is not
// in here. The defence against that misunderstanding is not a release note. It
// is that the scope is in the generation's directory name on the platter, in
// the sealed header, in the clear-text manifest, in the backup_runs row, in the
// job's own log lines, and in the UI. This file writes four of those six.

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
	// Scope is proto.BackupScopeIdentityOnly or proto.BackupScopeFull. The
	// single most important field in the file.
	Scope string `json:"scope"`
	// Complete is Scope == full, restated as a boolean because a reader
	// skimming JSON for reassurance finds a boolean before they find a string
	// they have to interpret.
	Complete bool `json:"complete"`
	// Warning is prose, present whenever Complete is false, and written to be
	// understood by somebody who has never read design/storage.md.
	Warning string `json:"warning,omitempty"`
	// KeyID names the §4.6 keypair the sealed archive beside this manifest is
	// encrypted to. An identifier — never key material, and there is no field
	// here for any.
	KeyID string `json:"keyId,omitempty"`
	// Entries is what was captured.
	Entries []ManifestEntry `json:"entries"`
	// AppVolumes is the fan-out's own record. Present on every manifest, with
	// Captured empty, because a section that vanished when it found nothing
	// would make "no app volumes" and "this build does not do app volumes" look
	// identical.
	AppVolumes AppVolumeReport `json:"appVolumes"`
	// Excluded is §4.5's exclusion list, restated so a restore does not go
	// looking for observability data it was never given.
	Excluded []string `json:"excluded,omitempty"`
	// PlaintextBytes is the sum of Entries' sizes.
	PlaintextBytes int64 `json:"plaintextBytes"`
}

// AppVolumeReport is the declared-but-empty per-node volume fan-out.
//
// A type of its own rather than an omitted field, because the whole risk this
// slice carries is somebody reading a generation and assuming their apps are in
// it. `"appVolumes": {"captured": [], "capturedCount": 0, "reason": "..."}` is
// an answer. A missing key is not.
type AppVolumeReport struct {
	// Captured is the volumes that went into the archive. Empty on every
	// generation this build writes.
	Captured []string `json:"captured"`
	// CapturedCount is len(Captured), stated separately so a reader who
	// skimmed past an empty array still sees a zero.
	CapturedCount int `json:"capturedCount"`
	// NodesConsulted is how many nodes the fan-out asked. Zero here: with no
	// classification to act on there is nothing to ask them, and pretending to
	// have asked would be worse than saying we did not.
	NodesConsulted int `json:"nodesConsulted"`
	// Reason says WHY, in full, and names the issues that will change it. It is
	// the sentence an operator reads on the day they discover their app data is
	// not in the archive, and it should answer them completely at that moment.
	Reason string `json:"reason"`
	// BlockedBy is the machine-readable form of the same thing.
	BlockedBy []string `json:"blockedBy,omitempty"`
}

// appVolumeFanOutReason is the prose above, in one place, so the manifest, the
// job log and the UI all say the same words.
const appVolumeFanOutReason = "No app volumes were captured. design/storage.md §4.5 requires every volume " +
	"classed `critical` or `state` on any node, but no volume anywhere carries a backup class yet: the tileschema " +
	"fields that declare one (#292), the catalog classification that fills them in (#293), the quiesce drivers that " +
	"make a copy safe (#294), the per-node streaming path (#295) and the ingest endpoint (#296) are all unbuilt. " +
	"This archive therefore restores the controlplane's identity — the database, the mesh CA and Headscale state — " +
	"and NOT the data belonging to any installed app, including a password vault. It is not a complete backup."

// AppVolumeFanOutReason is the fan-out's prose, exported so the api's HTTP
// surface and the UI say the SAME words as the manifest on the platter and the
// warning in the job feed.
//
// One string in one place, deliberately. The risk this slice carries is an
// operator believing a generation contains their app data; six paraphrases of
// the caveat, drifting apart, is how one of them eventually says something
// weaker than the truth.
func AppVolumeFanOutReason() string { return appVolumeFanOutReason }

// FanOutAppVolumes is §4.5's per-node volume phase. It runs on every backup and
// captures nothing.
//
// A function rather than a comment, and called rather than skipped, because the
// shape of the thing that is missing should be visible in the code that will
// eventually contain it. When #293 lands, this is where the classified volumes
// come from and this is the report that stops being empty; nothing else in the
// saga has to move.
//
// It takes no arguments today for the same reason it returns an empty set:
// there is no classification to consult and no node to ask. Giving it a node
// list now would be modelling a conversation that cannot happen.
func FanOutAppVolumes() AppVolumeReport {
	return AppVolumeReport{
		Captured:       []string{},
		CapturedCount:  0,
		NodesConsulted: 0,
		Reason:         appVolumeFanOutReason,
		BlockedBy: []string{
			"geekdojo/geekdojo-brain#292 tileschema backup class fields",
			"geekdojo/geekdojo-brain#293 catalog volume classification",
			"geekdojo/geekdojo-brain#294 quiesce drivers",
			"geekdojo/geekdojo-brain#295 per-node streaming",
			"geekdojo/geekdojo-brain#296 ingest endpoint",
		},
	}
}

// identityExclusions is §4.5's "Excluded" column, restated in the manifest.
var identityExclusions = []string{
	"app volumes (see appVolumes — none are captured by this build)",
	"`cache`-class volumes (regenerable index, queue and model caches)",
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
			total += uint64(info.Size())
		}
	}
	_ = filepath.WalkDir(headscaleDir(src), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // an unreadable subtree contributes zero, it does not fail an estimate
		}
		if info, ierr := d.Info(); ierr == nil && info.Mode().IsRegular() {
			total += uint64(info.Size())
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
// aesthetics: a reader streaming a decrypted archive learns the scope before it
// has read a single byte of anything else, so a restore can refuse an
// identity-only archive it was told was complete without buffering the lot.
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

	// The fan-out phase. It runs on every backup, and on this build it captures
	// nothing — see AppVolumeReport for why that is a report and not an
	// omission.
	fanOut := FanOutAppVolumes()

	m := &Manifest{
		ManifestVersion: ManifestVersion,
		GenerationID:    opts.GenerationID,
		JobID:           opts.JobID,
		ClusterID:       opts.ClusterID,
		CreatedAt:       now,
		Scope:           proto.BackupScopeIdentityOnly,
		Complete:        false,
		Warning:         appVolumeFanOutReason,
		KeyID:           opts.KeyID,
		AppVolumes:      fanOut,
		Excluded:        identityExclusions,
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
