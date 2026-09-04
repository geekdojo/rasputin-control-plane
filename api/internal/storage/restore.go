package storage

import (
	"archive/tar"
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/geekdojo/rasputin-control-plane/backupxfer/fsat"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// design/storage.md §4.5's restore, phase 1: the IDENTITY SET, before the
// api's first start (#291).
//
// # Where this runs, and what it is
//
// A re-flashed controlplane boots into first-run with an empty
// /var/lib/rasputin. If a disk attached to it carries a Rasputin backup set
// with generations, the first-run surface offers "Restore from this backup"
// beside "Set up fresh". No OS-image change; the api does all of it, and the
// path is open only while NO OPERATOR EXISTS — the moment a passkey is
// registered it closes (see the HTTP handler). That is the same posture as
// the first-user registration race iam.md §3.1 already accepts, on the same
// window, and it is what "restore-before-first-boot" means in a product where
// the api is the only thing that runs.
//
// # Custody is authorization
//
// The archive is authenticated by its AEAD under a key only the holder of the
// passphrase or the recovery code can derive. There is no separate signature:
// a signing key that survived re-flash would be the same custody problem
// again. Possession of a custody secret IS the authorization to restore, and
// the api proves it before touching anything — the supplied private key must
// derive the public key the disk's own marker carries.
//
// # The private key transits once
//
// The browser unwraps it and sends it over TLS; the api holds it in memory
// for the duration of one restore and zeroes it on every exit path. It is
// never logged, never written to the ledger, never in a step result — there
// is no job for it to be a step result OF, deliberately: a job spec is
// persisted and rendered, and this is the one request body that must not be.
// So the restore is a synchronous handler, not a saga.
//
// # This is the trust-injection seam #230's MEDIUM lived in
//
// Root writing into the identity directory from a disk somebody plugged in.
// Every extracted path is validated beneath the root; every open goes through
// backupxfer/fsat (openat, O_NOFOLLOW, fstat) relative to an fd, never by
// path; symlink members are refused, not recreated; `..` and absolute paths
// are refused; sizes are bounded by the manifest; the manifest's per-entry
// sha256 is verified on every entry before it counts as restored. Everything
// lands in a staging directory first and moves into place once, at the next
// start, before any database is opened — so a failed restore leaves the
// partition exactly as it found it.
//
// # Scope: identity only, and said so
//
// rasputin.db, trust/mesh-ca.{key,pem} and mesh/headscale. App volumes live
// on compute nodes and their restore is the reverse transport — phase 2.
// Every app-volume member the generation holds is recorded BY NAME in the
// restore's own report as present and not restored, so nobody mistakes an
// identity restore for a full one.

// Directory names under the data dir. restorePendingDirName is the handoff to
// the next start; restoreAppliedDirName is the report waiting to be written
// into the restored database; restoreStagingPrefix is an extraction in
// progress, swept if the process dies mid-way.
const (
	restorePendingDirName = "restore-pending"
	restoreAppliedDirName = "restore-applied"
	restoreStagingPrefix  = ".restore-staging-"
	restoreReportFile     = "restore.json"
	// restoreReplacedPrefix holds the fresh install's own identity files,
	// moved aside rather than deleted when the restore is applied.
	restoreReplacedPrefix = "restore-replaced-"
)

// RestorePhase names what this build restores. Stamped into every report so a
// reader years from now knows an "identity" restore put no app data back.
const RestorePhase = "identity"

// Bounds on what is read off the disk before anything is trusted.
const (
	maxMarkerBytes   = 64 << 10
	maxManifestBytes = 8 << 20
	// maxRestoreEntries bounds the manifest's entry list; the identity set is
	// a database, two PEMs and a small state tree.
	maxRestoreEntries = 10000
)

// Errors a caller branches on. Each is a refusal that touched nothing.
var (
	// ErrRestoreKeyMismatch — the supplied private key does not derive the
	// public key on the disk's marker. The passphrase or recovery code opened
	// a wrapping, and what was inside is not this disk's key.
	ErrRestoreKeyMismatch = errors.New("the supplied archive key does not belong to this disk: it does not derive the public key its marker carries")
	// ErrRestorePending — a prepared restore is already waiting for the next
	// start. One at a time; the operator restarts, or removes it.
	ErrRestorePending = errors.New("a restore is already prepared and waiting for the api to restart; refusing to prepare a second one")
	// ErrRestoreArchive — the archive or its manifest failed a check. The
	// message names which. Nothing outside the staging directory was written,
	// and the staging directory is gone.
	ErrRestoreArchive = errors.New("the archive did not pass verification")
)

// RestoreConfig is the environment a restore runs in.
type RestoreConfig struct {
	// NC is the bus, for the co-located agent's storage verbs.
	NC *nats.Conn
	// SelfNodeID is the node this api runs on. Restore reads the disk through
	// the filesystem — the agent mounts it and reports where — so the disk
	// has to be on this host, and every RPC goes to this node and no other.
	// Empty refuses every restore rather than trusting whoever answers.
	SelfNodeID string
	// DataDir is /var/lib/rasputin: where the staging directory is created
	// and where the pending restore waits.
	DataDir string
	// ClusterID is what THIS box was flashed with (RASPUTIN_CLUSTER_ID). It is
	// reported beside each candidate so the UI can warn when an archive was
	// written by a cluster of a different name — the RP ID passkeys bind to
	// is derived from it, so the two must agree for the restored passkeys to
	// work.
	ClusterID string
}

// RestoreCandidate is one attached disk carrying a Rasputin backup set, as
// the first-run restore surface shows it.
type RestoreCandidate struct {
	NodeID     string                 `json:"nodeId"`
	DevicePath string                 `json:"devicePath"`
	Model      string                 `json:"model,omitempty"`
	Serial     string                 `json:"serial,omitempty"`
	SizeBytes  uint64                 `json:"sizeBytes"`
	Transport  proto.StorageTransport `json:"transport"`
	Removable  bool                   `json:"removable"`
	// Marker is the disk's own record of itself: cluster id, partition UUID,
	// key id, the PUBLIC key, and the two WRAPPED copies of the private key
	// the browser needs in order to unwrap. Ciphertext and identifiers — the
	// same thing the disk publishes to anyone holding it.
	Marker *proto.StorageBackupSet `json:"marker,omitempty"`
	// Generations are the retained generations on the disk, newest first,
	// each with what its clear-text manifest says it holds.
	Generations []RestoreGeneration `json:"generations"`
	// Restorable is true when this disk can be restored from at all; Problem
	// says why not when it is false.
	Restorable bool   `json:"restorable"`
	Problem    string `json:"problem,omitempty"`
}

// RestoreGeneration is one generation as its clear-text manifest describes it.
type RestoreGeneration struct {
	ID              string    `json:"id"`
	CreatedAt       time.Time `json:"createdAt"`
	Scope           string    `json:"scope,omitempty"`
	Complete        bool      `json:"complete"`
	KeyID           string    `json:"keyId,omitempty"`
	ClusterID       string    `json:"clusterId,omitempty"`
	ManifestVersion int       `json:"manifestVersion"`
	ArchiveBytes    uint64    `json:"archiveBytes"`
	// IdentityEntries is how many files the identity archive holds.
	IdentityEntries int `json:"identityEntries"`
	// AppVolumesPresent names every app volume the generation holds — which
	// this phase will NOT restore — and AppVolumesAbsent every classified
	// volume the run did not capture, with its reason.
	AppVolumesPresent []AppVolumeMention `json:"appVolumesPresent"`
	AppVolumesAbsent  []AppVolumeMention `json:"appVolumesAbsent"`
	Restorable        bool               `json:"restorable"`
	Problem           string             `json:"problem,omitempty"`
}

// AppVolumeMention is one app volume named in a report: present in the
// generation (Member set) or absent from it (Reason set).
type AppVolumeMention struct {
	Name      string `json:"name"`
	Class     string `json:"class,omitempty"`
	NodeID    string `json:"nodeId,omitempty"`
	Member    string `json:"member,omitempty"`
	SizeBytes uint64 `json:"sizeBytes,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// RestoreCandidatesResponse is GET /api/restore/candidates.
type RestoreCandidatesResponse struct {
	NodeID string `json:"nodeId"`
	// ClusterID is this box's own cluster id, for the mismatch warning.
	ClusterID  string             `json:"clusterId"`
	Candidates []RestoreCandidate `json:"candidates"`
	Ts         time.Time          `json:"ts"`
}

// RestoreRequest is one restore, as PrepareRestore takes it.
type RestoreRequest struct {
	PartUUID     string
	GenerationID string
	KeyID        string
	// PrivateKey is the 32-byte X25519 scalar the browser unwrapped. Borrowed:
	// the caller zeroes it when PrepareRestore returns, on every path.
	PrivateKey []byte
}

// RestoredEntry is one identity file put back, with the digest that was
// verified before it counted.
type RestoredEntry struct {
	Path      string `json:"path"`
	SizeBytes int64  `json:"sizeBytes"`
	SHA256    string `json:"sha256"`
	Note      string `json:"note,omitempty"`
}

// NotRestoredItem is an identity-archive member this phase did not put back.
type NotRestoredItem struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// RestoreReport is the record of one restore: what was put back, with
// digests; what was present and NOT put back, by name; the generation; the
// key id; and when. Written into the restored database so the Storage page
// can say "this cluster was restored from generation X on date Y".
//
// No field here carries key material, and none can be added: this struct is
// persisted and served.
type RestoreReport struct {
	ID    string `json:"id"`
	Phase string `json:"phase"`
	// The generation, as its manifest described it.
	GenerationID        string    `json:"generationId"`
	GenerationCreatedAt time.Time `json:"generationCreatedAt"`
	ClusterID           string    `json:"clusterId,omitempty"`
	KeyID               string    `json:"keyId,omitempty"`
	Scope               string    `json:"scope,omitempty"`
	Complete            bool      `json:"complete"`
	ManifestVersion     int       `json:"manifestVersion"`
	// The disk it came from.
	PartUUID    string `json:"partUuid"`
	SourceLabel string `json:"sourceLabel,omitempty"`
	NodeID      string `json:"nodeId"`
	// SealedDigest is over the archive as read; SealedBytes its length.
	SealedDigest string `json:"sealedDigest"`
	SealedBytes  uint64 `json:"sealedBytes"`
	// Restored is every identity file put back, with its verified digest.
	Restored []RestoredEntry `json:"restored"`
	// NotRestored is every member of the identity archive this phase left
	// alone — a version-1 generation's in-archive app volumes, for instance.
	NotRestored []NotRestoredItem `json:"notRestored"`
	// AppVolumesPresent names every app-volume member the generation holds.
	// PRESENT AND NOT RESTORED: app volumes are phase 2.
	AppVolumesPresent []AppVolumeMention `json:"appVolumesPresent"`
	// AppVolumesAbsent names every classified volume the run did not capture.
	AppVolumesAbsent []AppVolumeMention `json:"appVolumesAbsent"`
	// Warning is the standing caveat, in prose, for a reader who has this
	// record and nothing else.
	Warning    string     `json:"warning"`
	PreparedAt time.Time  `json:"preparedAt"`
	AppliedAt  *time.Time `json:"appliedAt,omitempty"`
	RecordedAt *time.Time `json:"recordedAt,omitempty"`
}

// restoreWarning is the report's standing caveat.
const restoreWarning = "This restore put back the control-plane IDENTITY SET only — the database (users and passkeys, node bus tokens, app declarations, mesh intents), " +
	"the mesh CA and Headscale state. Every operator device, user and node re-authenticates with no ceremony. " +
	"APP DATA WAS NOT RESTORED: every app volume the generation holds is listed by name under appVolumesPresent and is still on the backup disk, sealed. " +
	"Restoring app volumes to the nodes that host them is a later phase. Do not read this record as a full restore of the cluster."

// identityRestorePath reports whether an archive member path is part of the
// identity set this phase restores, and the note the report carries for it.
func identityRestorePath(p string) (note string, ok bool) {
	switch {
	case p == "rasputin.db":
		return "the control-plane database — users and passkey credentials, the bus-token store, app declarations, mesh intents, the job ledger", true
	case p == "trust/mesh-ca.key":
		return "the per-installation mesh CA private key — every operator device's installed trust", true
	case p == "trust/mesh-ca.pem":
		return "the per-installation mesh CA certificate", true
	case strings.HasPrefix(p, "mesh/headscale/"):
		return "Headscale state — tailnet identity; nodes stay enrolled", true
	}
	return "", false
}

// safePathSegment is one component of an archive member path: the same
// alphabet the writer can produce, with `.` and `..` refused separately.
var safePathSegment = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// safePartUUID mirrors the agent's own shape check on a partition UUID: what
// blkid prints, and nothing that could be a path.
var safePartUUID = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// validateRestorePath refuses anything that is not a clean, relative,
// slash-separated path of safe components. It is a validation by SHAPE, not a
// sanitisation: a member the writer could not have named is refused, never
// repaired into something that opens.
func validateRestorePath(p string) error {
	if p == "" {
		return errors.New("empty member path")
	}
	if strings.HasPrefix(p, "/") || filepath.IsAbs(p) {
		return fmt.Errorf("member path %q is absolute", p)
	}
	if strings.Contains(p, `\`) {
		return fmt.Errorf("member path %q contains a backslash", p)
	}
	if path.Clean(p) != p {
		return fmt.Errorf("member path %q is not clean", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("member path %q contains %q", p, seg)
		}
		if !safePathSegment.MatchString(seg) {
			return fmt.Errorf("member path %q has a component outside [A-Za-z0-9._-]", p)
		}
	}
	return nil
}

// ----- Candidates ---------------------------------------------------------

// ListRestoreCandidates asks the co-located agent for its disks and reports
// every one carrying a Rasputin backup set, with what its generations hold.
// Read-only.
func ListRestoreCandidates(ctx context.Context, cfg RestoreConfig) (*RestoreCandidatesResponse, error) {
	if strings.TrimSpace(cfg.SelfNodeID) == "" {
		return nil, errors.New("this api does not know which node it runs on (RASPUTIN_SELF_NODE_ID is unset), so it cannot look for a backup disk beside it")
	}
	ack, err := Enumerate(ctx, cfg.NC, cfg.SelfNodeID)
	if err != nil {
		return nil, err
	}
	out := &RestoreCandidatesResponse{
		NodeID: cfg.SelfNodeID, ClusterID: cfg.ClusterID, Ts: ack.Ts,
		Candidates: []RestoreCandidate{},
	}
	for i := range ack.Candidates {
		c := ack.Candidates[i]
		if !c.HasBackupSet {
			continue
		}
		cand := RestoreCandidate{
			NodeID: cfg.SelfNodeID, DevicePath: c.DevicePath, Model: c.Model, Serial: c.Serial,
			SizeBytes: c.SizeBytes, Transport: c.Transport, Removable: c.Removable,
			Marker: c.BackupSet, Generations: []RestoreGeneration{},
		}
		switch {
		case c.Protected:
			cand.Problem = "this is the disk the controlplane is running from; it cannot be a backup source"
		case c.BackupSet == nil:
			cand.Problem = "the disk announces a Rasputin backup set but its marker could not be read"
		case strings.TrimSpace(c.BackupSet.PartUUID) == "":
			cand.Problem = "the marker names no partition UUID, so the disk cannot be mounted by its own account"
		case strings.TrimSpace(c.BackupSet.PublicKey) == "" || c.BackupSet.WrappedByPassphrase == "" || c.BackupSet.WrappedByRecoveryCode == "":
			cand.Problem = "this disk's archive key predates the keypair design (no public key or no wrapped private key on the marker); its generations cannot be opened by this build"
		default:
			mountPath, merr := mountTarget(ctx, cfg.NC, cfg.SelfNodeID, c.BackupSet.PartUUID)
			if merr != nil {
				cand.Problem = "the disk could not be mounted: " + merr.Error()
				break
			}
			gens, gerr := listRestoreGenerations(mountPath, c.BackupSet.KeyID)
			if gerr != nil {
				cand.Problem = "the generations directory could not be read: " + gerr.Error()
				break
			}
			cand.Generations = gens
			for _, g := range gens {
				if g.Restorable {
					cand.Restorable = true
				}
			}
			if !cand.Restorable {
				cand.Problem = "the disk carries no generation this build can restore from"
			}
		}
		out.Candidates = append(out.Candidates, cand)
	}
	return out, nil
}

// mountTarget asks the agent to mount a claimed target by partition UUID and
// returns where it landed, after the same shape gate the run applies to a
// mount path that came off the wire.
func mountTarget(ctx context.Context, nc *nats.Conn, nodeID, partUUID string) (string, error) {
	if nc == nil {
		return "", errors.New("no bus connection")
	}
	if !safePartUUID.MatchString(partUUID) {
		return "", fmt.Errorf("%q is not a partition UUID", partUUID)
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, proto.StorageMountWork+rpcSlack)
		defer cancel()
	}
	cmd, err := json.Marshal(proto.StorageMountCmd{PartUUID: partUUID})
	if err != nil {
		return "", err
	}
	msg, err := nc.RequestWithContext(ctx, proto.StorageMountSubject(nodeID), cmd)
	if err != nil {
		return "", fmt.Errorf("storage mount rpc to %s: %w", nodeID, err)
	}
	var ack proto.StorageMountAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		return "", fmt.Errorf("storage mount: unreadable reply from %s: %w", nodeID, err)
	}
	if !ack.OK {
		return "", refusalError("mount", ack.Refusal, ack.Detail)
	}
	mountPath := strings.TrimSpace(ack.MountPath)
	if err := checkStagingRoot(mountPath); err != nil {
		return "", fmt.Errorf("the agent on %s named %q as the mount path: %w", nodeID, mountPath, err)
	}
	return mountPath, nil
}

// listRestoreGenerations reads the target's generations through fsat and
// describes each from its clear-text manifest, newest first.
func listRestoreGenerations(mountPath, markerKeyID string) ([]RestoreGeneration, error) {
	root, err := fsat.OpenRoot(mountPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	gens, err := fsat.OpenDir(root, proto.BackupGenerationsDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []RestoreGeneration{}, nil
		}
		return nil, err
	}
	defer func() { _ = gens.Close() }()
	ents, err := gens.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	out := make([]RestoreGeneration, 0, len(ents))
	for _, e := range ents {
		name := e.Name()
		if strings.HasPrefix(name, ".") || !proto.BackupValidGenerationID(name) {
			continue
		}
		dir, derr := fsat.OpenDir(gens, name)
		if derr != nil {
			// A file, or a symlink, where a generation directory should be:
			// not a generation.
			continue
		}
		g := describeGeneration(dir, name, markerKeyID)
		_ = dir.Close()
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

// describeGeneration reads one generation's sidecar manifest and archive size.
// The sidecar is what an operator sees in the picker; the copy INSIDE the
// archive is what the restore trusts.
func describeGeneration(dir *os.File, id, markerKeyID string) RestoreGeneration {
	g := RestoreGeneration{ID: id, AppVolumesPresent: []AppVolumeMention{}, AppVolumesAbsent: []AppVolumeMention{}}
	if f, err := fsat.OpenFile(dir, proto.BackupArchiveFile); err == nil {
		if st, serr := f.Stat(); serr == nil {
			g.ArchiveBytes = byteCount(st.Size())
			g.CreatedAt = st.ModTime().UTC()
		}
		_ = f.Close()
	} else {
		g.Problem = "the generation has no identity archive"
		return g
	}
	raw, err := readBounded(dir, proto.BackupManifestFile, maxManifestBytes)
	if err != nil {
		g.Problem = "the generation's manifest could not be read: " + err.Error()
		return g
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		g.Problem = "the generation's manifest is not readable JSON"
		return g
	}
	fillGenerationFromManifest(&g, &m)
	switch {
	case m.ManifestVersion < 1 || m.ManifestVersion > ManifestVersion:
		g.Problem = fmt.Sprintf("the manifest is version %d; this build reads versions 1 to %d", m.ManifestVersion, ManifestVersion)
	case markerKeyID != "" && m.KeyID != "" && m.KeyID != markerKeyID:
		g.Problem = fmt.Sprintf("the generation is sealed to key %s but the disk's marker names key %s; the disk has been re-keyed since this generation was written", m.KeyID, markerKeyID)
	case !hasIdentityEntry(m.Entries, "rasputin.db"):
		g.Problem = "the manifest names no rasputin.db; an archive without the database restores nothing this phase puts back"
	default:
		g.Restorable = true
	}
	return g
}

func fillGenerationFromManifest(g *RestoreGeneration, m *Manifest) {
	if !m.CreatedAt.IsZero() {
		g.CreatedAt = m.CreatedAt.UTC()
	}
	g.Scope = m.Scope
	g.Complete = m.Complete
	g.KeyID = m.KeyID
	g.ClusterID = m.ClusterID
	g.ManifestVersion = m.ManifestVersion
	g.IdentityEntries = len(m.Entries)
	g.AppVolumesPresent, g.AppVolumesAbsent = appVolumeMentions(m)
}

// appVolumeMentions splits a manifest's per-volume record into the members
// the generation holds and the classified volumes it does not.
func appVolumeMentions(m *Manifest) (present, absent []AppVolumeMention) {
	present, absent = []AppVolumeMention{}, []AppVolumeMention{}
	for _, v := range m.AppVolumes.Volumes {
		name := v.App + "/" + v.Volume
		if v.Captured {
			present = append(present, AppVolumeMention{
				Name: name, Class: v.Class, NodeID: v.Node, Member: v.Member, SizeBytes: v.SizeBytes,
			})
			continue
		}
		absent = append(absent, AppVolumeMention{Name: name, Class: v.Class, NodeID: v.Node, Reason: v.Reason})
	}
	return present, absent
}

func hasIdentityEntry(entries []ManifestEntry, p string) bool {
	for _, e := range entries {
		if e.Path == p {
			return true
		}
	}
	return false
}

// readBounded reads parent/name through fsat, refusing a file over limit.
func readBounded(parent *os.File, name string, limit int64) ([]byte, error) {
	f, err := fsat.OpenFile(parent, name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > limit {
		return nil, fmt.Errorf("%s is %d bytes; refusing to read more than %d", name, st.Size(), limit)
	}
	return io.ReadAll(io.LimitReader(f, limit))
}

// ----- Prepare ------------------------------------------------------------

// PrepareRestore verifies custody, opens the generation and unpacks the
// identity set into a staging directory under the data dir, then moves that
// directory to the pending location the next start applies. It returns the
// report it wrote there.
//
// Nothing under the data dir other than the staging directory is written, and
// on any failure the staging directory is removed — so a restore that fails
// mid-way leaves the partition as it found it. The live database is not
// touched: this process has it open, and replacing a file under an open
// SQLite connection is not a restore, it is corruption. The swap is the next
// start's first act, before any store opens (ApplyPendingRestore).
//
// req.PrivateKey is borrowed. The caller zeroes it.
func PrepareRestore(ctx context.Context, cfg RestoreConfig, req RestoreRequest) (*RestoreReport, error) {
	if strings.TrimSpace(cfg.SelfNodeID) == "" {
		return nil, errors.New("this api does not know which node it runs on (RASPUTIN_SELF_NODE_ID is unset); a restore reads the disk beside it and needs that name")
	}
	if strings.TrimSpace(cfg.DataDir) == "" {
		return nil, errors.New("no data directory configured")
	}
	if !safePartUUID.MatchString(req.PartUUID) {
		return nil, fmt.Errorf("%w: %q is not a partition UUID", ErrRestoreArchive, req.PartUUID)
	}
	if !proto.BackupValidGenerationID(req.GenerationID) {
		return nil, fmt.Errorf("%w: %q is not a generation id", ErrRestoreArchive, req.GenerationID)
	}
	if strings.TrimSpace(req.KeyID) == "" {
		return nil, fmt.Errorf("%w: the request names no key id", ErrRestoreArchive)
	}
	suppliedPub, err := PublicKeyForPrivate(req.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRestoreArchive, err)
	}
	if allZero(req.PrivateKey) {
		return nil, fmt.Errorf("%w: the supplied key is all zeroes", ErrRestoreArchive)
	}
	if !fsat.Supported {
		return nil, fsat.ErrUnsupported
	}

	// One at a time, and refused before the disk is touched.
	dataRoot, err := fsat.OpenRoot(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dataRoot.Close() }()
	if exists, err := fsat.Exists(dataRoot, restorePendingDirName); err != nil {
		return nil, err
	} else if exists {
		return nil, ErrRestorePending
	}

	// The disk, through the agent's mount, then through fsat from its root.
	mountPath, err := mountTarget(ctx, cfg.NC, cfg.SelfNodeID, req.PartUUID)
	if err != nil {
		return nil, err
	}
	root, err := fsat.OpenRoot(mountPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	// Custody first: the marker's public key against the supplied private
	// key. Nothing else is opened until this holds.
	rawMarker, err := readBounded(root, proto.StorageMarkerFile, maxMarkerBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: the disk's marker could not be read: %v", ErrRestoreArchive, err)
	}
	var marker proto.StorageBackupSet
	if err := json.Unmarshal(rawMarker, &marker); err != nil {
		return nil, fmt.Errorf("%w: the disk's marker is not readable JSON", ErrRestoreArchive)
	}
	if marker.PartUUID != "" && marker.PartUUID != req.PartUUID {
		return nil, fmt.Errorf("%w: the disk mounted for %s carries a marker for %s", ErrRestoreArchive, req.PartUUID, marker.PartUUID)
	}
	if marker.KeyID != req.KeyID {
		return nil, fmt.Errorf("%w: the request names key %s but the disk's marker names key %s", ErrRestoreArchive, req.KeyID, marker.KeyID)
	}
	if !publicKeysEqual(marker.PublicKey, suppliedPub) {
		return nil, ErrRestoreKeyMismatch
	}

	gens, err := fsat.OpenDir(root, proto.BackupGenerationsDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRestoreArchive, err)
	}
	defer func() { _ = gens.Close() }()
	gen, err := fsat.OpenDir(gens, req.GenerationID)
	if err != nil {
		return nil, fmt.Errorf("%w: generation %s: %v", ErrRestoreArchive, req.GenerationID, err)
	}
	defer func() { _ = gen.Close() }()
	// The sidecar is read for the one check that should fail before a
	// passphrase-worth of work is spent: the key it names.
	if raw, rerr := readBounded(gen, proto.BackupManifestFile, maxManifestBytes); rerr == nil {
		var side Manifest
		if json.Unmarshal(raw, &side) == nil && side.KeyID != "" && side.KeyID != req.KeyID {
			return nil, fmt.Errorf("%w: generation %s is sealed to key %s, not %s", ErrRestoreArchive, req.GenerationID, side.KeyID, req.KeyID)
		}
	}
	archive, err := fsat.OpenFile(gen, proto.BackupArchiveFile)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRestoreArchive, err)
	}
	defer func() { _ = archive.Close() }()

	// Staging: a fresh directory under the data dir, created exclusively,
	// removed on every failure path below.
	stagingName := restoreStagingPrefix + randomHex(8)
	if exists, err := fsat.Exists(dataRoot, stagingName); err != nil || exists {
		return nil, fmt.Errorf("staging directory %s already exists", stagingName)
	}
	staging, err := fsat.MkdirOpen(dataRoot, stagingName)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		_ = staging.Close()
		if !committed {
			_ = os.RemoveAll(filepath.Join(cfg.DataDir, stagingName))
		}
	}()

	report, err := extractIdentity(archive, staging, req)
	if err != nil {
		return nil, err
	}
	report.PartUUID = req.PartUUID
	report.SourceLabel = marker.Label
	report.NodeID = cfg.SelfNodeID

	// The report goes into the staging directory beside what it describes,
	// and the rename is the commit.
	if err := writeReport(staging, report); err != nil {
		return nil, err
	}
	if err := staging.Sync(); err != nil {
		return nil, err
	}
	if err := fsat.Rename(dataRoot, stagingName, restorePendingDirName); err != nil {
		return nil, fmt.Errorf("commit restore: %w", err)
	}
	committed = true
	_ = dataRoot.Sync()
	return report, nil
}

// extractIdentity unseals the archive into the staging directory, verifying
// every member against the manifest INSIDE the archive, and returns the
// report. On error the caller removes the staging directory.
func extractIdentity(archive io.Reader, staging *os.File, req RestoreRequest) (*RestoreReport, error) {
	// Unseal runs into a pipe; the tar reader consumes it. Chunks are
	// authenticated before they are written, so what the tar reader sees is
	// authentic — completeness is decided by Unseal's return, which is
	// checked after the tar is exhausted.
	pr, pw := io.Pipe()
	u := &unsealer{finished: make(chan struct{})}
	go func() {
		defer close(u.finished)
		u.res, u.err = Unseal(pw, bufio.NewReaderSize(archive, 256<<10), req.PrivateKey)
		_ = pw.CloseWithError(u.err)
	}()
	// Whatever happens below, the pipe is closed so the goroutine ends.
	defer func() { _ = pr.Close() }()

	tr := tar.NewReader(pr)
	hdr, err := tr.Next()
	if err != nil {
		return nil, fmt.Errorf("%w: the archive did not open as a tar: %v", ErrRestoreArchive, u.explain(err))
	}
	if hdr.Name != proto.BackupManifestFile || hdr.Typeflag != tar.TypeReg {
		return nil, fmt.Errorf("%w: the archive's first member is %q, not the manifest", ErrRestoreArchive, hdr.Name)
	}
	if hdr.Size > maxManifestBytes {
		return nil, fmt.Errorf("%w: the inner manifest is %d bytes; refusing to read more than %d", ErrRestoreArchive, hdr.Size, maxManifestBytes)
	}
	rawManifest, err := io.ReadAll(io.LimitReader(tr, maxManifestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: reading the inner manifest: %v", ErrRestoreArchive, u.explain(err))
	}
	var m Manifest
	if err := json.Unmarshal(rawManifest, &m); err != nil {
		return nil, fmt.Errorf("%w: the inner manifest is not readable JSON", ErrRestoreArchive)
	}
	if m.ManifestVersion < 1 || m.ManifestVersion > ManifestVersion {
		return nil, fmt.Errorf("%w: the manifest is version %d; this build reads versions 1 to %d", ErrRestoreArchive, m.ManifestVersion, ManifestVersion)
	}
	if m.GenerationID != "" && m.GenerationID != req.GenerationID {
		return nil, fmt.Errorf("%w: the archive's manifest is for generation %s, not %s", ErrRestoreArchive, m.GenerationID, req.GenerationID)
	}
	if m.KeyID != "" && m.KeyID != req.KeyID {
		return nil, fmt.Errorf("%w: the archive's manifest names key %s, not %s", ErrRestoreArchive, m.KeyID, req.KeyID)
	}
	if len(m.Entries) > maxRestoreEntries {
		return nil, fmt.Errorf("%w: the manifest lists %d entries; refusing more than %d", ErrRestoreArchive, len(m.Entries), maxRestoreEntries)
	}

	// The manifest decides what may be extracted: every identity entry it
	// names, at the size and digest it names, and nothing it does not name.
	expected := map[string]ManifestEntry{}
	for _, e := range m.Entries {
		if err := validateRestorePath(e.Path); err != nil {
			return nil, fmt.Errorf("%w: manifest: %v", ErrRestoreArchive, err)
		}
		if e.SizeBytes < 0 {
			return nil, fmt.Errorf("%w: manifest entry %s has a negative size", ErrRestoreArchive, e.Path)
		}
		if _, err := hex.DecodeString(e.SHA256); err != nil || len(e.SHA256) != sha256.Size*2 {
			return nil, fmt.Errorf("%w: manifest entry %s has no usable sha256", ErrRestoreArchive, e.Path)
		}
		if _, dup := expected[e.Path]; dup {
			return nil, fmt.Errorf("%w: manifest names %s twice", ErrRestoreArchive, e.Path)
		}
		expected[e.Path] = e
	}
	if _, ok := expected["rasputin.db"]; !ok {
		return nil, fmt.Errorf("%w: the manifest names no rasputin.db; an archive without the database restores nothing this phase puts back", ErrRestoreArchive)
	}

	report := &RestoreReport{
		ID: "rs-" + randomHex(8), Phase: RestorePhase,
		GenerationID: req.GenerationID, GenerationCreatedAt: m.CreatedAt.UTC(),
		ClusterID: m.ClusterID, KeyID: req.KeyID, Scope: m.Scope, Complete: m.Complete,
		ManifestVersion: m.ManifestVersion,
		Restored:        []RestoredEntry{}, NotRestored: []NotRestoredItem{},
		Warning:    restoreWarning,
		PreparedAt: time.Now().UTC(),
	}
	report.AppVolumesPresent, report.AppVolumesAbsent = appVolumeMentions(&m)

	seen := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: reading the archive: %v", ErrRestoreArchive, u.explain(err))
		}
		name := hdr.Name
		if err := validateRestorePath(name); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRestoreArchive, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			// The writer produces regular files and nothing else. A symlink,
			// a directory entry, a device: not something this archive can
			// contain, and not something a restore will recreate.
			return nil, fmt.Errorf("%w: member %s is not a regular file (type %q); an identity archive holds only regular files, and a symlink is never recreated", ErrRestoreArchive, name, string(hdr.Typeflag))
		}
		if seen[name] {
			return nil, fmt.Errorf("%w: the archive holds %s twice", ErrRestoreArchive, name)
		}
		seen[name] = true
		note, identity := identityRestorePath(name)
		if !identity {
			// Present, not restored, and said so: a version-1 generation's
			// in-archive app volumes are the case.
			report.NotRestored = append(report.NotRestored, NotRestoredItem{
				Path: name, Reason: "not part of the identity set this phase restores",
			})
			continue
		}
		want, ok := expected[name]
		if !ok {
			return nil, fmt.Errorf("%w: the archive holds %s but the manifest does not name it", ErrRestoreArchive, name)
		}
		if hdr.Size != want.SizeBytes {
			return nil, fmt.Errorf("%w: %s is %d bytes in the archive and %d in the manifest", ErrRestoreArchive, name, hdr.Size, want.SizeBytes)
		}
		sum, err := writeMember(staging, name, tr, want.SizeBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrRestoreArchive, name, u.explain(err))
		}
		if !strings.EqualFold(sum, want.SHA256) {
			return nil, fmt.Errorf("%w: %s does not match the manifest's sha256 (archive %s, manifest %s)", ErrRestoreArchive, name, sum, want.SHA256)
		}
		report.Restored = append(report.Restored, RestoredEntry{Path: name, SizeBytes: want.SizeBytes, SHA256: sum, Note: note})
	}
	// Every identity entry the manifest names must have arrived.
	for p := range expected {
		if _, identity := identityRestorePath(p); identity && !seen[p] {
			return nil, fmt.Errorf("%w: the manifest names %s but the archive has no such member", ErrRestoreArchive, p)
		}
	}
	// The tar is exhausted; let the unseal finish (there may be trailing
	// zero blocks after the last entry) and require it to have ended well.
	_, _ = io.Copy(io.Discard, pr)
	u.wait()
	if u.err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRestoreArchive, u.err)
	}
	if u.res.Header.KeyID != "" && u.res.Header.KeyID != req.KeyID {
		return nil, fmt.Errorf("%w: the sealed header names key %s, not %s", ErrRestoreArchive, u.res.Header.KeyID, req.KeyID)
	}
	if m.Scope != "" && u.res.Header.Scope != m.Scope {
		return nil, fmt.Errorf("%w: the sealed header's scope %q disagrees with the manifest's %q", ErrRestoreArchive, u.res.Header.Scope, m.Scope)
	}
	report.SealedDigest = u.res.SealedDigest
	report.SealedBytes = u.res.SealedBytes
	sort.Slice(report.Restored, func(i, j int) bool { return report.Restored[i].Path < report.Restored[j].Path })
	return report, nil
}

// unsealer is the unseal goroutine's outcome, readable once finished is
// closed.
type unsealer struct {
	finished chan struct{}
	res      *UnsealResult
	err      error
}

func (u *unsealer) wait() { <-u.finished }

// explain prefers the unseal's own error when a pipe read failed because of
// it: a tar error that is really "the key was wrong" should say so.
func (u *unsealer) explain(err error) error {
	select {
	case <-u.finished:
		if u.err != nil {
			return u.err
		}
	default:
	}
	return err
}

// writeMember writes one member beneath the staging directory through fsat,
// creating parent directories exclusively as it goes, bounded by size, and
// returns the sha256 of what it wrote. The file is fsynced.
func writeMember(staging *os.File, name string, src io.Reader, size int64) (string, error) {
	parts := strings.Split(name, "/")
	dir := staging
	for _, p := range parts[:len(parts)-1] {
		next, err := fsat.MkdirOpen(dir, p)
		if dir != staging {
			_ = dir.Close()
		}
		if err != nil {
			return "", err
		}
		dir = next
	}
	defer func() {
		if dir != staging {
			_ = dir.Close()
		}
	}()
	f, err := fsat.CreateExclusive(dir, parts[len(parts)-1])
	if err != nil {
		return "", err
	}
	h := sha256.New()
	// One byte past the declared size, so an over-long member is detected
	// rather than silently truncated to the manifest's number.
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(src, size+1))
	if err != nil {
		_ = f.Close()
		return "", err
	}
	if n != size {
		_ = f.Close()
		return "", fmt.Errorf("wrote %d bytes, expected %d", n, size)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// writeReport writes restore.json beside the staged files, fsynced.
func writeReport(dir *os.File, r *RestoreReport) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	f, err := fsat.CreateExclusive(dir, restoreReportFile)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is a broken host; a fixed suffix still yields
		// an exclusive create, which is the property that matters.
		return "00000000"
	}
	return hex.EncodeToString(b)
}

func allZero(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}
