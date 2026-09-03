package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/disk"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The agent half of design/storage.md §4.1's `backup.run`: preflight, write,
// prune. Three filesystem operations on a mounted target, and nothing else.
//
// # Why these are free functions and not Backend methods
//
// Everything here happens on a MOUNT POINT, and both backends already know how
// to produce one — Backend.Mount resolves a claimed target by partition UUID
// and returns where it landed, mounting it if needed. Past that boundary the
// work is identical for a real ext4 partition and for the mock's file-backed
// simulation: create a directory, copy a file, fsync, unlink. Adding three
// methods to Backend would have meant writing that twice and, worse, letting
// the two copies drift — and the mock is the copy that carries the weight here
// exactly as it does for Claim (see doc.go).
//
// So the handler calls these with the backend it has, and the ONE
// backend-specific step, resolving the mount, goes through the interface.
//
// # What this code deliberately cannot do
//
// It cannot read an archive. The api seals to the target's public key (§4.6)
// and this node holds no private key, so integrity is verified from a digest
// over the ciphertext and never by opening it. It cannot read a file outside
// the staging root: BackupWriteCmd carries a NAME, validated, joined onto a
// root this process was configured with. And it cannot delete an arbitrary
// path: prune only ever removes a directory it found by listing the target's
// own generations directory, and never the one the current run just wrote.

// backupStagingDirName is the staging directory's name under the agent's state
// dir. It is not a shared constant: nothing outside this package derives this
// path any more. See StagingRoot.
const backupStagingDirName = "backup-staging"

// StagingRoot returns the directory the write verb reads staged archives from,
// and the ONE place that directory is decided.
//
// <stateDir>/backup-staging, with RASPUTIN_BACKUP_STAGING_DIR as an override
// for a dev tree or a test. Both are local to this process — no part of the
// answer comes off the wire, which is the point.
//
// # Why the agent decides, and the api asks
//
// This used to be derived twice. The api joined `backup-staging` onto its DATA
// dir and the agent joined it onto its STATE dir, and the sentence in both
// files said the shared RASPUTIN_BACKUP_STAGING_DIR was what kept them pointed
// at one directory. On the shipping image that variable is set nowhere, so the
// two halves resolved to /var/lib/rasputin/backup-staging and
// /var/lib/rasputin/agent-state/backup-staging respectively: the api sealed a
// 105 MB archive and the agent refused it as missing, every time, in the only
// configuration that ships (e3bench 2026-09-02). The unit tests passed because
// each side was asked to resolve the SAME argument, which is not the question
// production asks.
//
// So the derivation happens once, here, and the api learns the answer from
// BackupPreflightAck.StagingRoot — step 2 of the saga, on the same node, before
// anything is staged. The direction is not arbitrary. This root is the write
// verb's containment boundary: BackupWrite joins a validated plain file NAME
// onto it and will open nothing else. A root supplied by the api would make
// that boundary something the caller chooses, i.e. not a boundary — one bug in
// the api and a verb that copies files onto a removable disk could be aimed at
// /etc. The command still carries a name and never a path, and this function's
// answer still comes only from this node's own configuration.
//
// A compute or storage node keeps its own root under its own state dir with no
// api co-located, which stays correct: it reports what it will read, and
// whoever stages has to put the file there.
func StagingRoot(stateDir string) string {
	if v := strings.TrimSpace(os.Getenv("RASPUTIN_BACKUP_STAGING_DIR")); v != "" {
		return v
	}
	return filepath.Join(stateDir, backupStagingDirName)
}

// ErrStagingMissing is the refusal for a staged file that is not where the
// command said it would be — or whose name was never a plain file name.
var ErrStagingMissing = errors.New("storage: staged archive not found under the staging root")

// ErrDigestMismatch is the refusal for staged bytes that do not hash to the
// digest the api computed. NOTHING is written to the target.
var ErrDigestMismatch = errors.New("storage: staged archive does not match the digest the api computed")

// ErrInsufficientSpace is §4.4's pre-flight refusal.
var ErrInsufficientSpace = errors.New("storage: the backup target has not got room for this archive")

// BackupPreflight is §4.4's "pre-flight free-space check before a run starts",
// executed against the live target.
//
// It REFUSES rather than reporting a caveat. §4.4's failure mode is a
// full-every-week policy with no space guard failing on the same night every
// week once the disk fills; the answer to that is a run that does not start,
// with numbers an operator can act on. Note that the numbers are filled in on
// the refusal too — "there is not room" is useless next to "900 MB free, needs
// 1.4 GB".
//
// It also answers the OTHER question the api has to have answered before it
// stages anything: where this node's staging root is. stagingRoot is echoed
// into the ack on every path, including the unplugged one, because it is a
// property of the node and not of the disk. See StagingRoot for why the agent
// is the one that decides it.
func BackupPreflight(ctx context.Context, b Backend, stagingRoot string, cmd proto.BackupPreflightCmd) (*proto.BackupPreflightAck, error) {
	if err := checkPartUUID(cmd.PartUUID); err != nil {
		return nil, err
	}
	mountPath, err := b.Mount(ctx, cmd.PartUUID)
	if errors.Is(err, ErrNotFound) {
		// The operator unplugged their backup disk. An answer, not a failure —
		// same shape as Inspect, and the api turns it into a clean refusal.
		return &proto.BackupPreflightAck{
			OK: true, Present: false, PartUUID: cmd.PartUUID,
			StagingRoot: stagingRoot,
			Refusal:     proto.StorageRefusalNotFound,
			Detail:      "no attached disk carries that partition UUID — the backup target is not plugged in",
		}, nil
	}
	if err != nil {
		return nil, err
	}
	ack := &proto.BackupPreflightAck{
		OK: true, Present: true, PartUUID: cmd.PartUUID, MountPath: mountPath, FSType: "ext4",
		StagingRoot: stagingRoot,
	}
	if du, derr := disk.UsageWithContext(ctx, mountPath); derr == nil {
		ack.TotalBytes = du.Total
		ack.FreeBytes = du.Free
	}
	gens, gerr := listGenerations(mountPath)
	if gerr != nil && !os.IsNotExist(gerr) {
		return nil, fmt.Errorf("list generations on %s: %w", mountPath, gerr)
	}
	ack.Generations = gens

	ack.RequiredBytes = requiredBytes(cmd.EstimateBytes)
	ack.Sufficient = ack.FreeBytes >= ack.RequiredBytes
	if !ack.Sufficient {
		ack.OK = false
		ack.Refusal = proto.BackupRefusalInsufficientSpace
		ack.Detail = fmt.Sprintf("%s has %s free; this run needs about %s (a %s archive plus a %s reserve). "+
			"Nothing was written. Free space on the target, or claim a larger one",
			mountPath, humanBytes(ack.FreeBytes), humanBytes(ack.RequiredBytes),
			humanBytes(cmd.EstimateBytes), humanBytes(proto.BackupTargetReserveBytes))
	}
	return ack, nil
}

// requiredBytes is the space a run needs: the estimate plus the reserve, with
// the addition saturating rather than wrapping.
//
// The saturation is not theoretical tidiness. An estimate that overflowed to a
// small number would produce a REQUIREMENT smaller than the archive, i.e. a
// preflight that passes on a disk with no room — the exact outcome this
// function exists to prevent, arrived at by arithmetic.
func requiredBytes(estimate uint64) uint64 {
	sum := estimate + proto.BackupTargetReserveBytes
	if sum < estimate {
		return ^uint64(0)
	}
	return sum
}

// BackupWrite lands one sealed archive on the target as a new generation.
//
// The order is the safety property, and it is the same shape as Claim's: every
// refusal happens before anything is created, and the last thing that happens
// is the rename that makes the generation visible.
//
//  1. validate the names — a staging name that is not a plain file name, or a
//     generation id that is not, never reaches the filesystem at all;
//  2. resolve the mount;
//  3. stat and re-hash the staged file, refusing on size or digest;
//  4. write into the generation's `.partial-` directory — the one the api's
//     ingest endpoint has been landing per-volume members into — and fsync
//     both files;
//  5. rename it into place and fsync the parent.
//
// A crash anywhere before (5) leaves a `.partial-*` directory and no
// generation, which is the correct failure: prune ignores it, the listing
// skips it, and the api's terminal hook removes it. A crash during (5) leaves
// a complete generation, because everything in it was already fsynced.
func BackupWrite(ctx context.Context, b Backend, stagingRoot string, cmd proto.BackupWriteCmd) (*proto.BackupWriteAck, error) {
	if err := checkPartUUID(cmd.PartUUID); err != nil {
		return nil, err
	}
	if !proto.BackupValidGenerationID(cmd.GenerationID) {
		return nil, fmt.Errorf("%w: %q is not a usable generation id", ErrStagingMissing, cmd.GenerationID)
	}
	if !proto.BackupValidStagingName(cmd.StagingName) {
		// Refused by SHAPE rather than sanitised, so this verb can never be
		// talked into reading a file somewhere else on the node.
		return nil, fmt.Errorf("%w: %q is not a plain file name", ErrStagingMissing, cmd.StagingName)
	}
	if strings.TrimSpace(cmd.Digest) == "" {
		return nil, fmt.Errorf("%w: the command carried no digest, so nothing can be verified", ErrDigestMismatch)
	}
	if strings.TrimSpace(stagingRoot) == "" {
		return nil, fmt.Errorf("%w: this agent has no staging root configured", ErrStagingMissing)
	}

	staged := filepath.Join(stagingRoot, cmd.StagingName)
	info, err := os.Stat(staged)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s", ErrStagingMissing, staged)
	}
	if cmd.SizeBytes > 0 && byteCount(info.Size()) != cmd.SizeBytes {
		return nil, fmt.Errorf("%w: the staged file is %d bytes and the api sealed %d",
			ErrDigestMismatch, info.Size(), cmd.SizeBytes)
	}
	sum, err := fileDigest(staged)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(sum, strings.TrimSpace(cmd.Digest)) {
		// §4.6: integrity is verified from a digest, never by decrypting. This
		// node holds no private key and could not open the archive if it wanted
		// to — re-hashing what it is about to copy is the whole check, and it
		// is a real one because the api hashed the same bytes.
		return nil, fmt.Errorf("%w: staged %s, expected %s", ErrDigestMismatch, sum, cmd.Digest)
	}

	mountPath, err := b.Mount(ctx, cmd.PartUUID)
	if errors.Is(err, ErrNotFound) {
		return &proto.BackupWriteAck{
			OK: false, PartUUID: cmd.PartUUID,
			Refusal: proto.StorageRefusalNotFound,
			Detail:  "no attached disk carries that partition UUID — the backup target is not plugged in",
		}, nil
	}
	if err != nil {
		return nil, err
	}

	gensDir := filepath.Join(mountPath, proto.BackupGenerationsDir)
	if err := os.MkdirAll(gensDir, 0o700); err != nil {
		return nil, err
	}
	final := filepath.Join(gensDir, cmd.GenerationID)
	if _, err := os.Stat(final); err == nil {
		// The api mints ids from a timestamp plus a job discriminator, so this
		// is a replay rather than a collision. Refused, not overwritten: the
		// generation already on the platter is a record of something that
		// happened, and the saga step that calls this is declared Irreversible
		// precisely so a second attempt is a human's decision.
		return nil, fmt.Errorf("refusing to write generation %s: it already exists at %s", cmd.GenerationID, final)
	}

	// The in-flight directory is `.partial-<generation>`, and it may ALREADY
	// EXIST: the api's ingest endpoint creates it at the start of the fan-out
	// and lands every per-volume member beneath it (proto.BackupPartialDirName
	// — one name, two writers). This verb adds the identity archive and the
	// manifest beside those members and renames the whole directory into
	// place, which is the commit for the generation as a unit. Adopted only
	// as a real directory: a symlink or a file of that name is refused.
	tmp := filepath.Join(gensDir, proto.BackupPartialDirName(cmd.GenerationID))
	if st, lerr := os.Lstat(tmp); lerr == nil {
		if !st.IsDir() {
			return nil, fmt.Errorf("refusing to write generation %s: %s exists and is not a directory", cmd.GenerationID, tmp)
		}
	} else if errors.Is(lerr, os.ErrNotExist) {
		if err := os.Mkdir(tmp, 0o700); err != nil {
			return nil, err
		}
	} else {
		return nil, lerr
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(tmp)
		}
	}()

	written, err := copyFileSync(staged, filepath.Join(tmp, proto.BackupArchiveFile))
	if err != nil {
		return nil, fmt.Errorf("write archive to %s: %w", mountPath, err)
	}
	manifest := cmd.ManifestJSON
	if strings.TrimSpace(manifest) == "" {
		// A generation with no readable manifest is a generation nobody can
		// tell the scope of, which is the failure this whole slice is shaped to
		// avoid. Refuse rather than write a nameless archive.
		return nil, errors.New("refusing to write a generation with no manifest: an archive nobody can read the scope of is exactly what this must never produce")
	}
	if err := writeFileSync(filepath.Join(tmp, proto.BackupManifestFile), []byte(manifest)); err != nil {
		return nil, fmt.Errorf("write manifest to %s: %w", mountPath, err)
	}
	if err := syncDir(tmp); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, final); err != nil {
		return nil, err
	}
	committed = true
	if err := syncDir(gensDir); err != nil {
		return nil, err
	}

	ack := &proto.BackupWriteAck{
		OK:       true,
		PartUUID: cmd.PartUUID,
		Generation: proto.BackupGeneration{
			ID:           cmd.GenerationID,
			ArchivePath:  filepath.Join(final, proto.BackupArchiveFile),
			ManifestPath: filepath.Join(final, proto.BackupManifestFile),
			SizeBytes:    byteCount(written),
			Digest:       sum,
			WrittenAt:    time.Now().UTC(),
			Scope:        scopeOf(manifest),
		},
	}
	if du, derr := disk.UsageWithContext(ctx, mountPath); derr == nil {
		ack.FreeBytes = du.Free
	}
	return ack, nil
}

// BackupPrune converges the target on §4.4's retention: Keep generations,
// newest first, oldest deleted.
//
// CONVERGENT, not imperative — the whole reason the api's prune step is
// retryable. Running this twice on a settled target deletes nothing the second
// time, because the second call finds Keep generations and stops. A
// "delete the oldest" verb would take a bite on every retry, which would make a
// lost ack on a slow USB disk cost a generation.
//
// Two things it refuses outright: a Keep below one (a prune that empties the
// disk is not a retention policy, and a zero-valued struct must not be able to
// express one), and deletion of ProtectGenerationID (the run's own output,
// which no clock skew or coarse filesystem timestamp may cost it).
func BackupPrune(ctx context.Context, b Backend, cmd proto.BackupPruneCmd) (*proto.BackupPruneAck, error) {
	if err := checkPartUUID(cmd.PartUUID); err != nil {
		return nil, err
	}
	if cmd.Keep < 1 {
		return nil, fmt.Errorf("refusing to prune with keep=%d: a retention that keeps nothing is not a retention policy", cmd.Keep)
	}
	mountPath, err := b.Mount(ctx, cmd.PartUUID)
	if errors.Is(err, ErrNotFound) {
		return &proto.BackupPruneAck{
			OK: false, PartUUID: cmd.PartUUID,
			Refusal: proto.StorageRefusalNotFound,
			Detail:  "no attached disk carries that partition UUID — the backup target is not plugged in",
		}, nil
	}
	if err != nil {
		return nil, err
	}
	gens, err := listGenerations(mountPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("list generations on %s: %w", mountPath, err)
	}
	ack := &proto.BackupPruneAck{OK: true, PartUUID: cmd.PartUUID}
	gensDir := filepath.Join(mountPath, proto.BackupGenerationsDir)
	for i, g := range gens {
		if i < cmd.Keep || (cmd.ProtectGenerationID != "" && g.ID == cmd.ProtectGenerationID) {
			ack.Kept = append(ack.Kept, g.ID)
			continue
		}
		// Only ever a directory this function found by listing the target's own
		// generations directory. The path is rebuilt from the listed name
		// rather than taken from anywhere the api could influence.
		if err := os.RemoveAll(filepath.Join(gensDir, g.ID)); err != nil {
			return nil, fmt.Errorf("prune generation %s: %w", g.ID, err)
		}
		ack.Pruned = append(ack.Pruned, g.ID)
	}
	if len(ack.Pruned) > 0 {
		_ = syncDir(gensDir)
	}
	if du, derr := disk.UsageWithContext(ctx, mountPath); derr == nil {
		ack.FreeBytes = du.Free
	}
	return ack, nil
}

// listGenerations reads the target's retained generations, NEWEST FIRST.
//
// Ordered by the archive file's modification time with the directory name as
// the tiebreak, rather than by parsing the timestamp out of the name. A
// generation an operator copied onto the disk by hand, or one restored from
// elsewhere, still sorts sensibly; and a name that does not parse is a
// generation, not a parse error.
//
// `.partial-*` directories — a write that crashed mid-copy — are skipped, not
// counted and not pruned. They are the write path's own litter and it removes
// them; treating one as a generation would let a crashed run push a real
// generation over the retention line.
func listGenerations(mountPath string) ([]proto.BackupGeneration, error) {
	gensDir := filepath.Join(mountPath, proto.BackupGenerationsDir)
	ents, err := os.ReadDir(gensDir)
	if err != nil {
		return nil, err
	}
	out := make([]proto.BackupGeneration, 0, len(ents))
	for _, e := range ents {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		g := proto.BackupGeneration{
			ID:           e.Name(),
			ArchivePath:  filepath.Join(gensDir, e.Name(), proto.BackupArchiveFile),
			ManifestPath: filepath.Join(gensDir, e.Name(), proto.BackupManifestFile),
		}
		if st, serr := os.Stat(g.ArchivePath); serr == nil {
			g.SizeBytes = byteCount(st.Size())
			g.WrittenAt = st.ModTime().UTC()
		} else if di, derr := e.Info(); derr == nil {
			g.WrittenAt = di.ModTime().UTC()
		}
		if raw, rerr := readCapped(g.ManifestPath, 1<<20); rerr == nil {
			g.Scope = scopeOf(string(raw))
		}
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].WrittenAt.Equal(out[j].WrittenAt) {
			return out[i].WrittenAt.After(out[j].WrittenAt)
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

// scopeOf pulls the `scope` field out of a manifest without committing this
// package to the manifest's full shape — which the api owns and will extend
// when the §4.5 volume fan-out becomes non-empty.
func scopeOf(manifest string) string {
	var probe struct {
		Scope string `json:"scope"`
	}
	if err := json.Unmarshal([]byte(manifest), &probe); err != nil {
		return ""
	}
	return probe.Scope
}

func readCapped(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, limit))
}

func fileDigest(path string) (string, error) {
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

// copyFileSync copies src to dst and fsyncs dst before returning. The fsync is
// the point: a generation that is in the page cache when the operator unplugs
// the USB disk is a generation that is not on it.
func copyFileSync(src, dst string) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return 0, err
	}
	n, cerr := io.Copy(out, in)
	if cerr != nil {
		_ = out.Close()
		return n, cerr
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return n, err
	}
	return n, out.Close()
}

func writeFileSync(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
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

func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// CleanStaging removes orphaned staged archives left by a run that died between
// sealing and writing — §4.7's "cleanup on failure and on boot".
//
// An orphaned staging file is a permanent disk leak with no owner and no alert,
// on the partition §5's budget table is about, and the archive is the largest
// single thing this product stages. Called at agent start.
//
// Only files DIRECTLY under the root, and only regular ones: a directory or a
// symlink under the staging root is not something this agent put there, and
// removing it is not this function's business.
func CleanStaging(root string) (removed int, freed int64) {
	ents, err := os.ReadDir(root)
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
		if err := os.Remove(filepath.Join(root, e.Name())); err == nil {
			removed++
			freed += info.Size()
		}
	}
	return removed, freed
}

// humanBytes renders a size for an operator-facing refusal. Deliberately
// coarse: the point of the sentence is "not enough, by roughly this much".
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
// or a completed io.Copy — but if one ever arrived, a bare `uint64(n)` would
// turn it into roughly eighteen exabytes, and every size comparison downstream
// (the write verb's staged-size check, the preflight's free-space arithmetic)
// would then be reasoning about that number. Clamping to zero keeps a nonsense
// input reading as "nothing", which is the direction those comparisons fail
// safely in.
func byteCount(n int64) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}
