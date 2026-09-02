package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// RunJobKind is the workflow kind for design/storage.md §4.1's backup producer:
// a normal saga on the normal job bus, visible in the Tasks feed like every
// other job. Scheduled weekly by default, and submitted on demand by the
// "Back up now" control.
const RunJobKind = "backup.run"

// ReasonScheduled and ReasonManual are §4.1's two producers, recorded on the
// run so an operator looking at a 3 a.m. failure knows which one it was.
const (
	ReasonScheduled = "scheduled"
	ReasonManual    = "manual"
)

// Step timeouts. Each api step's budget is its own work; each agent step's is
// the AGENT's budget from proto plus slack for the round trip and the marshal —
// the api must outwait the agent or it gives up on a handler about to answer.
//
// snapshot and assemble get generous budgets because they are I/O over the
// whole identity set on a machine whose storage may be an SD card.
const (
	runValidateTimeout  = 15 * time.Second
	runPreflightTimeout = proto.BackupPreflightWork + rpcSlack
	runSnapshotTimeout  = 20 * time.Minute
	runAssembleTimeout  = 20 * time.Minute
	runSealTimeout      = 20 * time.Minute
	runWriteTimeout     = proto.BackupWriteWork + 90*time.Second
	runPruneTimeout     = proto.BackupPruneWork + rpcSlack
)

// RunConfig is the environment a backup run executes in.
type RunConfig struct {
	// ClusterID is stamped into the manifest.
	ClusterID string
	// StagingDir is §4.7's staging path — where the snapshot, the assembled tar
	// and the sealed archive live, and the ONLY directory the agent's write verb
	// will read a file from. Both halves derive it from
	// RASPUTIN_BACKUP_STAGING_DIR; see StagingDir.
	StagingDir string
	// Sources says where the §4.5 identity set lives on this controlplane.
	Sources IdentitySources
	// DB is the live control-plane database, snapshotted with VACUUM INTO by
	// step 3. Never copied as a file — see SnapshotDB.
	DB *sql.DB
	// DBPath is the live database file, used only to SIZE it for the staging
	// guard before the snapshot is taken.
	DBPath string
	// Retain is §4.4's retention. Zero means proto.BackupRetainGenerations.
	Retain int
	// Store is the backup ledger, so the write step can record its generation
	// the moment it lands rather than at the end of the saga. Set by
	// RunWorkflow from its own argument — a caller never fills it in.
	Store *Store
}

func (c RunConfig) retain() int {
	if c.Retain <= 0 {
		return proto.BackupRetainGenerations
	}
	return c.Retain
}

// RunSpec is the spec body of a backup.run job.
//
// Deliberately tiny. Everything else — which disk, which key, how many
// generations — is POLICY, and §4.1 puts policy on the control plane. A spec
// that carried a partition UUID or a retention count would let a caller aim a
// run at a disk the operator never claimed, or empty the retained set, through
// the job ledger.
type RunSpec struct {
	// Reason is ReasonScheduled or ReasonManual. Anything else is normalised to
	// manual rather than refused: it is a label on a row, and refusing a backup
	// over it would be the wrong trade.
	Reason string `json:"reason,omitempty"`
}

// ParseRunSpec decodes a run spec. Every failure is a step-1 refusal, which is
// the cheapest kind: nothing has been read, staged or written.
func ParseRunSpec(raw json.RawMessage) (*RunSpec, error) {
	spec := RunSpec{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &spec); err != nil {
			return nil, fmt.Errorf("invalid spec: %w", err)
		}
	}
	if spec.Reason != ReasonScheduled {
		spec.Reason = ReasonManual
	}
	return &spec, nil
}

// RunWorkflow returns the seven-step backup.run saga.
//
//	1 validate     api    a claimed target exists, resolved by partition UUID,
//	                      with a §4.6 public key; no other run is in flight
//	2 preflight    agent  the target is present, mounted and has room (§4.4)
//	3 snapshot_db  api    VACUUM INTO — never a file copy of a live database
//	4 assemble     api    the §4.5 identity set + the manifest, INCLUDING the
//	                      declared-but-empty app-volume fan-out
//	5 seal         api    encrypt to the target's PUBLIC key, fresh ephemeral
//	                      per run; record a digest
//	6 write        agent  THE IRREVERSIBLE STEP — land the sealed archive as a
//	                      new generation
//	7 prune        agent  converge on §4.4's four generations
//
// # Why the order is what it is
//
// jobs.Runner has no compensation: a step's failure leaves every prior step
// exactly as it ran. So every refusal that can happen has to happen before the
// write, and the write is the last thing that changes the target's contents
// except for the prune that follows it.
//
// # Why step 7 is NOT Irreversible, when it deletes archives
//
// This is the one judgement call in the file worth stating out loud, because
// "it deletes data, therefore mark it Irreversible" is the obvious reading and
// it is the wrong one.
//
// Irreversible means: running this step twice does the thing twice. It is for a
// `dd`, a mkfs, a mint-and-hand-out of a credential. proto.BackupPruneCmd is
// not that shape — it is DECLARATIVE. It says "the target should end up holding
// Keep generations", so a second run on a settled target finds Keep generations
// and deletes nothing. The effect does not compound.
//
// And the cost of marking it Irreversible would be real. A prune that is never
// retried leaves the target OVER-RETAINED after any transient failure — a lost
// ack on a slow USB disk, an RPC timeout — and an over-retained target fills,
// which is precisely §4.4's stated failure mode ("a full-every-week policy with
// no space guard fails on the same night every week once the disk fills"). So
// refusing to retry would make the disk-full outcome MORE likely, in exchange
// for protecting against a compounding effect that cannot occur.
//
// The protections that actually matter for prune are on the verb instead:
// keep < 1 is refused outright, the run's own generation is named in
// ProtectGenerationID and never deleted, and prune only ever removes a
// directory it found by listing the target's own generations directory. And its
// PLACE in the saga is a protection too: it runs after the write, so a failure
// here leaves a complete, fresh backup on the disk and an over-retained set —
// the benign side of the trade.
func RunWorkflow(store *Store, cfg RunConfig) jobs.Workflow {
	cfg.Store = store
	return jobs.Workflow{
		Kind: RunJobKind,
		Steps: []jobs.WorkflowStep{
			{Name: "validate", Timeout: runValidateTimeout, Do: runValidate(store)},
			{Name: "preflight", Timeout: runPreflightTimeout, Retries: 1, Do: runPreflight(cfg)},
			{Name: "snapshot_db", Timeout: runSnapshotTimeout, Do: runSnapshotDB(cfg)},
			{Name: "assemble", Timeout: runAssembleTimeout, Do: runAssemble(cfg)},
			{Name: "seal", Timeout: runSealTimeout, Do: runSeal(cfg)},
			// Irreversible: the runner refuses to retry it, and refuses to
			// re-run it for a job whose ledger already records an attempt. A
			// generation is a file on somebody's disk; a second attempt is a
			// human's decision, not a backoff's.
			{Name: "write", Timeout: runWriteTimeout, Retries: 0, Irreversible: true, Do: runWrite(cfg)},
			{Name: "prune", Timeout: runPruneTimeout, Retries: 1, Do: runPrune(store, cfg)},
		},
		OnTerminal: finalizeRunRow(store, cfg),
	}
}

// ----- Step results -------------------------------------------------------
//
// Typed structs, and every one of them is a published surface: a step result is
// persisted in the job ledger and rendered in the Tasks view. So the rule that
// governs every field below is the same one ClaimWorkflow's results follow —
// identifiers, sizes, digests and prose, and NOTHING key-shaped. The archive
// public key is the one piece of §4.6 material that appears, because it is a
// public key and §4.6's amendment is precisely that a public key at rest is
// harmless.

// runTarget is step 1's verdict: which target this run writes to.
type runTarget struct {
	TargetJobID string `json:"targetJobId"`
	PartUUID    string `json:"partUuid"`
	NodeID      string `json:"nodeId"`
	Label       string `json:"label,omitempty"`
	MountPath   string `json:"mountPath,omitempty"`
	KeyID       string `json:"keyId,omitempty"`
	// PublicKey is the X25519 public key step 5 seals to. In clear, which is
	// the 2026-09-02 amendment and not an exception to the rule above.
	PublicKey string `json:"publicKey"`
	// GenerationID is minted here, at the start, so every later step and every
	// log line names the same generation — including the ones that run before
	// anything has been written.
	GenerationID string `json:"generationId"`
	Scope        string `json:"scope"`
	Reason       string `json:"reason"`
	// EstimateBytes is the measured size of the §4.5 identity set, used as the
	// target-side preflight estimate. A measurement, not a guess.
	EstimateBytes uint64 `json:"estimateBytes"`
}

// runPreflightResult is what the target said about itself.
type runPreflightResult struct {
	PartUUID         string `json:"partUuid"`
	MountPath        string `json:"mountPath,omitempty"`
	TotalBytes       uint64 `json:"totalBytes,omitempty"`
	FreeBytes        uint64 `json:"freeBytes,omitempty"`
	RequiredBytes    uint64 `json:"requiredBytes,omitempty"`
	GenerationsFound int    `json:"generationsFound"`
}

// runSnapshotResult is step 3's output. StagingName is a plain file name, never
// a path: it is what the agent joins onto ITS staging root.
type runSnapshotResult struct {
	StagingName string        `json:"stagingName"`
	SizeBytes   uint64        `json:"sizeBytes"`
	Budget      StagingBudget `json:"budget"`
}

// runAssembleResult is step 4's, and it is the first place the empty fan-out
// becomes a fact in the ledger rather than a property of the code.
type runAssembleResult struct {
	StagingName string `json:"stagingName"`
	SizeBytes   uint64 `json:"sizeBytes"`
	Scope       string `json:"scope"`
	Complete    bool   `json:"complete"`
	EntryCount  int    `json:"entryCount"`
	// AppVolumesCaptured is 0, and it is in the step result so the Tasks view
	// renders a number rather than an absence.
	AppVolumesCaptured int `json:"appVolumesCaptured"`
	// Warning is the fan-out's prose, verbatim.
	Warning string `json:"warning"`
	// ManifestJSON is the clear-text sidecar the agent writes beside the
	// archive. Carried through the ledger because it IS the honest record and
	// there is nothing in it that should not be readable.
	ManifestJSON string `json:"manifestJson"`
}

// runSealResult is step 5's. See SealResult for why no secret can be here.
type runSealResult struct {
	StagingName string      `json:"stagingName"`
	Seal        *SealResult `json:"seal"`
}

// runWriteResult is step 6's.
type runWriteResult struct {
	GenerationID string `json:"generationId"`
	ArchivePath  string `json:"archivePath,omitempty"`
	SizeBytes    uint64 `json:"sizeBytes"`
	Digest       string `json:"digest"`
	FreeBytes    uint64 `json:"freeBytes,omitempty"`
}

// ----- Step 1: validate ---------------------------------------------------

// runValidate is the whole of the api's own policy check, and it is where four
// separate refusals live. Each of them costs a re-run; none of them touches a
// disk.
func runValidate(store *Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		spec, err := ParseRunSpec(sc.Spec)
		if err != nil {
			return nil, err
		}

		// A second run while one is in flight is refused BEFORE the row is
		// created, so the refusal cannot be the thing that makes the ledger
		// look busy. Two runs staging archives at once is exactly the disk
		// pressure §4.7 warns about, and the weekly schedule colliding with an
		// operator's "Back up now" is the normal way it would happen.
		running, err := store.ListRunning(sc.Ctx)
		if err != nil {
			return nil, fmt.Errorf("in-flight runs: %w", err)
		}
		for _, r := range running {
			if r.JobID != sc.JobID {
				return nil, fmt.Errorf("a backup is already running (job %s, started %s). Only one runs at a time — two archives staged at once is how a backup fills the disk it is protecting",
					r.JobID, r.StartedAt.Format(time.RFC3339))
			}
		}

		claimed, err := store.ListClaimed(sc.Ctx)
		if err != nil {
			return nil, fmt.Errorf("claimed targets: %w", err)
		}
		if len(claimed) == 0 {
			// §4.4's install-time gate says a `critical` app may be installed
			// with no backup target — loudly. The consequence lands here: a
			// scheduled run with no target fails with a sentence saying what to
			// do, rather than succeeding at nothing.
			return nil, errors.New("no backup target is claimed, so there is nowhere to write. Claim a disk under Storage → Backups first — until then nothing on this cluster is backed up anywhere")
		}
		target := claimed[0]
		if strings.TrimSpace(target.PartUUID) == "" {
			return nil, fmt.Errorf("the claimed backup target (%s on %s) has no partition UUID recorded, which is the only identifier a target has. Re-claim the disk",
				displayLabel(target.Label), target.NodeID)
		}
		if strings.TrimSpace(target.PublicKey) == "" {
			// The single most consequential refusal in the saga. See
			// ErrNoPublicKey: writing in clear here would put an unencrypted,
			// portable copy of every secret in the cluster on a disk somebody
			// can unplug, which is the exposure §4.6 exists to close, on the
			// path where nobody is watching.
			return nil, fmt.Errorf("the claimed backup target (%s, partUuid %s) has no archive public key, so an archive cannot be encrypted to it — and this will not write one in clear. "+
				"Targets claimed before encryption was configured, or under the earlier symmetric design, are in this state; re-claim the disk to mint a keypair",
				displayLabel(target.Label), target.PartUUID)
		}
		if err := validatePublicKey(target.PublicKey); err != nil {
			return nil, fmt.Errorf("the claimed backup target's archive public key is unusable: %w. Nothing was written; re-claim the disk", err)
		}

		now := time.Now().UTC()
		gen := proto.BackupGenerationID(now, sc.JobID, proto.BackupScopeIdentityOnly)
		if err := store.StartRun(sc.Ctx, sc.JobID, spec.Reason, proto.BackupScopeIdentityOnly, now); err != nil {
			return nil, fmt.Errorf("record backup run: %w", err)
		}
		if err := store.BindRunTarget(sc.Ctx, sc.JobID, target.JobID, target.PartUUID, target.NodeID, target.KeyID); err != nil {
			return nil, fmt.Errorf("bind run to target: %w", err)
		}

		out := runTarget{
			TargetJobID:  target.JobID,
			PartUUID:     target.PartUUID,
			NodeID:       target.NodeID,
			Label:        target.Label,
			MountPath:    target.MountPath,
			KeyID:        target.KeyID,
			PublicKey:    target.PublicKey,
			GenerationID: gen,
			Scope:        proto.BackupScopeIdentityOnly,
			Reason:       spec.Reason,
		}
		sc.Log("info", fmt.Sprintf("backup run %s → target %s (partUuid %s) on %s, sealing to key %s",
			gen, displayLabel(target.Label), target.PartUUID, target.NodeID, displayLabel(target.KeyID)))
		// Said at the START of every run, not only in the manifest at the end.
		// An operator watching the live stream should learn the scope before
		// the run has done anything, so "my apps are not in this" is never a
		// discovery made after the fact.
		sc.Log("warn", "SCOPE: "+appVolumeFanOutReason)
		return json.Marshal(out)
	}
}

// ----- Step 2: preflight --------------------------------------------------

// runPreflight is §4.4's pre-flight free-space check, on the TARGET side. The
// SOURCE side's guard is step 3's, because it needs a measurement step 3 makes.
func runPreflight(cfg RunConfig) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		tgt, err := priorRunTarget(sc)
		if err != nil {
			return nil, err
		}
		// Size the estimate from the live identity set. A measurement, so the
		// target-side check is against real numbers rather than a constant that
		// was true when it was written.
		estimate := MeasureIdentitySet(cfg.Sources, fileSize(cfg.DBPath))
		cmd, err := json.Marshal(proto.BackupPreflightCmd{
			PartUUID: tgt.PartUUID, EstimateBytes: estimate,
		})
		if err != nil {
			return nil, err
		}
		msg, err := sc.NATS.RequestWithContext(sc.Ctx, proto.BackupPreflightSubject(tgt.NodeID), cmd)
		if err != nil {
			return nil, fmt.Errorf("backup preflight rpc to %s: %w", tgt.NodeID, err)
		}
		var ack proto.BackupPreflightAck
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			return nil, fmt.Errorf("backup preflight: unreadable reply from %s: %w", tgt.NodeID, err)
		}
		if !ack.Present {
			return nil, fmt.Errorf("the backup target (partUuid %s) is not attached to %s — it was unplugged. Nothing was written",
				tgt.PartUUID, tgt.NodeID)
		}
		if !ack.OK {
			return nil, refusalError("backup preflight on "+tgt.NodeID, ack.Refusal, ack.Detail)
		}
		res := runPreflightResult{
			PartUUID: tgt.PartUUID, MountPath: ack.MountPath,
			TotalBytes: ack.TotalBytes, FreeBytes: ack.FreeBytes,
			RequiredBytes: ack.RequiredBytes, GenerationsFound: len(ack.Generations),
		}
		sc.Log("info", fmt.Sprintf("target %s: %s free of %s, %d generation(s) retained; this run needs about %s",
			ack.MountPath, humanBytes(ack.FreeBytes), humanBytes(ack.TotalBytes),
			len(ack.Generations), humanBytes(ack.RequiredBytes)))
		return json.Marshal(res)
	}
}

// ----- Step 3: snapshot_db ------------------------------------------------

// runSnapshotDB takes a consistent snapshot of the live database, guarded by
// §4.7's source-side free-space check.
//
// The guard runs FIRST, before a byte is written, because the thing being
// guarded against is this step filling `/var/lib/rasputin` — the partition with
// a real 100%-full incident on record. See staging.go for the arithmetic and
// for what is deliberately left to #393.
func runSnapshotDB(cfg RunConfig) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		tgt, err := priorRunTarget(sc)
		if err != nil {
			return nil, err
		}
		if err := EnsureStagingDir(cfg.StagingDir); err != nil {
			return nil, fmt.Errorf("staging dir %s: %w", cfg.StagingDir, err)
		}
		dbBytes := fileSize(cfg.DBPath)
		identityBytes := MeasureIdentitySet(cfg.Sources, dbBytes)
		budget, err := PlanStaging(cfg.StagingDir, dbBytes, identityBytes)
		if err != nil {
			return nil, err
		}
		sc.Log("info", fmt.Sprintf("staging %s: %s free, this run peaks at about %s plus a %s reserve",
			cfg.StagingDir, humanBytes(budget.FreeBytes), humanBytes(budget.PeakBytes),
			humanBytes(budget.ReserveBytes)))

		name := stagingName(tgt.GenerationID, "db")
		dst := filepath.Join(cfg.StagingDir, name)
		// A leftover from a previous attempt is removed rather than adopted:
		// SnapshotDB refuses to write onto an existing file, and adopting a
		// stale snapshot would mean sealing yesterday's database as today's.
		_ = os.Remove(dst)
		size, err := SnapshotDB(sc.Ctx, cfg.DB, dst)
		if err != nil {
			_ = os.Remove(dst)
			return nil, err
		}
		sc.Log("info", fmt.Sprintf("database snapshot via VACUUM INTO: %s (live database is %s)",
			humanBytes(size), humanBytes(dbBytes)))
		return json.Marshal(runSnapshotResult{StagingName: name, SizeBytes: size, Budget: budget})
	}
}

// ----- Step 4: assemble ---------------------------------------------------

func runAssemble(cfg RunConfig) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		tgt, err := priorRunTarget(sc)
		if err != nil {
			return nil, err
		}
		var snap runSnapshotResult
		if err := priorResult(sc, "snapshot_db", &snap); err != nil {
			return nil, err
		}
		snapPath := filepath.Join(cfg.StagingDir, snap.StagingName)

		name := stagingName(tgt.GenerationID, "tar")
		dst := filepath.Join(cfg.StagingDir, name)
		_ = os.Remove(dst)
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err != nil {
			return nil, fmt.Errorf("stage archive: %w", err)
		}
		manifest, aerr := Assemble(f, AssembleOptions{
			Sources:      cfg.Sources,
			SnapshotPath: snapPath,
			GenerationID: tgt.GenerationID,
			JobID:        sc.JobID,
			ClusterID:    cfg.ClusterID,
			KeyID:        tgt.KeyID,
			Now:          time.Now().UTC(),
		})
		if cerr := f.Close(); cerr != nil && aerr == nil {
			aerr = cerr
		}
		if aerr != nil {
			// Both artefacts, not just this step's. The snapshot is a plaintext
			// copy of the whole database; leaving it for the boot sweep means
			// leaving it on disk until the next restart.
			_ = os.Remove(dst)
			_ = os.Remove(snapPath)
			return nil, aerr
		}
		// The snapshot's job is done the moment it is inside the tar. Deleting
		// it here rather than at the end of the saga is what keeps §4.7's peak
		// residency down to the tar plus the sealed archive.
		_ = os.Remove(snapPath)

		manifestJSON, err := manifest.JSON()
		if err != nil {
			_ = os.Remove(dst)
			return nil, err
		}
		info, err := os.Stat(dst)
		if err != nil {
			return nil, err
		}
		for _, e := range manifest.Entries {
			sc.Log("info", fmt.Sprintf("captured %s (%s)", e.Path, humanBytes(uint64(e.SizeBytes))))
		}
		// The fan-out phase's own line in the job feed. It runs on every backup
		// and reports what it found, which is nothing — see FanOutAppVolumes.
		sc.Log("warn", fmt.Sprintf("app-volume fan-out: %d volume(s) captured across %d node(s). %s",
			manifest.AppVolumes.CapturedCount, manifest.AppVolumes.NodesConsulted, manifest.AppVolumes.Reason))

		return json.Marshal(runAssembleResult{
			StagingName:        name,
			SizeBytes:          uint64(info.Size()),
			Scope:              manifest.Scope,
			Complete:           manifest.Complete,
			EntryCount:         len(manifest.Entries),
			AppVolumesCaptured: manifest.AppVolumes.CapturedCount,
			Warning:            manifest.Warning,
			ManifestJSON:       string(manifestJSON),
		})
	}
}

// ----- Step 5: seal -------------------------------------------------------

func runSeal(cfg RunConfig) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		tgt, err := priorRunTarget(sc)
		if err != nil {
			return nil, err
		}
		var asm runAssembleResult
		if err := priorResult(sc, "assemble", &asm); err != nil {
			return nil, err
		}
		src := filepath.Join(cfg.StagingDir, asm.StagingName)
		in, err := os.Open(src)
		if err != nil {
			return nil, fmt.Errorf("open assembled archive: %w", err)
		}
		defer func() { _ = in.Close() }()

		name := stagingName(tgt.GenerationID, "sealed")
		dst := filepath.Join(cfg.StagingDir, name)
		_ = os.Remove(dst)
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err != nil {
			return nil, fmt.Errorf("stage sealed archive: %w", err)
		}
		res, serr := Seal(out, in, tgt.PublicKey, tgt.KeyID, asm.Scope)
		if serr == nil {
			// fsync before the agent is told the file exists: the write verb
			// re-hashes what it finds on disk, and a sealed archive still in
			// the page cache when the api dies is a digest mismatch at best.
			serr = out.Sync()
		}
		if cerr := out.Close(); cerr != nil && serr == nil {
			serr = cerr
		}
		if serr != nil {
			// The tar goes with it. It is the plaintext identity set — the mesh
			// CA's private key and the whole database — and a failed seal is
			// exactly the case where it would otherwise linger longest.
			_ = os.Remove(dst)
			_ = os.Remove(src)
			return nil, serr
		}
		// The plaintext tar is deleted the instant it has been sealed. It is a
		// clear copy of the mesh CA's private key and the whole database; the
		// window in which it exists on disk is the one thing this step can
		// shorten, and this is where it shortens it.
		_ = os.Remove(src)

		sc.Log("info", fmt.Sprintf("sealed %s to key %s (%s plaintext → %s sealed, sha256 %s)",
			tgt.GenerationID, displayLabel(tgt.KeyID),
			humanBytes(res.PlaintextBytes), humanBytes(res.SizeBytes), short(res.Digest)))
		return json.Marshal(runSealResult{StagingName: name, Seal: res})
	}
}

// ----- Step 6: write ------------------------------------------------------

// runWrite lands the sealed archive as a new generation. THE IRREVERSIBLE STEP.
//
// Like ClaimWorkflow's claim step, it acts only on what earlier steps produced
// and re-derives nothing: a missing seal result fails the job with nothing
// written, rather than reconstructing its own authorization.
func runWrite(cfg RunConfig) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		tgt, err := priorRunTarget(sc)
		if err != nil {
			return nil, err
		}
		var asm runAssembleResult
		if err := priorResult(sc, "assemble", &asm); err != nil {
			return nil, err
		}
		var sealed runSealResult
		if err := priorResult(sc, "seal", &sealed); err != nil {
			return nil, err
		}
		if sealed.Seal == nil || sealed.Seal.Digest == "" {
			return nil, errors.New("refusing to write: the seal step produced no digest, so nothing can verify what would be written")
		}
		cmd, err := json.Marshal(proto.BackupWriteCmd{
			PartUUID:     tgt.PartUUID,
			GenerationID: tgt.GenerationID,
			StagingName:  sealed.StagingName,
			Digest:       sealed.Seal.Digest,
			SizeBytes:    sealed.Seal.SizeBytes,
			ManifestJSON: asm.ManifestJSON,
		})
		if err != nil {
			return nil, err
		}
		sc.Log("info", fmt.Sprintf("writing generation %s (%s) to the backup target on %s",
			tgt.GenerationID, humanBytes(sealed.Seal.SizeBytes), tgt.NodeID))
		msg, err := sc.NATS.RequestWithContext(sc.Ctx, proto.BackupWriteSubject(tgt.NodeID), cmd)
		if err != nil {
			return nil, fmt.Errorf("backup write rpc to %s: %w", tgt.NodeID, err)
		}
		var ack proto.BackupWriteAck
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			return nil, fmt.Errorf("backup write: unreadable reply from %s: %w", tgt.NodeID, err)
		}
		if !ack.OK {
			return nil, refusalError("backup write to "+tgt.NodeID, ack.Refusal, ack.Detail)
		}
		// The staged copy is removed once the agent says it landed. Not before:
		// the agent reads it, so deleting it earlier would break the very RPC
		// that is in flight. And not never: §4.7's third discipline is that an
		// orphaned staging file is a permanent disk leak with no owner.
		_ = os.Remove(filepath.Join(cfg.StagingDir, sealed.StagingName))

		// Recorded NOW, not at the end of the saga. Step 7 runs after this one,
		// so a prune failure would otherwise leave a `failed` row naming no
		// generation while a complete, fresh archive sat on the target — and an
		// operator reading that row would conclude they had no backup from
		// tonight. They do. Best-effort: a ledger write that fails must not
		// un-write a generation that is already on the platter.
		if err := cfg.Store.MarkRunGeneration(sc.Ctx, sc.JobID, ack.Generation.ID,
			ack.Generation.Digest, ack.Generation.SizeBytes, asm.AppVolumesCaptured); err != nil {
			log.Printf("storage: record generation %s for run %s: %v", ack.Generation.ID, sc.JobID, err)
		}
		sc.Log("info", fmt.Sprintf("generation %s written: %s at %s (%s free on the target)",
			ack.Generation.ID, humanBytes(ack.Generation.SizeBytes), ack.Generation.ArchivePath,
			humanBytes(ack.FreeBytes)))
		return json.Marshal(runWriteResult{
			GenerationID: ack.Generation.ID,
			ArchivePath:  ack.Generation.ArchivePath,
			SizeBytes:    ack.Generation.SizeBytes,
			Digest:       ack.Generation.Digest,
			FreeBytes:    ack.FreeBytes,
		})
	}
}

// ----- Step 7: prune ------------------------------------------------------

// runPrune converges the target on §4.4's retention and records the run.
//
// It also does the ledger write for the whole saga, because it is the last
// step: a run is not "done" until the disk holds four generations and the row
// says which one this run added.
func runPrune(store *Store, cfg RunConfig) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		tgt, err := priorRunTarget(sc)
		if err != nil {
			return nil, err
		}
		var asm runAssembleResult
		if err := priorResult(sc, "assemble", &asm); err != nil {
			return nil, err
		}
		var wrote runWriteResult
		if err := priorResult(sc, "write", &wrote); err != nil {
			return nil, err
		}
		keep := cfg.retain()
		cmd, err := json.Marshal(proto.BackupPruneCmd{
			PartUUID: tgt.PartUUID, Keep: keep,
			// The run's own output, named so no ordering accident can cost it.
			ProtectGenerationID: wrote.GenerationID,
		})
		if err != nil {
			return nil, err
		}
		msg, err := sc.NATS.RequestWithContext(sc.Ctx, proto.BackupPruneSubject(tgt.NodeID), cmd)
		if err != nil {
			return nil, fmt.Errorf("backup prune rpc to %s: %w", tgt.NodeID, err)
		}
		var ack proto.BackupPruneAck
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			return nil, fmt.Errorf("backup prune: unreadable reply from %s: %w", tgt.NodeID, err)
		}
		if !ack.OK {
			return nil, refusalError("backup prune on "+tgt.NodeID, ack.Refusal, ack.Detail)
		}
		if len(ack.Pruned) > 0 {
			sc.Log("info", fmt.Sprintf("retention: kept %d generation(s), pruned %d oldest (%s)",
				len(ack.Kept), len(ack.Pruned), strings.Join(ack.Pruned, ", ")))
		} else {
			sc.Log("info", fmt.Sprintf("retention: %d generation(s) retained, nothing to prune", len(ack.Kept)))
		}

		if err := store.FinishRun(sc.Ctx, sc.JobID, RunResult{
			GenerationID:       wrote.GenerationID,
			Digest:             wrote.Digest,
			SizeBytes:          wrote.SizeBytes,
			AppVolumesCaptured: asm.AppVolumesCaptured,
			GenerationsKept:    len(ack.Kept),
			GenerationsPruned:  len(ack.Pruned),
			At:                 time.Now().UTC(),
		}); err != nil {
			return nil, fmt.Errorf("record backup run outcome: %w", err)
		}
		// Last word on a successful run, and it is the caveat rather than the
		// congratulation. A run that ends "backup complete" would be a false
		// statement about what is on that disk.
		sc.Log("warn", fmt.Sprintf("generation %s is on the target. It contains the controlplane's identity and NO app data — %s",
			wrote.GenerationID, appVolumeFanOutReason))
		return json.Marshal(map[string]any{
			"kept":               ack.Kept,
			"pruned":             ack.Pruned,
			"retain":             keep,
			"freeBytes":          ack.FreeBytes,
			"scope":              asm.Scope,
			"appVolumesCaptured": asm.AppVolumesCaptured,
		})
	}
}

// ----- OnTerminal ---------------------------------------------------------

// finalizeRunRow gives the backup_runs row a terminal status on EVERY path the
// job can end on — ADR-0005 Decision 5, and the #53 lesson that
// finalizeTargetRow was written for.
//
// It matters more here than it does for a claim. §4.4 requires failure to be
// LOUD, and a run stranded `running` is the opposite: it renders as a backup
// still in progress, indefinitely, which is the one appearance a failed backup
// must never be able to take. The OVERDUE tile and the alert path (#298) will
// read this table; a row that never reaches `failed` is a row those never fire
// on.
func finalizeRunRow(store *Store, cfg RunConfig) func(context.Context, string, bool, string) {
	return func(ctx context.Context, jobID string, success bool, errMsg string) {
		row, err := store.GetRun(ctx, jobID)
		if err != nil || row == nil {
			return // not a backup run, or the row was never created
		}
		// §4.7's third discipline, on every terminal path: a run that died
		// between sealing and writing leaves the sealed archive staged, and an
		// orphaned staging file is a permanent disk leak with no owner and no
		// alert. The per-step error paths clean up what they can see; this is
		// the backstop for the ones that cannot (a write that failed after the
		// agent had already been handed the name).
		//
		// A blanket sweep is safe because step 1 refuses to start a second run
		// while one is in flight, so there is never another run's staged
		// artefact here to destroy.
		if cfg.StagingDir != "" {
			if n, freed := CleanStaging(cfg.StagingDir); n > 0 {
				log.Printf("storage: backup run %s left %d staged file(s) behind; removed them (%d bytes)", jobID, n, freed)
			}
		}
		if row.Status != RunRunning {
			return // already has a verdict
		}
		if errMsg == "" {
			// A job that succeeded with its row still running means a step
			// ended the saga without recording an outcome. Say so rather than
			// inventing a generation that is not on any disk.
			errMsg = "job ended without recording a backup generation"
		}
		if err := store.FailRun(ctx, jobID, errMsg, time.Now().UTC()); err != nil {
			log.Printf("storage: finalize backup run %s: %v", jobID, err)
			return
		}
		log.Printf("storage: backup run %s finalized as failed (%s)", jobID, errMsg)
	}
}

// ReconcileStrandedRuns finalizes running rows whose job is already terminal.
// Called once at api start, for the same reason ReconcileStrandedRows is: the
// hook cannot reach back to a row stranded by a process that died between
// failing the job and firing it.
func ReconcileStrandedRuns(ctx context.Context, store *Store, jobStore *jobs.Store) error {
	rows, err := store.ListRunning(ctx)
	if err != nil {
		return err
	}
	for _, row := range rows {
		j, err := jobStore.GetJob(ctx, row.JobID)
		if err != nil || j == nil {
			continue
		}
		if j.Status != jobs.StatusFailed && j.Status != jobs.StatusSucceeded {
			continue // still genuinely running
		}
		msg := j.Error
		if msg == "" {
			msg = "job reached a terminal state without recording a backup generation"
		}
		if err := store.FailRun(ctx, row.JobID, msg, time.Now().UTC()); err != nil {
			log.Printf("storage: reconcile stranded backup run %s: %v", row.JobID, err)
			continue
		}
		log.Printf("storage: reconciled stranded backup run %s (job already %s)", row.JobID, j.Status)
	}
	return nil
}

// ----- helpers ------------------------------------------------------------

// priorRunTarget reads step 1's verdict.
//
// There is deliberately NO fallback that re-derives it from the store, the way
// claimCheckExisting re-derives an enumeration. Step 1 is where the run's
// generation id is minted and where the target is bound to the ledger row; a
// step that reconstructed a target for itself could write a generation to a
// disk that the recorded run does not name.
func priorRunTarget(sc *jobs.StepCtx) (*runTarget, error) {
	var tgt runTarget
	if err := priorResult(sc, "validate", &tgt); err != nil {
		return nil, err
	}
	if tgt.PartUUID == "" || tgt.NodeID == "" || tgt.GenerationID == "" {
		return nil, errors.New("the validate step left no usable target, so nothing has decided where this backup would go")
	}
	return &tgt, nil
}

func priorResult(sc *jobs.StepCtx, step string, into any) error {
	raw, ok := sc.PriorResults[step]
	if !ok || len(raw) == 0 {
		return fmt.Errorf("step %q left no result; a backup step does not reconstruct its own inputs", step)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("decode %q result: %w", step, err)
	}
	return nil
}

// stagingName builds the plain file name a staged artefact gets. It must
// satisfy proto.BackupValidStagingName, which is what the agent checks before
// it will read anything.
func stagingName(generationID, kind string) string {
	return generationID + "." + kind
}

// fileSize is the size of a file, or zero if it cannot be read. Zero is a safe
// answer for the two callers: the staging guard sizes UP from it (a zero
// contribution only makes the estimate smaller, and the database is always
// present in production), and the preflight estimate is advisory.
func fileSize(path string) uint64 {
	if strings.TrimSpace(path) == "" {
		return 0
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return 0
	}
	return uint64(info.Size())
}
