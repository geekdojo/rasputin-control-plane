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
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/backupxfer"
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
	// runFanOutTimeout bounds the WHOLE app-volume phase, not one volume: each
	// stage RPC is separately bounded at the agent's own budget plus slack, and
	// the phase stops asking for more volumes when what is left of this budget
	// would not cover another one — recording the rest as not captured rather
	// than being cut off mid-copy with an app stopped.
	//
	// Two hours because the phase is serial by design and a `stop`-strategy
	// volume on an SD card is genuinely slow. A cluster whose app data cannot
	// be staged inside two hours has a backup that does not fit its weekly
	// window, and the record of which volumes were dropped is the signal.
	runFanOutTimeout   = runFanOutBudget
	runAssembleTimeout = 20 * time.Minute
	// runFanOutBudget is the same number, named, because the fan-out quotes it
	// back to an operator when it runs out of it.
	runFanOutBudget = 2 * time.Hour
	runSealTimeout  = 20 * time.Minute
	runWriteTimeout = proto.BackupWriteWork + 90*time.Second
	runPruneTimeout = proto.BackupPruneWork + rpcSlack
)

// RunConfig is the environment a backup run executes in.
type RunConfig struct {
	// ClusterID is stamped into the manifest.
	ClusterID string
	// SelfNodeID is the node this api runs on, and step 1 refuses any target
	// that is not on it.
	//
	// Not a tidiness check. A run seals the IDENTITY archive on THIS host and
	// hands the agent a file name to find on ITS host, and the ingest endpoint
	// writes volume members under the mount that agent reports — so both
	// handoffs only exist when the two are the same machine. (App volumes on
	// OTHER nodes travel over the transport and do not need this; the target
	// disk itself still has to be on the controlplane.) And since the staging
	// directory and the mount path arrive in that node's preflight ack,
	// accepting either from a node the api does not share a filesystem with would
	// mean letting a remote party name a directory this process creates files
	// in and sweeps files out of. Refusing at step 1 closes both: the only
	// staging root this api will ever act on comes from the agent running
	// beside it, which is already root on the same box and gains nothing by
	// steering the api.
	//
	// Empty refuses every run rather than defaulting to "trust whoever
	// answers": see runValidate.
	SelfNodeID string
	// Sources says where the §4.5 identity set lives on this controlplane.
	Sources IdentitySources
	// Apps and Tiles are the two halves of §4.5's app-volume enumeration, and
	// there is deliberately no third: the api's `apps` rows say what is
	// installed, on which node, from which tile, and the catalog says what
	// volumes that tile declares and how §4.2 classes each one. See
	// PlanAppVolumes.
	//
	// Both are required. A run that could not enumerate installed apps would
	// write an archive that silently contains no app data — which is exactly
	// the outcome this whole slice exists to make impossible — so step 1
	// refuses rather than proceeding without them.
	Apps  AppLister
	Tiles TileVolumes
	// Inventory is what the fan-out consults when nobody on a node answers a
	// stage request, so the manifest says whether the node was offline or
	// online with an agent that predates the verb
	// (inventory.ExplainNoResponder). Nil reads every silence as offline —
	// the 2026-09-04 e3bench misreport — so main wires it and only the tests
	// that are not about it leave it out.
	Inventory *inventory.Store
	// DB is the live control-plane database, snapshotted with VACUUM INTO by
	// step 3. Never copied as a file — see SnapshotDB.
	DB *sql.DB
	// DBPath is the live database file, used only to SIZE it for the staging
	// guard before the snapshot is taken.
	DBPath string
	// Retain is §4.4's retention. Zero means proto.BackupRetainGenerations.
	Retain int
	// Ingest is the endpoint volume members land at — the same *Ingest the
	// HTTP server mounts, so the credentials this run mints are verifiable by
	// exactly the endpoint that receives them — and IngestBaseURL is the
	// api's public base URL, from which the destination the agents are handed
	// is derived (backupxfer.IngestDestination). Both required: step 1
	// refuses a run that could not land a single app volume rather than
	// writing an identity-only generation and recording every volume failed.
	Ingest        *backupxfer.Ingest
	IngestBaseURL string
	// Store is the backup ledger, so the write step can record its generation
	// the moment it lands rather than at the end of the saga. Set by
	// RunWorkflow from its own argument — a caller never fills it in.
	Store *Store
	// staging remembers the staging root step 2 was told about, for the ONE
	// consumer that cannot read a step result: the OnTerminal hook, which is
	// handed a job id and a verdict and nothing else. Set by RunWorkflow.
	staging *stagingRootRef
	// generation remembers the generation id step 1 minted, for the same
	// consumer: the terminal hook has to close the ingest generation and
	// remove its partial directory on a run that never reached the write.
	generation *stagingRootRef
}

// stagingRootRef carries the agent-reported staging root from step 2 to
// finalizeRunRow.
//
// A field on the config rather than a package variable, and written only by
// preflight. It is safe to keep one per workflow because step 1 refuses to
// start a second run while one is in flight, so there is never a second run
// whose root this could be confused with — the same argument the blanket sweep
// in finalizeRunRow already rests on.
type stagingRootRef struct {
	mu   sync.Mutex
	root string
}

func (r *stagingRootRef) set(dir string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.root = dir
}

func (r *stagingRootRef) get() string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.root
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

// RunWorkflow returns the eight-step backup.run saga.
//
//	1 validate     api    a claimed target exists, resolved by partition UUID,
//	                      with a §4.6 public key; no other run is in flight
//	2 preflight    agent  the target is present, mounted and has room (§4.4)
//	3 snapshot_db  api    VACUUM INTO — never a file copy of a live database
//	4 fan_out      agent  §4.5's app volumes on EVERY node, one at a time:
//	                      quiesce, stage, seal on the node, upload to the
//	                      ingest endpoint, confirm, unstage. STOPS APPS.
//	5 assemble     api    the §4.5 identity set + the manifest that indexes
//	                      every member and names every volume that was not
//	6 seal         api    encrypt to the target's PUBLIC key, fresh ephemeral
//	                      per run; record a digest
//	7 write        agent  THE IRREVERSIBLE STEP — land the sealed archive as a
//	                      new generation
//	8 prune        agent  converge on §4.4's four generations, and fail the run
//	                      if the fan-out left an app down
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
	cfg.staging = &stagingRootRef{}
	cfg.generation = &stagingRootRef{}
	return jobs.Workflow{
		Kind: RunJobKind,
		Steps: []jobs.WorkflowStep{
			{Name: "validate", Timeout: runValidateTimeout, Do: runValidate(store, cfg)},
			{Name: "preflight", Timeout: runPreflightTimeout, Retries: 1, Do: runPreflight(cfg)},
			{Name: "snapshot_db", Timeout: runSnapshotTimeout, Do: runSnapshotDB(cfg)},
			// The app-volume fan-out. It runs BEFORE assemble, not after,
			// because the manifest is the archive's first member and cannot
			// both go first and describe volumes nobody has staged yet.
			//
			// Retries: 0. A retried fan-out would stop every app a second time
			// — an outage repeated because of a backoff, which is the one thing
			// §4.7's restart contract is written against.
			{Name: "fan_out", Timeout: runFanOutTimeout, Retries: 0, Do: runFanOutStep(cfg)},
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
	// StagingRoot is the directory the TARGET NODE'S agent will read the staged
	// archive from, as that agent reported it. Every later step stages into
	// this and the api derives no staging path of its own — see runStagingDir.
	// A path, and it is in the ledger on purpose: the one thing an operator
	// reading a "staged archive not found" failure needs is both halves of the
	// disagreement, and this is the api's half.
	StagingRoot string `json:"stagingRoot,omitempty"`
}

// runSnapshotResult is step 3's output. StagingName is a plain file name, never
// a path: it is what the agent joins onto ITS staging root.
type runSnapshotResult struct {
	StagingName string        `json:"stagingName"`
	SizeBytes   uint64        `json:"sizeBytes"`
	Budget      StagingBudget `json:"budget"`
}

// runFanOutResult is the app-volume phase's own row in the ledger. The whole
// AppVolumeReport travels in it, because the ledger is a published surface and
// the per-volume record is the thing an operator needs to be able to read
// without decrypting an archive. Note what is NOT in it: any credential. They
// are minted per member, live in one command each, and expire.
type runFanOutResult struct {
	// Destination is the URI the agents uploaded to, and GenerationDir the
	// partial generation directory on the target the members landed in.
	Destination   string          `json:"destination,omitempty"`
	GenerationDir string          `json:"generationDir,omitempty"`
	Report        AppVolumeReport `json:"report"`
}

// runAssembleResult is step 5's, and it is where the fan-out's outcome becomes
// a fact in the ledger rather than a property of the code.
type runAssembleResult struct {
	StagingName string `json:"stagingName"`
	SizeBytes   uint64 `json:"sizeBytes"`
	Scope       string `json:"scope"`
	Complete    bool   `json:"complete"`
	EntryCount  int    `json:"entryCount"`
	// AppVolumesCaptured and AppVolumesSkipped are in the step result so the
	// Tasks view renders numbers rather than an absence — and so "two of three"
	// is legible without opening the manifest.
	AppVolumesCaptured int `json:"appVolumesCaptured"`
	AppVolumesSkipped  int `json:"appVolumesSkipped"`
	// AppVolumesFailed and FailedVolumes are §4.4's failed-not-skipped: the
	// volumes the run tried to take and could not. Non-empty fails the run at
	// step 8, with the generation still written and recorded.
	AppVolumesFailed int      `json:"appVolumesFailed"`
	FailedVolumes    []string `json:"failedVolumes,omitempty"`
	// AppsLeftDown names every app the fan-out stopped and could not start
	// again. Non-empty fails the run at step 8 — see runPrune.
	AppsLeftDown []string `json:"appsLeftDown,omitempty"`
	// Warning is the fan-out's prose, verbatim.
	Warning string `json:"warning"`
	// ManifestJSON is the clear-text sidecar the agent writes beside the
	// archive. Carried through the ledger because it IS the honest record and
	// there is nothing in it that should not be readable.
	ManifestJSON string `json:"manifestJson"`
}

// runSealResult is step 6's. See backupxfer.SealResult for why no secret can
// be here.
type runSealResult struct {
	StagingName string                 `json:"stagingName"`
	Seal        *backupxfer.SealResult `json:"seal"`
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
func runValidate(store *Store, cfg RunConfig) jobs.DoFn {
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
		// The archive is sealed HERE and read by the agent THERE, by name. That
		// only works when here and there are the same machine, and it is also
		// what confines the staging root this run will accept to the agent
		// sharing this filesystem — see RunConfig.SelfNodeID.
		self := strings.TrimSpace(cfg.SelfNodeID)
		if self == "" {
			return nil, errors.New("this api does not know which node it runs on (RASPUTIN_SELF_NODE_ID is unset), and a backup run has to know that before it will stage an archive for an agent to read. Nothing was staged")
		}
		if target.NodeID != self {
			return nil, fmt.Errorf("the claimed backup target (%s, partUuid %s) is on node %s, and this api runs on %s. "+
				"A run seals the identity archive on the control plane and hands the agent BESIDE IT a file name to find, and the ingest "+
				"endpoint writes volume members under the mount that agent reports; a target on another node has no such handoff. Claim a target on %s",
				displayLabel(target.Label), target.PartUUID, target.NodeID, self, self)
		}
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
		if cfg.Apps == nil || cfg.Tiles == nil {
			// Refused rather than proceeding with an empty fan-out. An api that
			// cannot enumerate installed apps would write an archive containing
			// no app data and no record of why — which is the precise failure
			// §4.5's fan-out exists to make impossible. A loud refusal at step 1
			// costs a re-run; a silently identity-only archive costs a vault.
			return nil, errors.New("this api is not wired to the installed-app list or the tile catalog, so it cannot know which app volumes to capture. " +
				"Refusing rather than writing an archive that would silently contain no app data")
		}
		if cfg.Ingest == nil {
			return nil, errors.New("this api has no backup ingest endpoint, so no app volume could land anywhere. " +
				"Refusing rather than writing a generation that would record every volume as failed")
		}
		if _, err := backupxfer.IngestDestination(cfg.IngestBaseURL); err != nil {
			return nil, fmt.Errorf("this api cannot tell the nodes where to upload volumes: %v (RASPUTIN_PUBLIC_BASE_URL). Nothing was staged", err)
		}

		now := time.Now().UTC()
		gen := proto.BackupGenerationID(now, sc.JobID, proto.BackupScopeFull)
		cfg.generation.set(gen)
		if err := store.StartRun(sc.Ctx, sc.JobID, spec.Reason, proto.BackupScopeFull, now); err != nil {
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
			Scope:        proto.BackupScopeFull,
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
//
// It is also where the api learns WHERE TO STAGE. The ack carries the node's
// staging root, and every step that touches a staged file reads it from this
// step's result rather than deriving one — see runStagingDir.
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
		stagingRoot := strings.TrimSpace(ack.StagingRoot)
		if err := checkStagingRoot(stagingRoot); err != nil && stagingRoot != "" {
			return nil, fmt.Errorf("the agent on %s named %q as its backup staging root: %w. Nothing was staged", tgt.NodeID, stagingRoot, err)
		}
		if stagingRoot == "" {
			// Refused HERE, which is the cheapest place: nothing has been
			// snapshotted, assembled or sealed. An agent that does not name its
			// staging root is one the api would have to guess for, and guessing
			// is the bug this field exists to end — the guess was wrong on
			// every shipping image until 2026-09-02.
			return nil, fmt.Errorf("the agent on %s did not say where its backup staging root is, so there is nowhere to stage an archive it will read. "+
				"That field arrived with the fix for the staging-root disagreement; this node is running an agent older than its api. Nothing was staged",
				tgt.NodeID)
		}
		// The mount path is where the ingest endpoint will write volume
		// members, under generations/. Same shape gate as the staging root,
		// for the same reason: it came off the wire, and it is about to be
		// joined and opened.
		mountPath := strings.TrimSpace(ack.MountPath)
		if err := checkStagingRoot(mountPath); err != nil {
			return nil, fmt.Errorf("the agent on %s named %q as the target's mount path: %w. Nothing was staged", tgt.NodeID, mountPath, err)
		}
		// Remembered for the OnTerminal sweep, which gets no step results.
		cfg.staging.set(stagingRoot)
		res := runPreflightResult{
			PartUUID: tgt.PartUUID, MountPath: mountPath,
			TotalBytes: ack.TotalBytes, FreeBytes: ack.FreeBytes,
			RequiredBytes: ack.RequiredBytes, GenerationsFound: len(ack.Generations),
			StagingRoot: stagingRoot,
		}
		sc.Log("info", fmt.Sprintf("target %s: %s free of %s, %d generation(s) retained; this run needs about %s",
			ack.MountPath, humanBytes(ack.FreeBytes), humanBytes(ack.TotalBytes),
			len(ack.Generations), humanBytes(ack.RequiredBytes)))
		sc.Log("info", fmt.Sprintf("%s stages backup archives in %s; this run will seal into it", tgt.NodeID, stagingRoot))
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
		stagingDir, err := runStagingDir(sc)
		if err != nil {
			return nil, err
		}
		if err := EnsureStagingDir(stagingDir); err != nil {
			return nil, fmt.Errorf("staging dir %s: %w", stagingDir, err)
		}
		// §4.7's third discipline, immediately before the guard that cares
		// about it: an archive orphaned by a run that died between sealing and
		// writing is a permanent disk leak, and it is also free space this
		// run's budget would otherwise be denied. Swept here rather than at api
		// start because this is the first moment the api knows which directory
		// the handoff uses — and it is the moment the space matters. Safe as a
		// blanket sweep for the same reason finalizeRunRow's is: step 1 refuses
		// to start a second run while one is in flight.
		if n, freed := CleanStaging(stagingDir); n > 0 {
			sc.Log("warn", fmt.Sprintf("swept %d orphaned staged archive(s) from %s before staging (%s reclaimed) — a previous run died between sealing and writing",
				n, stagingDir, humanBytes(byteCount(freed))))
		}
		dbBytes := fileSize(cfg.DBPath)
		identityBytes := MeasureIdentitySet(cfg.Sources, dbBytes)
		// Zero for the two volume terms: nothing has been staged yet, so
		// nothing is known about their sizes. The fan-out re-runs this guard
		// before every stage with what it has measured — see PlanStaging.
		budget, err := PlanStaging(stagingDir, dbBytes, identityBytes, 0, 0)
		if err != nil {
			return nil, err
		}
		sc.Log("info", fmt.Sprintf("staging %s: %s free, this run peaks at about %s plus a %s reserve",
			stagingDir, humanBytes(budget.FreeBytes), humanBytes(budget.PeakBytes),
			humanBytes(budget.ReserveBytes)))

		name := stagingName(tgt.GenerationID, "db")
		dst, err := stagedPath(sc, name)
		if err != nil {
			return nil, err
		}
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

// ----- Step 4: fan_out ----------------------------------------------------

// runFanOutStep is §4.5's per-node app-volume phase, and it is the step that
// makes a backup contain something a user would recognise as theirs.
//
// It opens the generation at the ingest endpoint — `.partial-<generation>`
// under the target's generations directory — enumerates the installed apps
// against the catalog's classification, and for every `critical`/`state`
// volume on every node, one at a time: stages it through the hosting agent
// (proto.BackupStageVolumeCmd), has that agent seal and upload it on a
// credential minted for that one member (proto.BackupTransferCmd), confirms
// against the endpoint's own record, and unstages it before asking for the
// next. Then it closes the generation, so no member can land after the
// manifest that indexes them is built.
//
// Everything it cannot take — a node that is offline, a refusal, an upload
// that did not land, a `bulk` volume, an app with no tile — is RECORDED by
// name with its reason and the run continues. See fanout.go for why
// continuing is the right trade, and runPrune for the two outcomes that end
// the run failed anyway: a volume the run tried to take and could not, and an
// app the fan-out stopped and could not start again.
func runFanOutStep(cfg RunConfig) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		tgt, err := priorRunTarget(sc)
		if err != nil {
			return nil, err
		}
		var pre runPreflightResult
		if err := priorResult(sc, "preflight", &pre); err != nil {
			return nil, err
		}
		if cfg.Apps == nil || cfg.Tiles == nil {
			return nil, errors.New("this api cannot enumerate installed apps, so it cannot know which app volumes to capture")
		}
		if cfg.Ingest == nil {
			return nil, errors.New("this api has no backup ingest endpoint for volumes to land at")
		}
		installed, err := cfg.Apps.List(sc.Ctx)
		if err != nil {
			// A failure to LIST is not a volume-level problem and is not
			// recorded as one: it means the run does not know what exists, and
			// an archive assembled in that state would be silently short with
			// nothing to say so.
			return nil, fmt.Errorf("list installed apps: %w", err)
		}
		plan := PlanAppVolumes(installed, cfg.Tiles)
		destination, err := backupxfer.IngestDestination(cfg.IngestBaseURL)
		if err != nil {
			return nil, err
		}

		// The mount path is the co-located agent's answer, shape-checked on
		// the way in and again here on the way out of the ledger, exactly as
		// the staging root is. The generations directory beneath it is the
		// only place the api writes on the target, and the ingest endpoint
		// writes beneath THAT through openat: nothing below this join is a
		// path-based open.
		mountPath := strings.TrimSpace(pre.MountPath)
		if err := checkStagingRoot(mountPath); err != nil {
			return nil, fmt.Errorf("the recorded mount path %q is unusable: %w", mountPath, err)
		}
		gensDir := filepath.Join(mountPath, proto.BackupGenerationsDir)
		genDir, err := cfg.Ingest.Open(gensDir, tgt.GenerationID, sc.JobID)
		if err != nil {
			return nil, fmt.Errorf("open generation %s for ingest: %w", tgt.GenerationID, err)
		}
		// Closed on every path out of this step: after this, no member may
		// land, because the manifest built next is the index of what did.
		defer cfg.Ingest.Close(tgt.GenerationID)
		sc.Log("info", fmt.Sprintf("generation %s is open for ingest at %s; nodes upload sealed volumes to %s", tgt.GenerationID, genDir, destination))

		report, err := runFanOut(sc.Ctx, fanOutOpts{
			NATS:         sc.NATS,
			Nodes:        nodeLookupOrNil(cfg.Inventory),
			JobID:        sc.JobID,
			GenerationID: tgt.GenerationID,
			Ingest:       cfg.Ingest,
			Destination:  destination,
			PublicKey:    tgt.PublicKey,
			KeyID:        tgt.KeyID,
			Scope:        tgt.Scope,
			Plan:         plan.Stage,
			Skipped:      plan.Skipped,
			Enumeration:  plan.AppEnumeration,
			Log:          sc.Log,
		})
		if err != nil {
			return nil, err
		}
		return json.Marshal(runFanOutResult{Destination: destination, GenerationDir: genDir, Report: report})
	}
}

// ----- Step 5: assemble ---------------------------------------------------

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
		var fan runFanOutResult
		if err := priorResult(sc, "fan_out", &fan); err != nil {
			return nil, err
		}
		snapPath, err := stagedPath(sc, snap.StagingName)
		if err != nil {
			return nil, err
		}
		// The api's staging root holds the identity set and nothing else —
		// the volumes went node-to-target and never touched it — so the
		// source-side guard is sized for the identity set alone, re-checked
		// here before a byte of the archive is written.
		dbBytes := fileSize(cfg.DBPath)
		identityBytes := MeasureIdentitySet(cfg.Sources, dbBytes)
		if _, err := PlanStaging(filepath.Dir(snapPath), dbBytes, identityBytes, 0, 0); err != nil {
			return nil, err
		}
		name := stagingName(tgt.GenerationID, "tar")
		dst, err := stagedPath(sc, name)
		if err != nil {
			return nil, err
		}
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
			AppVolumes:   fan.Report,
			Scope:        tgt.Scope,
		})
		if cerr := f.Close(); cerr != nil && aerr == nil {
			aerr = cerr
		}
		if aerr != nil {
			// Every artefact, not just this step's. The snapshot is a plaintext
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
			sc.Log("info", fmt.Sprintf("captured %s (%s)", e.Path, humanBytes(byteCount(e.SizeBytes))))
		}
		// The scope, in the job feed, on every run — the fourth of the six
		// surfaces that carry it, and the one an operator is watching live.
		level := "warn"
		if manifest.Complete {
			level = "info"
		}
		if manifest.AppVolumes.FailedCount > 0 {
			level = "error"
		}
		sc.Log(level, fmt.Sprintf("scope %s: %d app volume(s) captured across %d node(s), %d NOT captured, %d FAILED. %s",
			manifest.Scope, manifest.AppVolumes.CapturedCount, manifest.AppVolumes.NodesConsulted,
			manifest.AppVolumes.SkippedCount, manifest.AppVolumes.FailedCount, manifest.AppVolumes.Summary))

		return json.Marshal(runAssembleResult{
			StagingName:        name,
			SizeBytes:          byteCount(info.Size()),
			Scope:              manifest.Scope,
			Complete:           manifest.Complete,
			EntryCount:         len(manifest.Entries),
			AppVolumesCaptured: manifest.AppVolumes.CapturedCount,
			AppVolumesSkipped:  manifest.AppVolumes.SkippedCount,
			AppVolumesFailed:   manifest.AppVolumes.FailedCount,
			FailedVolumes:      manifest.AppVolumes.Failed,
			AppsLeftDown:       manifest.AppVolumes.AppsLeftDown,
			Warning:            manifest.Warning,
			ManifestJSON:       string(manifestJSON),
		})
	}
}

// ----- Step 6: seal -------------------------------------------------------

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
		src, err := stagedPath(sc, asm.StagingName)
		if err != nil {
			return nil, err
		}
		in, err := os.Open(src)
		if err != nil {
			return nil, fmt.Errorf("open assembled archive: %w", err)
		}
		defer func() { _ = in.Close() }()

		name := stagingName(tgt.GenerationID, "sealed")
		dst, err := stagedPath(sc, name)
		if err != nil {
			return nil, err
		}
		_ = os.Remove(dst)
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err != nil {
			return nil, fmt.Errorf("stage sealed archive: %w", err)
		}
		res, serr := backupxfer.Seal(out, in, tgt.PublicKey, tgt.KeyID, asm.Scope)
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

// ----- Step 7: write ------------------------------------------------------

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
		sc.Log("info", fmt.Sprintf("writing generation %s (%s identity archive, %d volume member(s) already landed) to the backup target on %s",
			tgt.GenerationID, humanBytes(sealed.Seal.SizeBytes), asm.AppVolumesCaptured, tgt.NodeID))
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
		if staged, derr := stagedPath(sc, sealed.StagingName); derr == nil {
			_ = os.Remove(staged)
		}

		// Recorded NOW, not at the end of the saga. Step 7 runs after this one,
		// so a prune failure would otherwise leave a `failed` row naming no
		// generation while a complete, fresh archive sat on the target — and an
		// operator reading that row would conclude they had no backup from
		// tonight. They do. Best-effort: a ledger write that fails must not
		// un-write a generation that is already on the platter.
		if err := cfg.Store.MarkRunGeneration(sc.Ctx, sc.JobID, ack.Generation.ID,
			ack.Generation.Digest, ack.Generation.SizeBytes, asm.AppVolumesCaptured, asm.AppVolumesSkipped, asm.AppVolumesFailed); err != nil {
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

// ----- Step 8: prune ------------------------------------------------------

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

		res := RunResult{
			GenerationID:       wrote.GenerationID,
			Digest:             wrote.Digest,
			SizeBytes:          wrote.SizeBytes,
			AppVolumesCaptured: asm.AppVolumesCaptured,
			AppVolumesSkipped:  asm.AppVolumesSkipped,
			AppVolumesFailed:   asm.AppVolumesFailed,
			Scope:              asm.Scope,
			Complete:           asm.Complete,
			GenerationsKept:    len(ack.Kept),
			GenerationsPruned:  len(ack.Pruned),
			At:                 time.Now().UTC(),
		}

		// §4.7's one intolerable outcome, and the reason this step can fail a
		// run that produced a perfectly good archive.
		//
		// AppRestored false means the agent stopped an app to copy a volume and
		// could not start it again. The app is DOWN, right now, because of a
		// backup — which §4.7 says is worse than a failed backup. The watchdog
		// is still retrying and a boot sweep will restart it, but nothing tells
		// the operator unless this does: #298's alert path is not built, so the
		// job feed is the only place it can be loud today.
		//
		// The archive is NOT thrown away for it. It is already written, sealed
		// and pruned to; discarding it would turn one problem into two. So the
		// generation is recorded, the retention is recorded, and then the run
		// ends FAILED with the app named — the terminal hook writes that
		// verdict onto the row, which still names the generation that landed.
		if len(asm.AppsLeftDown) > 0 {
			res.Warning = appsLeftDownMessage(asm.AppsLeftDown)
			if err := store.MarkRunRetention(sc.Ctx, sc.JobID, res); err != nil {
				log.Printf("storage: record retention for run %s: %v", sc.JobID, err)
			}
			for _, app := range asm.AppsLeftDown {
				sc.Log("error", fmt.Sprintf("APP LEFT DOWN: %s did not come back after this backup stopped it", app))
			}
			sc.Log("info", fmt.Sprintf("generation %s IS on the target (%s) and is intact — this run is failed for the app(s) above, not for the archive",
				wrote.GenerationID, humanBytes(wrote.SizeBytes)))
			return nil, errors.New(res.Warning)
		}

		// §4.4's other red outcome: a volume this run tried to take and could
		// not — its node was offline, its agent refused, its upload did not
		// land. "Failed, not skipped": the generation is on the target with
		// everything that DID arrive, the row names it, and the run ends
		// FAILED with the volumes named so the job feed, the OVERDUE tile and
		// the alert path (#298) all see red rather than a green run with a
		// caveat nobody reads.
		if asm.AppVolumesFailed > 0 {
			res.Warning = failedVolumesMessage(asm.FailedVolumes)
			if err := store.MarkRunRetention(sc.Ctx, sc.JobID, res); err != nil {
				log.Printf("storage: record retention for run %s: %v", sc.JobID, err)
			}
			for _, v := range asm.FailedVolumes {
				sc.Log("error", fmt.Sprintf("VOLUME FAILED: %s was not backed up by this run; the manifest names why", v))
			}
			sc.Log("info", fmt.Sprintf("generation %s IS on the target (%s) with %d volume member(s) — this run is failed for the volume(s) above, not for what landed",
				wrote.GenerationID, humanBytes(wrote.SizeBytes), asm.AppVolumesCaptured))
			return nil, errors.New(res.Warning)
		}

		if !asm.Complete {
			res.Warning = fmt.Sprintf("%d app volume(s) were not captured; the manifest names each one and its reason", asm.AppVolumesSkipped)
		}
		if err := store.FinishRun(sc.Ctx, sc.JobID, res); err != nil {
			return nil, fmt.Errorf("record backup run outcome: %w", err)
		}
		// Last word on a successful run. It is the caveat rather than the
		// congratulation whenever anything was missed — a run that ended
		// "backup complete" over a skipped volume would be a false statement
		// about what is on that disk.
		if asm.Complete {
			sc.Log("info", fmt.Sprintf("generation %s is on the target, scope %s: the controlplane's identity set and all %d classified app volume(s) on this cluster, each sealed on its own node",
				wrote.GenerationID, asm.Scope, asm.AppVolumesCaptured))
		} else {
			sc.Log("warn", fmt.Sprintf("generation %s is on the target, scope %s: %d app volume(s) captured, %d NOT — %s",
				wrote.GenerationID, asm.Scope, asm.AppVolumesCaptured, asm.AppVolumesSkipped, appVolumeFanOutReason))
		}
		return json.Marshal(map[string]any{
			"kept":               ack.Kept,
			"pruned":             ack.Pruned,
			"retain":             keep,
			"freeBytes":          ack.FreeBytes,
			"scope":              asm.Scope,
			"complete":           asm.Complete,
			"appVolumesCaptured": asm.AppVolumesCaptured,
			"appVolumesSkipped":  asm.AppVolumesSkipped,
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
		//
		// The directory is the one step 2 was told about, remembered on the
		// config. Empty means the run never got past step 1 — no staging root
		// was ever resolved, so nothing was staged and there is nothing to
		// sweep.
		if dir := cfg.staging.get(); dir != "" {
			if n, freed := CleanStaging(dir); n > 0 {
				log.Printf("storage: backup run %s left %d staged file(s) behind; removed them (%d bytes)", jobID, n, freed)
			}
		}
		// The ingest generation, on every terminal path. A run that reached
		// the write has already renamed `.partial-<gen>` into place and this
		// finds nothing; a run that died before it leaves the partial
		// directory — with whatever members landed — and that is litter with
		// no manifest, removed here rather than left for a boot sweep the
		// target has no owner for.
		if cfg.Ingest != nil {
			if gen := cfg.generation.get(); gen != "" {
				if err := cfg.Ingest.Abandon(gen); err != nil {
					log.Printf("storage: backup run %s: remove the partial generation %s: %v", jobID, gen, err)
				}
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

// runStagingDir is the ONLY way a step learns where to stage, and it re-derives
// nothing: the answer came off the target node in step 2 and is read back out
// of that step's persisted result.
//
// The alternative — each step resolving a directory from the api's own
// configuration — is the bug this saga shipped with. Two independent
// derivations of one path agree exactly as long as nobody changes either, and
// then they do not, silently, in the configuration that ships.
// checkStagingRoot is the shape gate on the one path in this saga that comes
// off the wire.
//
// Step 1 has already established that the answering agent is the one on this
// host, which is the substantive control — a directory named by a process that
// is already root beside us is not an escalation. This is the second, cheap
// one: a value that is not an absolute, already-clean path is not a staging
// root any agent of ours resolves, so it is a bug or a corrupted reply, and
// either way it must not reach os.MkdirAll, CleanStaging or a file open. `..`
// in particular can never travel: filepath.Clean would have removed it, so a
// path containing one is refused rather than normalised.
func checkStagingRoot(dir string) error {
	if dir == "" {
		return errors.New("it is empty")
	}
	if !filepath.IsAbs(dir) {
		return errors.New("it is not an absolute path")
	}
	if filepath.Clean(dir) != dir {
		return errors.New("it is not a clean path — a staging root with a `..`, a doubled separator or a trailing slash is not one this api will write into")
	}
	return nil
}

// stagedPath is the ONE place a path under the staging root is built, and the
// only way any step in this saga names a staged file.
//
// Both halves are checked HERE, immediately before the join, rather than at the
// boundary each arrived at. That is the point: the root and the name both
// round-trip through the job ledger as JSON between steps, so a check that ran
// once when the value was produced does not cover the read that actually opens
// the file. The root passes checkStagingRoot (absolute, already clean); the
// name passes proto.BackupValidStagingName, the SAME predicate the agent's
// write verb applies to what it is sent — a single path component of
// [A-Za-z0-9._-], no separator, no leading dot. Neither can contribute a
// traversal, so the result is always a direct child of the staging root.
func stagedPath(sc *jobs.StepCtx, name string) (string, error) {
	dir, err := runStagingDir(sc)
	if err != nil {
		return "", err
	}
	if !proto.BackupValidStagingName(name) {
		return "", fmt.Errorf("refusing to touch %q under %s: a staged file is named by a single plain file name and this is not one", name, dir)
	}
	return filepath.Join(dir, name), nil
}

func runStagingDir(sc *jobs.StepCtx) (string, error) {
	var pre runPreflightResult
	if err := priorResult(sc, "preflight", &pre); err != nil {
		return "", err
	}
	dir := strings.TrimSpace(pre.StagingRoot)
	if dir == "" {
		return "", errors.New("the preflight step recorded no staging root, so nothing knows where the agent would look for this archive. Nothing was staged")
	}
	// Re-checked on the way out of the ledger, not only on the way in. The
	// value round-trips through JSON in the job store between steps, and a
	// guard that runs once at the boundary is a guard that does not cover the
	// read — which is where the path is actually joined and opened.
	if err := checkStagingRoot(dir); err != nil {
		return "", fmt.Errorf("the recorded staging root %q is unusable: %w", dir, err)
	}
	return dir, nil
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
	return byteCount(info.Size())
}

// AppLister is the installed-app list §4.5's fan-out enumerates, narrowed to
// the one method it calls. Satisfied by *apps.Store.
//
// An interface rather than the concrete store so this package does not have to
// stand up an app database to test a plan, and so the dependency reads as what
// it is: the fan-out needs to know what is installed, and nothing else.
type AppLister interface {
	List(ctx context.Context) ([]*apps.App, error)
}

// appsLeftDownMessage is the sentence a run dies on when a backup stopped an
// app and could not start it again. It names the apps, says what is happening
// about it, and says what the operator should check.
func appsLeftDownMessage(apps []string) string {
	subject := "an app"
	if len(apps) > 1 {
		subject = "apps"
	}
	return fmt.Sprintf("BACKUP LEFT %s DOWN: %s was stopped to take a consistent copy and did not come back. "+
		"The archive for this run IS on the backup target and is intact — this run is failed for the outage, not for the backup. "+
		"The agent keeps retrying in the background and will try again at its next start; check the app's own job history "+
		"if it is still down. design/storage.md §4.7 treats an app left down by a backup as worse than a failed backup, "+
		"which is why this run ends red",
		strings.ToUpper(subject), strings.Join(apps, ", "))
}

// failedVolumesMessage is the sentence a run dies on when a classified volume
// it tried to take did not make it into the generation.
func failedVolumesMessage(vols []string) string {
	noun := "APP VOLUME"
	if len(vols) > 1 {
		noun = "APP VOLUMES"
	}
	return fmt.Sprintf("BACKUP FAILED FOR %s: %s could not be captured — a node offline at backup time, an agent that refused, "+
		"or an upload that did not land; the manifest names the reason for each. Everything else this run captured IS on the backup target, "+
		"sealed and indexed — this run is failed for what is missing, not for what landed. "+
		"design/storage.md §4.4: an app whose backup did not happen has a FAILED backup, not a skipped one",
		noun, strings.Join(vols, ", "))
}
