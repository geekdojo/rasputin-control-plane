package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// The fan-out itself: stage one volume on its node, have that node seal and
// upload it, confirm it landed, give the space back, move to the next.
//
// # Why one at a time
//
// §4.7 is explicit about it, and the reason is the peak. Staging every volume
// and then consuming them would put the SUM of a node's app data on its
// staging partition at once. Staging one, transferring it, and unstaging it
// before asking for the next keeps every agent's staging root holding at most
// one copy, so the peak is the largest single volume rather than the sum.
//
// It has a second effect that matters more than the disk: staging a volume
// with a `stop` strategy STOPS THE APP. Doing them one at a time means one
// app is down at a time, for seconds. Doing them in parallel would be a
// house-wide outage every backup night. It also means the ingest endpoint's
// semaphore is never contended by this run — the backpressure exists for the
// day a build parallelises nodes, and it costs nothing today.
//
// # Where the bytes go
//
// Nowhere near the api's staging root. The hosting agent seals the staged
// tar to the target's public key and streams it straight to the ingest
// endpoint (backupxfer), which lands it as a member of the open generation
// on the claimed disk. The api holds no copy of any volume, sealed or
// otherwise, at any point. The controlplane's own volumes take the same path
// over loopback.
//
// # What the run does when something goes wrong
//
// It CONTINUES, records the volume as FAILED, and fails at the end. A volume
// whose node is offline, whose agent refuses, whose upload does not land or
// whose digest disagrees is recorded with the reason and the next volume is
// attempted. The identity archive still gets written, still gets sealed,
// still lands as a generation beside every member that did arrive — and the
// manifest names every gap. Then runPrune ends the run failed with the
// volumes named, because §4.4 says a backup that did not happen must never
// render like ordinary green.
//
// The alternative — abort on the first bad volume — is worse in the case that
// actually happens: one node is off, and an installation that would have had
// eleven of its twelve volumes gets nothing at all.

// stageRPCBudget is how long ONE stage verb may take: the agent's own work
// budget plus room for the round trip and the marshal. The api must outwait
// the agent or it gives up on a handler that is about to answer — and for
// this verb, on a handler that has an app STOPPED.
const stageRPCBudget = proto.BackupStageWork + 90*time.Second

// transferRPCBudget is the same for the transfer verb, and it is also the
// credential's life: the credential is minted immediately before the verb is
// sent, for exactly as long as the verb may run plus the round trip.
const transferRPCBudget = proto.BackupTransferWork + 90*time.Second

// transferAttempts is how many times a transfer is tried per volume. Two:
// §4.7's "retry without re-quiescing" — a stalled upload is another upload
// of the same staged file on a fresh credential, and the app is not stopped
// again. More than one retry is a slow disk or a dead api, and the run
// should say so rather than spend its two-hour budget on one volume.
const transferAttempts = 2

// requester is the one method the fan-out needs from NATS, named so the
// orchestration below can be exercised without a bus.
type requester interface {
	RequestWithContext(ctx context.Context, subj string, data []byte) (*nats.Msg, error)
}

// nodeLookup is the one question the fan-out asks inventory: why did nobody
// on that node answer? *inventory.Store answers it.
type nodeLookup interface {
	ExplainNoResponder(ctx context.Context, subject string) inventory.NoResponder
}

// nodeLookupOrNil keeps a nil *inventory.Store a nil interface, so the nil
// check in silenceReason means what it says.
func nodeLookupOrNil(inv *inventory.Store) nodeLookup {
	if inv == nil {
		return nil
	}
	return inv
}

// fanOutOpts is one fan-out pass.
type fanOutOpts struct {
	NATS requester
	// Nodes reads a stage request nobody answered against inventory, so the
	// manifest says whether the node was offline or online with an agent
	// that predates the verb. Nil reads every silence as offline.
	Nodes nodeLookup
	// JobID is the run, which the credential is scoped to.
	JobID string
	// GenerationID names every staged file this pass mints and the
	// generation every member lands in.
	GenerationID string
	// Ingest is the endpoint the members land at; Destination is the URI the
	// agents are handed for it. PublicKey, KeyID and Scope are what every
	// member is sealed to and with.
	Ingest      *backupxfer.Ingest
	Destination string
	PublicKey   string
	KeyID       string
	Scope       string
	// Plan is what to stage, in order; Skipped is everything already known not
	// to be capturable, records complete; Enumeration is what the plan looked
	// at to arrive at both.
	Plan        []PlannedVolume
	Skipped     []VolumeRecord
	Enumeration AppEnumeration
	// Log writes to the job feed.
	Log func(level, msg string)
}

// budgetAllows reports whether what is left of the step's deadline could hold
// another volume — a stage and a transfer.
func (o fanOutOpts) budgetAllows(ctx context.Context) bool {
	deadline, ok := ctx.Deadline()
	if !ok {
		return true
	}
	return time.Until(deadline) > stageRPCBudget+transferRPCBudget
}

func (o fanOutOpts) log(level, msg string) {
	if o.Log != nil {
		o.Log(level, msg)
	}
}

// runFanOut stages, transfers and unstages every planned volume in turn and
// returns the finished report.
//
// It returns an error only for a failure that is NOT about one volume — no
// ingest endpoint to land on. A volume that could not be captured is a
// record, not an error, which is the whole point.
func runFanOut(ctx context.Context, o fanOutOpts) (AppVolumeReport, error) {
	records := append([]VolumeRecord(nil), o.Skipped...)
	nodes := map[string]bool{}
	o.log("info", fmt.Sprintf("app-volume fan-out: %d installed app(s), %d resolved to a tile that classifies its volumes, against catalog %s",
		o.Enumeration.AppsInstalled, o.Enumeration.AppsResolved, o.Enumeration.Catalog))
	if len(o.Plan) == 0 {
		if len(records) > 0 {
			o.log("warn", fmt.Sprintf("app-volume fan-out: nothing is eligible to stage; %d volume(s) are recorded as NOT captured", len(records)))
			for _, v := range records {
				o.log("warn", fmt.Sprintf("NOT captured: %s/%s (class %s) — %s", v.App, v.Volume, v.Class, v.Reason))
			}
		}
		return NewAppVolumeReport(o.Enumeration, records, 0), nil
	}
	if o.Ingest == nil || strings.TrimSpace(o.Destination) == "" {
		return AppVolumeReport{}, errors.New("this api has no ingest endpoint for volumes to land at, so no app volume can be captured; refusing rather than recording every one as failed")
	}

	o.log("info", fmt.Sprintf("app-volume fan-out: %d volume(s) to stage, one at a time — `critical` first, then `state` — each sealed on its own node and uploaded to %s. "+
		"A volume whose tile declares the `stop` strategy takes its app DOWN for the length of the local copy, and not for the upload",
		len(o.Plan), o.Destination))

	for i, pv := range o.Plan {
		// The phase's own budget, checked BEFORE each volume rather than
		// discovered mid-copy. Being cut off by a step timeout with an app
		// stopped is the one shape §4.7's restart contract exists to keep off
		// the normal path — the agent's watchdog would bring it back, but a
		// backstop that fires every week is not a backstop. So a volume that
		// would not fit in what is left is recorded as FAILED, with the
		// budget named, and the phase ends cleanly.
		if !o.budgetAllows(ctx) {
			for _, rest := range o.Plan[i:] {
				records = append(records, failedVolume(rest, fmt.Sprintf(
					"the run's %s app-volume budget was exhausted before this volume was reached. Volumes are staged one at a time "+
						"and each may take up to %s to stage and %s to transfer; a cluster whose app data cannot be moved inside the budget needs a longer one, "+
						"or fewer volumes classed `critical`/`state`", runFanOutBudget, proto.BackupStageWork, proto.BackupTransferWork)))
			}
			o.log("error", fmt.Sprintf("app-volume fan-out: out of time after %d of %d volume(s); the rest are FAILED", i, len(o.Plan)))
			break
		}
		nodes[pv.NodeID] = true
		records = append(records, o.captureOne(ctx, i, pv))
	}

	rep := NewAppVolumeReport(o.Enumeration, records, len(nodes))
	o.log("info", fmt.Sprintf("app-volume fan-out: %s", rep.Summary))
	for _, v := range rep.Volumes {
		switch {
		case v.Failed:
			o.log("error", fmt.Sprintf("FAILED: %s/%s (class %s, on %s) — %s", v.App, v.Volume, v.Class, v.Node, v.Reason))
		case !v.Captured:
			o.log("warn", fmt.Sprintf("NOT captured: %s/%s (class %s) — %s", v.App, v.Volume, v.Class, v.Reason))
		}
	}
	for _, app := range rep.AppsLeftDown {
		// The loudest line this saga can write, and it is written the moment
		// it is known rather than at the end. An app is down RIGHT NOW because
		// of a backup.
		o.log("error", fmt.Sprintf("APP LEFT DOWN: %s was stopped to take a backup copy and did not come back. "+
			"The agent's watchdog keeps retrying and a boot sweep will restart it, but the app is unavailable until it does. "+
			"§4.7 treats this as worse than a failed backup; this run will end FAILED because of it", app))
	}
	return rep, nil
}

// captureOne is the whole per-volume dance: stage, transfer, confirm, unstage.
//
// It never returns an error. Every way it can go wrong is a VolumeRecord with
// Captured false and a Reason — and Failed true, because every one of them is
// a volume this run tried to take.
func (o fanOutOpts) captureOne(ctx context.Context, i int, pv PlannedVolume) VolumeRecord {
	name := stagingName(o.GenerationID, fmt.Sprintf("vol%d", i))
	if !proto.BackupValidStagingName(name) {
		return failedVolume(pv, fmt.Sprintf("internal: %q is not a valid staging name", name))
	}
	node := strings.TrimSpace(pv.NodeID)

	// ----- stage -----------------------------------------------------------
	cmd, err := json.Marshal(proto.BackupStageVolumeCmd{
		AppID: pv.AppID, AppName: pv.AppName, Volume: pv.Volume,
		Class: pv.Class, Quiesce: pv.Quiesce, StagingName: name,
	})
	if err != nil {
		return failedVolume(pv, fmt.Sprintf("internal: %v", err))
	}
	if pv.Quiesce == "stop" {
		// Said BEFORE the verb is sent, as proto.BackupStageVolumeCmd asks: an
		// operator watching the feed should see the outage coming.
		o.log("warn", fmt.Sprintf("stopping %s on %s to copy %s consistently — the app is unavailable for the length of the local copy", pv.AppName, node, pv.Volume))
	}
	stageCtx, cancel := context.WithTimeout(ctx, stageRPCBudget)
	msg, err := o.NATS.RequestWithContext(stageCtx, proto.BackupStageVolumeSubject(node), cmd)
	cancel()
	if err != nil {
		if errors.Is(err, nats.ErrNoResponders) {
			// Nobody on that node answered. FAILED either way — not skipped,
			// not deferred — but the REASON depends on what inventory knows.
			return failedVolume(pv, o.silenceReason(ctx, node, proto.BackupStageVolumeSubject(node)))
		}
		// No ack, so nothing is known about the app's state. The agent's
		// watchdog is armed before the stop and fires on a lost reply and on a
		// deadline, which is why this is not reported as an app left down.
		o.unstage(ctx, node, name)
		return failedVolume(pv, fmt.Sprintf("the staging request to %s failed: %v. Whether the app was stopped is unknown from here; "+
			"the agent's watchdog restarts it on a lost reply and again at its next start", node, err))
	}
	var ack proto.BackupStageVolumeAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		o.unstage(ctx, node, name)
		return failedVolume(pv, fmt.Sprintf("the reply from %s was unreadable: %v", node, err))
	}

	rec := VolumeRecord{
		App: pv.AppName, AppID: pv.AppID, TileID: pv.TileID, Node: pv.NodeID,
		Volume: pv.Volume, Class: pv.Class, Strategy: pv.Quiesce,
		ServiceInterrupting: ack.ServiceInterrupting,
		DowntimeMillis:      ack.DowntimeMillis,
		AppRestored:         ack.AppRestored,
		RestoreDetail:       ack.RestoreDetail,
		Consistency:         string(ack.Consistency),
		Window:              ack.Window,
		Databases:           ack.Databases,
		SnapshotTool:        ack.SnapshotTool,
		Failed:              true, // until it lands
	}
	defer o.unstage(ctx, node, name)

	if !ack.OK {
		rec.Reason = refusalReason(node, ack.Refusal, ack.Detail)
		return rec
	}
	if ack.Digest == "" || ack.SizeBytes == 0 {
		rec.Reason = fmt.Sprintf("%s reported a successful copy with no digest or a zero length, so there is nothing this run can verify before sealing it", node)
		return rec
	}

	// ----- transfer --------------------------------------------------------
	member := pv.Member()
	var last string
	for attempt := 1; attempt <= transferAttempts; attempt++ {
		if attempt > 1 {
			o.log("warn", fmt.Sprintf("retrying the upload of %s/%s from %s (attempt %d of %d) — the staged copy is reused; the app is NOT stopped again",
				pv.AppName, pv.Volume, node, attempt, transferAttempts))
		}
		// The credential: one member, one generation, one run, one node,
		// bounded in bytes, minted now and dead by the time the verb's
		// budget is. Never logged and never in a step result — it goes into
		// the command and nowhere else.
		cred, err := o.Ingest.Mint(backupxfer.Grant{
			Generation: o.GenerationID, Member: member, NodeID: node, JobID: o.JobID,
			// Bounded to the member it is for: the stage verb reported the
			// tar's size, and a seal of it cannot be larger than this.
			MaxBytes: backupxfer.SealedSizeBound(ack.SizeBytes),
		}, transferRPCBudget)
		if err != nil {
			rec.Reason = fmt.Sprintf("could not mint an upload credential for %s: %v", member, err)
			return rec
		}
		tcmd, err := json.Marshal(proto.BackupTransferCmd{
			StagingName: name, Destination: o.Destination, Credential: cred,
			PublicKey: o.PublicKey, KeyID: o.KeyID, Scope: o.Scope,
			GenerationID: o.GenerationID, Member: member,
			AppID: pv.AppID, AppName: pv.AppName, Volume: pv.Volume,
			PlaintextDigest: ack.Digest, PlaintextBytes: ack.SizeBytes,
		})
		if err != nil {
			rec.Reason = fmt.Sprintf("internal: %v", err)
			return rec
		}
		xferCtx, cancel := context.WithTimeout(ctx, transferRPCBudget)
		tmsg, terr := o.NATS.RequestWithContext(xferCtx, proto.BackupTransferSubject(node), tcmd)
		cancel()

		var tack proto.BackupTransferAck
		if terr == nil {
			terr = json.Unmarshal(tmsg.Data, &tack)
		}
		// THE record of what landed is the endpoint's, not the agent's. An
		// ack can be lost on the bus after the member landed; the endpoint
		// wrote the file and it knows. Consulted on every path.
		if rc, landed := o.Ingest.Landed(o.GenerationID, member); landed {
			if terr != nil {
				o.log("warn", fmt.Sprintf("%s landed %s/%s and its reply was lost (%v); the endpoint's own record is used", node, pv.AppName, pv.Volume, terr))
			}
			return o.landed(rec, pv, ack, tack, rc, node)
		}
		switch {
		case terr != nil:
			last = fmt.Sprintf("the transfer request to %s failed: %v", node, terr)
		case !tack.OK:
			last = transferReason(node, tack)
			if tack.Refusal == proto.BackupRefusalDestinationRefused || tack.Refusal == proto.BackupRefusalDestinationUnsupported ||
				tack.Refusal == proto.BackupRefusalStagingMissing || tack.Refusal == proto.BackupRefusalDigestMismatch {
				// The destination said no, or the agent could not even
				// start: a second attempt on a fresh credential would say
				// the same thing.
				rec.Reason = last
				return rec
			}
		default:
			last = fmt.Sprintf("%s reported the upload of %s as landed and the endpoint has no record of it", node, member)
		}
		o.log("warn", fmt.Sprintf("upload of %s/%s from %s did not land: %s", pv.AppName, pv.Volume, node, last))
	}
	rec.Reason = fmt.Sprintf("the upload did not land after %d attempt(s); last: %s", transferAttempts, last)
	return rec
}

// landed fills in a record from the endpoint's receipt — and refuses to call
// the volume captured when the agent's own account of the plaintext disagrees
// with what it staged, because the member on the disk would then not be the
// copy the manifest describes.
func (o fanOutOpts) landed(rec VolumeRecord, pv PlannedVolume, stage proto.BackupStageVolumeAck, xfer proto.BackupTransferAck, rc *backupxfer.Receipt, node string) VolumeRecord {
	if xfer.OK && xfer.PlaintextDigest != "" && !strings.EqualFold(xfer.PlaintextDigest, stage.Digest) {
		rec.Reason = fmt.Sprintf("REFUSED: %s staged %s with digest %s and sealed bytes hashing to %s; the member on the target is not the copy the stage verb described and is not indexed",
			node, pv.Volume, short(stage.Digest), short(xfer.PlaintextDigest))
		return rec
	}
	if rc.PlaintextDigest != "" && !strings.EqualFold(rc.PlaintextDigest, stage.Digest) {
		rec.Reason = fmt.Sprintf("REFUSED: the member that landed declares plaintext digest %s and the stage verb reported %s; not indexed", short(rc.PlaintextDigest), short(stage.Digest))
		return rec
	}
	if !xfer.OK && xfer.Refusal == proto.BackupRefusalDigestMismatch {
		// The member landed, and the agent says its plaintext is not the
		// staged copy. The endpoint cannot see inside the seal; the agent's
		// word is the only check, and it said no.
		rec.Reason = transferReason(node, xfer)
		return rec
	}
	rec.Captured = true
	rec.Failed = false
	rec.Member = rc.Member
	rec.SealedBy = rc.NodeID
	rec.KeyID = o.KeyID
	rec.SealedSHA256 = rc.SealedDigest
	rec.SealedSizeBytes = rc.SealedBytes
	rec.SizeBytes = stage.SizeBytes
	rec.PlaintextBytes = stage.PlaintextBytes
	rec.FileCount = stage.FileCount
	rec.SHA256 = stage.Digest
	o.log("info", fmt.Sprintf("captured %s from %s (%s staged, %s sealed, %d file(s), %s, %s)%s",
		rc.Member, node, humanBytes(stage.SizeBytes), humanBytes(rc.SealedBytes), stage.FileCount, pv.Class, consistencyText(stage), downtimeText(stage)))
	return rec
}

// unstage gives the space back on the node that staged. §4.7's "delete each
// after a confirmed upload", which is what keeps the peak at one volume.
//
// Best-effort and never fatal: the file is under the agent's root, the agent
// sweeps its own root at start. A failure here costs disk on that node, and
// failing the run over it would cost the backup.
func (o fanOutOpts) unstage(ctx context.Context, node, name string) {
	cmd, err := json.Marshal(proto.BackupUnstageCmd{StagingName: name})
	if err != nil {
		return
	}
	// Its own deadline, and deliberately NOT the caller's: a phase that has
	// run out of time is exactly when the space matters most.
	unstageCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), proto.BackupUnstageWork+rpcSlack)
	defer cancel()
	msg, err := o.NATS.RequestWithContext(unstageCtx, proto.BackupUnstageSubject(node), cmd)
	if err != nil {
		if !errors.Is(err, nats.ErrNoResponders) {
			o.log("warn", fmt.Sprintf("could not ask %s to remove the staged copy %s: %v — that agent sweeps its staging root at its next start", node, name, err))
		}
		return
	}
	var ack proto.BackupUnstageAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil || !ack.OK {
		o.log("warn", fmt.Sprintf("%s did not remove the staged copy %s (%s) — that agent sweeps its staging root at its next start",
			node, name, strings.TrimSpace(string(ack.Refusal)+" "+ack.Detail)))
	}
}

// silenceReason is the manifest's reason for a stage request nobody answered.
//
// Three readings, and the record says which. The node is offline: §4.4's
// named case, and its wording. The node is online but its agent predates
// the verb: the sentence names the verb and the release that answers it,
// because "update the node" is the fix and OFFLINE would send the operator
// to check a cable. The node is online and its agent should have answered:
// a fault, said as one. All three are FAILED — the volume was not captured
// whichever it was.
//
// Without inventory to consult (Nodes nil) every silence reads as offline,
// which is what this saga said on e3bench 2026-09-04 about a node that was
// online running 2026.08.4-dev.130.
func (o fanOutOpts) silenceReason(ctx context.Context, node, subject string) string {
	if o.Nodes != nil {
		if why := o.Nodes.ExplainNoResponder(ctx, subject); why.Online() {
			return why.String() + ". Nothing could copy this volume, so this app's backup is FAILED, not skipped — §4.4 as for an offline node, though this node is NOT offline"
		}
	}
	return fmt.Sprintf("node %s is OFFLINE: no agent answered the staging request on the bus, so nothing could copy this volume. "+
		"§4.4: an app whose node is offline at backup time has a FAILED backup, not a skipped one", node)
}

func consistencyText(ack proto.BackupStageVolumeAck) string {
	if ack.Consistency == "" {
		return "consistency not stated"
	}
	return string(ack.Consistency)
}

func downtimeText(ack proto.BackupStageVolumeAck) string {
	if !ack.ServiceInterrupting || ack.DowntimeMillis <= 0 {
		return ""
	}
	return fmt.Sprintf("; the app was down for %.1fs", float64(ack.DowntimeMillis)/1000)
}

// refusalReason renders an agent refusal as the sentence that goes in the
// manifest beside the volume's name.
func refusalReason(nodeID string, refusal proto.StorageRefusal, detail string) string {
	r := strings.TrimSpace(string(refusal))
	if r == "" {
		r = "refused"
	}
	d := strings.TrimSpace(detail)
	if d == "" {
		d = "no detail given"
	}
	return fmt.Sprintf("%s refused to stage it (%s): %s", nodeID, r, d)
}

// transferReason renders a transfer refusal, with the destination's own code
// when it was the destination that said no.
func transferReason(nodeID string, ack proto.BackupTransferAck) string {
	r := strings.TrimSpace(string(ack.Refusal))
	if r == "" {
		r = "refused"
	}
	if ack.DestinationCode != "" {
		r += ", destination said " + ack.DestinationCode
	}
	d := strings.TrimSpace(ack.Detail)
	if d == "" {
		d = "no detail given"
	}
	return fmt.Sprintf("%s could not upload it (%s): %s", nodeID, r, d)
}
