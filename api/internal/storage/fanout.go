package storage

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// The fan-out itself: stage one volume, verify it, take it, give the space
// back, move to the next.
//
// # Why one at a time
//
// §4.7 is explicit about it, and the reason is the peak. Staging every volume
// and then consuming them would put the SUM of an installation's app data on
// the staging partition at once — on a controlplane whose writable partition
// has a 100%-full incident on record. Staging one, consuming it, and unstaging
// it before asking for the next keeps the agent's staging root holding at most
// one copy, so the peak is the largest single volume rather than the sum.
//
// It has a second effect that matters more than the disk: staging a volume with
// a `stop` strategy STOPS THE APP. Doing them one at a time means one app is
// down at a time, for seconds. Doing them in parallel would be a house-wide
// outage every backup night.
//
// # What the run does when something goes wrong
//
// It CONTINUES, and fails at the end. A volume that refuses, times out or fails
// its digest is recorded as not captured, with the agent's own words, and the
// next volume is attempted. The archive still gets written, still gets sealed,
// still lands as a generation — and the manifest beside it names every gap.
//
// The alternative is to abort the whole run on the first bad volume, and it is
// worse in the case that actually happens: one app misbehaves, and an
// installation that would have had a complete copy of its identity set and
// eleven of its twelve volumes gets nothing at all. A partial archive that
// names its gaps can be restored from. A run that aborted cannot.
//
// The one thing that is NOT tolerated quietly is an app left down — see
// AppsLeftDown and runVerifyApps. That does not abort the fan-out either (the
// remaining volumes are still worth having, and the agent's watchdog is already
// retrying), but it ends the run FAILED with the app named.

// stageRPCBudget is how long ONE stage verb may take: the agent's own work
// budget plus room for the round trip and the marshal, the same shape every
// other agent step in this saga uses. The api must outwait the agent or it
// gives up on a handler that is about to answer — and for this verb, on a
// handler that has an app STOPPED.
const stageRPCBudget = proto.BackupStageWork + 90*time.Second

// requester is the one method the fan-out needs from NATS, named so the
// orchestration below can be exercised without a bus.
type requester interface {
	RequestWithContext(ctx context.Context, subj string, data []byte) (*nats.Msg, error)
}

// fanOutOpts is one fan-out pass.
type fanOutOpts struct {
	NATS requester
	// NodeID is the controlplane's node — the only node this build stages
	// from, and the node whose agent shares this filesystem.
	NodeID string
	// StagingDir is the root the agent reported in the preflight ack. The api
	// derives no path of its own; see runStagingDir.
	StagingDir string
	// GenerationID names every staged file this pass mints.
	GenerationID string
	// VolsPath is the tar the captured members are written to, under the
	// staging root.
	VolsPath string
	// Plan is what to stage, in order; Skipped is everything already known not
	// to be capturable, records complete; Enumeration is what the plan looked
	// at to arrive at both, carried into the report so an empty one can be
	// read.
	Plan        []PlannedVolume
	Skipped     []VolumeRecord
	Enumeration AppEnumeration
	// DBBytes and IdentityBytes size the free-space guard alongside the volume
	// bytes this pass accumulates.
	DBBytes       uint64
	IdentityBytes uint64
	// Now stamps the tar members, so every member of one generation carries
	// one timestamp.
	Now time.Time
	// Log writes to the job feed.
	Log func(level, msg string)
}

// budgetAllows reports whether what is left of the step's deadline could hold
// another volume. A context with no deadline always allows one — the step
// always has one in the saga, and a caller without one has said it will wait.
func (o fanOutOpts) budgetAllows(ctx context.Context) bool {
	deadline, ok := ctx.Deadline()
	if !ok {
		return true
	}
	return time.Until(deadline) > stageRPCBudget
}

func (o fanOutOpts) log(level, msg string) {
	if o.Log != nil {
		o.Log(level, msg)
	}
}

// runFanOut stages every planned volume in turn and returns the finished
// report plus the size of the tar it built.
//
// It returns an error only for a failure that is NOT about one volume — an
// unwritable staging root, a tar it cannot close. A volume that could not be
// captured is a record, not an error, which is the whole point.
func runFanOut(ctx context.Context, o fanOutOpts) (AppVolumeReport, uint64, error) {
	records := append([]VolumeRecord(nil), o.Skipped...)
	nodes := 0
	// Which catalog the tiles came from, in the job feed, on every run: the
	// 2026-09-03 e3bench manifest would have been explicable in one line had
	// it said the fan-out read a catalog with no volume classifications.
	o.log("info", fmt.Sprintf("app-volume fan-out: %d installed app(s), %d resolved to a tile that classifies its volumes, against catalog %s",
		o.Enumeration.AppsInstalled, o.Enumeration.AppsResolved, o.Enumeration.Catalog))
	if len(o.Plan) == 0 {
		if len(records) > 0 {
			o.log("warn", fmt.Sprintf("app-volume fan-out: nothing on %s is eligible to stage; %d volume(s) are recorded as NOT captured",
				o.NodeID, len(records)))
			for _, v := range records {
				o.log("warn", fmt.Sprintf("NOT captured: %s/%s (class %s) — %s", v.App, v.Volume, v.Class, v.Reason))
			}
		}
		return NewAppVolumeReport(o.Enumeration, records, nodes), 0, nil
	}
	nodes = 1

	f, err := os.OpenFile(o.VolsPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return AppVolumeReport{}, 0, fmt.Errorf("stage app volumes: %w", err)
	}
	tw := tar.NewWriter(f)
	closed := false
	defer func() {
		if !closed {
			_ = tw.Close()
			_ = f.Close()
		}
	}()

	o.log("info", fmt.Sprintf("app-volume fan-out: %d volume(s) to stage from %s, one at a time — `critical` first, then `state`. "+
		"A volume whose tile declares the `stop` strategy takes its app DOWN for the length of the copy",
		len(o.Plan), o.NodeID))

	var volumeBytes, largest uint64
	for i, pv := range o.Plan {
		// The phase's own budget, checked BEFORE each volume rather than
		// discovered mid-copy. Being cut off by a step timeout with an app
		// stopped is the one shape §4.7's restart contract exists to keep off
		// the normal path — the agent's watchdog would bring it back, but a
		// backstop that fires every week is not a backstop. So a volume that
		// would not fit in what is left is RECORDED as not captured, with the
		// budget named, and the phase ends cleanly.
		if !o.budgetAllows(ctx) {
			for _, rest := range o.Plan[i:] {
				records = append(records, notCaptured(rest, fmt.Sprintf(
					"the run's %s app-volume budget was exhausted before this volume was reached. Volumes are staged one at a time "+
						"and each may take up to %s; a cluster whose app data cannot be staged inside the budget needs a longer one, "+
						"or fewer volumes classed `critical`/`state`", runFanOutBudget, proto.BackupStageWork)))
			}
			o.log("warn", fmt.Sprintf("app-volume fan-out: out of time after %d of %d volume(s); the rest are recorded as not captured",
				i, len(o.Plan)))
			break
		}
		rec, size := o.stageOne(ctx, i, pv, tw, volumeBytes, largest)
		records = append(records, rec)
		if rec.Captured {
			volumeBytes += size
			if size > largest {
				largest = size
			}
		}
	}

	if err := tw.Close(); err != nil {
		_ = f.Close()
		return AppVolumeReport{}, 0, fmt.Errorf("close app-volume tar: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return AppVolumeReport{}, 0, fmt.Errorf("sync app-volume tar: %w", err)
	}
	if err := f.Close(); err != nil {
		return AppVolumeReport{}, 0, fmt.Errorf("close app-volume tar: %w", err)
	}
	info, err := os.Stat(o.VolsPath)
	if err != nil {
		return AppVolumeReport{}, 0, err
	}
	closed = true

	rep := NewAppVolumeReport(o.Enumeration, records, nodes)
	o.log("info", fmt.Sprintf("app-volume fan-out: %s", rep.Summary))
	for _, v := range rep.Volumes {
		if !v.Captured {
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
	return rep, byteCount(info.Size()), nil
}

// stageOne is the whole per-volume dance: guard, stage, verify, copy, unstage.
//
// It never returns an error. Every way it can go wrong is a VolumeRecord with
// Captured false and a Reason, because that is the artefact an operator reads
// on restore day — and an error would end the run before the next volume, which
// is the trade this file's header argues against.
func (o fanOutOpts) stageOne(ctx context.Context, i int, pv PlannedVolume, tw *tar.Writer, volumeBytes, largest uint64) (VolumeRecord, uint64) {
	name := stagingName(o.GenerationID, fmt.Sprintf("vol%d", i))
	if !proto.BackupValidStagingName(name) {
		return notCaptured(pv, fmt.Sprintf("internal: %q is not a valid staging name", name)), 0
	}
	staged := joinStaging(o.StagingDir, name)

	// §4.7's source-side guard, re-run before every stage rather than once at
	// the top of the saga. It is the only place the numbers exist: a volume's
	// size is not knowable until it has been staged, so the run sizes with what
	// it has measured so far and refuses the REST rather than filling the disk.
	// See StagingBudget.
	if budget, err := PlanStaging(o.StagingDir, o.DBBytes, o.IdentityBytes, volumeBytes, largest); err != nil {
		_ = budget
		return notCaptured(pv, fmt.Sprintf("staging it would take the controlplane's disk below its reserve: %v", err)), 0
	}

	// A leftover from a previous attempt is removed rather than adopted: the
	// agent refuses to stage onto an existing name (BackupRefusalStagingExists)
	// and adopting one would mean archiving yesterday's copy as today's.
	_ = os.Remove(staged)

	cmd, err := json.Marshal(proto.BackupStageVolumeCmd{
		AppID: pv.AppID, AppName: pv.AppName, Volume: pv.Volume,
		Class: pv.Class, Quiesce: pv.Quiesce, StagingName: name,
	})
	if err != nil {
		return notCaptured(pv, fmt.Sprintf("internal: %v", err)), 0
	}
	if pv.Quiesce == "stop" {
		// Said BEFORE the verb is sent, as proto.BackupStageVolumeCmd asks: an
		// operator watching the feed should see the outage coming rather than
		// find it in a downtime number afterwards.
		o.log("warn", fmt.Sprintf("stopping %s to copy %s consistently — the app is unavailable for the length of the copy", pv.AppName, pv.Volume))
	}
	// Each stage gets its OWN deadline, derived from the agent's budget rather
	// than from what is left of the phase's. Sharing the phase's would let one
	// slow volume consume the budget for every volume after it, and the failure
	// would look like an RPC timeout rather than like the disk being slow.
	stageCtx, cancel := context.WithTimeout(ctx, stageRPCBudget)
	defer cancel()
	msg, err := o.NATS.RequestWithContext(stageCtx, proto.BackupStageVolumeSubject(o.NodeID), cmd)
	if err != nil {
		// No ack, so nothing is known about the app's state. The agent's
		// watchdog is armed before the stop and fires on a lost reply and on a
		// deadline, which is why this is not reported as an app left down: that
		// field means "the agent reported it did not come back", and no agent
		// reported anything.
		o.unstage(ctx, name)
		return notCaptured(pv, fmt.Sprintf("the staging request to %s failed: %v. Whether the app was stopped is unknown from here; "+
			"the agent's watchdog restarts it on a lost reply and again at its next start", o.NodeID, err)), 0
	}
	var ack proto.BackupStageVolumeAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		o.unstage(ctx, name)
		return notCaptured(pv, fmt.Sprintf("the reply from %s was unreadable: %v", o.NodeID, err)), 0
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
	}
	defer o.unstage(ctx, name)

	if !ack.OK {
		rec.Reason = refusalReason(o.NodeID, ack.Refusal, ack.Detail)
		return rec, 0
	}
	if ack.Digest == "" || ack.SizeBytes == 0 {
		rec.Reason = fmt.Sprintf("%s reported a successful copy with no digest or a zero length, so there is nothing this run can verify before sealing it", o.NodeID)
		return rec, 0
	}

	info, err := os.Stat(staged)
	if err != nil {
		rec.Reason = fmt.Sprintf("%s said it staged the copy as %s, and there is no such file under %s: %v. "+
			"This is the staging-root handoff failing — both halves must name the same directory", o.NodeID, name, o.StagingDir, err)
		return rec, 0
	}
	if !info.Mode().IsRegular() {
		rec.Reason = fmt.Sprintf("the staged copy %s is not a regular file; refusing to read it", name)
		return rec, 0
	}
	if got := byteCount(info.Size()); got != ack.SizeBytes {
		rec.Reason = fmt.Sprintf("%s reported a %d-byte staged copy and the file on disk is %d bytes", o.NodeID, ack.SizeBytes, got)
		return rec, 0
	}

	// The api re-hashes what it is about to read, exactly as the agent
	// re-hashes what it is about to write. §4.6's rule is that integrity is
	// verified from a digest and never by decrypting, and this is the one place
	// on the api's side of the handoff where that check is available: the bytes
	// that go into the archive must be the bytes the agent said it wrote, or
	// the archive's own manifest would be a false statement about its contents.
	sum, err := fileSHA256(staged)
	if err != nil {
		rec.Reason = fmt.Sprintf("the staged copy %s could not be read to verify it: %v", name, err)
		return rec, 0
	}
	if sum != ack.Digest {
		rec.Reason = fmt.Sprintf("REFUSED: %s reported digest %s for %s and the staged bytes hash to %s. "+
			"The copy is not what the agent says it is, so it is not going into an archive whose manifest would claim otherwise",
			o.NodeID, short(ack.Digest), name, short(sum))
		o.log("error", fmt.Sprintf("digest mismatch staging %s/%s: %s", pv.AppName, pv.Volume, rec.Reason))
		return rec, 0
	}

	arc := pv.ArchivePath()
	if err := writeTarFile(tw, arc, staged, info.Size(), o.Now); err != nil {
		rec.Reason = fmt.Sprintf("the staged copy %s could not be written into the archive: %v", name, err)
		return rec, 0
	}

	rec.Captured = true
	rec.Path = arc
	rec.SizeBytes = ack.SizeBytes
	rec.PlaintextBytes = ack.PlaintextBytes
	rec.FileCount = ack.FileCount
	rec.SHA256 = sum
	o.log("info", fmt.Sprintf("captured %s (%s, %d file(s), %s, %s)%s",
		arc, humanBytes(ack.SizeBytes), ack.FileCount, pv.Class, consistencyText(ack),
		downtimeText(ack)))
	return rec, ack.SizeBytes
}

// unstage gives the space back. §4.7's "delete each after a confirmed upload",
// which is what keeps the peak at one volume rather than the sum.
//
// Best-effort and never fatal: the file is under the agent's root, the agent
// sweeps its own root at start, and the api's own terminal hook sweeps it too.
// A failure here costs disk, and failing the run over it would cost the backup.
func (o fanOutOpts) unstage(ctx context.Context, name string) {
	cmd, err := json.Marshal(proto.BackupUnstageCmd{StagingName: name})
	if err != nil {
		return
	}
	// Its own deadline too, and deliberately NOT the caller's: unstage is the
	// call that gives the space back, and a phase that has run out of time is
	// exactly when the space matters most. context.WithoutCancel keeps a
	// cancelled phase from skipping its own cleanup.
	unstageCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), proto.BackupUnstageWork+rpcSlack)
	defer cancel()
	msg, err := o.NATS.RequestWithContext(unstageCtx, proto.BackupUnstageSubject(o.NodeID), cmd)
	if err != nil {
		o.log("warn", fmt.Sprintf("could not ask %s to remove the staged copy %s: %v — it will be swept at the end of this run", o.NodeID, name, err))
		return
	}
	var ack proto.BackupUnstageAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil || !ack.OK {
		o.log("warn", fmt.Sprintf("%s did not remove the staged copy %s (%s) — it will be swept at the end of this run",
			o.NodeID, name, strings.TrimSpace(string(ack.Refusal)+" "+ack.Detail)))
	}
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

// copyVolumeMembers copies the fan-out's tar into the archive member by member,
// and refuses an archive whose manifest would over-claim.
//
// It takes an OPEN READER rather than a path, deliberately. The only safe way
// to name a staged file is stagedPath, which checks the agent-reported root and
// the api-minted name at the join; a function that took a path would be a
// second route to a file open, reachable by any caller of Assemble, with the
// control two call frames away. The caller opens it where the check lives.
//
// The final check is the one that matters: every volume the manifest says was
// captured must actually be a member here. A manifest that named a member the
// archive does not contain would be discovered on restore day, which is the one
// day it must not be.
func copyVolumeMembers(tw *tar.Writer, vols io.Reader, report AppVolumeReport) error {
	want := map[string]bool{}
	for _, v := range report.Volumes {
		if v.Captured {
			if v.Path == "" {
				return fmt.Errorf("internal: %s/%s is recorded as captured with no archive path", v.App, v.Volume)
			}
			want[v.Path] = false
		}
	}
	if len(want) == 0 {
		return nil
	}
	if vols == nil {
		return errors.New("internal: the manifest records captured app volumes and the fan-out handed over no tar to take them from")
	}

	tr := tar.NewReader(vols)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read staged app volumes: %w", err)
		}
		seen, ok := want[hdr.Name]
		if !ok {
			// A member nobody recorded. It cannot happen — this file is written
			// by stageOne and by nothing else — and if it ever did, silently
			// copying an unrecorded member into an archive whose manifest does
			// not list it is the exact dishonesty this file is about.
			return fmt.Errorf("the staged app-volume tar holds a member %q that no manifest record names", hdr.Name)
		}
		if seen {
			return fmt.Errorf("the staged app-volume tar holds two members named %q", hdr.Name)
		}
		want[hdr.Name] = true
		if err := tw.WriteHeader(&tar.Header{
			Name: hdr.Name, Mode: 0o600, Size: hdr.Size, ModTime: hdr.ModTime, Typeflag: tar.TypeReg,
		}); err != nil {
			return err
		}
		n, err := io.Copy(tw, io.LimitReader(tr, hdr.Size))
		if err != nil {
			return fmt.Errorf("copy %s into the archive: %w", hdr.Name, err)
		}
		if n != hdr.Size {
			return fmt.Errorf("%s: copied %d of %d bytes into the archive", hdr.Name, n, hdr.Size)
		}
	}
	for name, seen := range want {
		if !seen {
			return fmt.Errorf("the manifest records %s as captured and it is not in the staged app-volume tar; "+
				"refusing to write an archive whose own manifest over-claims", name)
		}
	}
	return nil
}
