package storage

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The app-volume fan-out, end to end over the fake agent.
//
// Every case here is about the same question asked from a different angle: does
// the archive on the disk, and the manifest beside it, say the truth about what
// is in it? The answers that would be WRONG are all quiet ones — a volume that
// vanished, a `complete` that is true, a captured count that includes something
// the archive does not hold, an app left down that nobody mentions.

// A small cluster: two apps on the controlplane and one on a compute node,
// carrying every class §4.2 defines.
const computeNodeID = "n-compute"

func clusterApps() []*apps.App {
	return []*apps.App{
		testApp("app-vw", "vaultwarden", runNodeID, "vaultwarden"),
		testApp("app-pl", "paperless", runNodeID, "paperless"),
		testApp("app-im", "immich", computeNodeID, "immich"),
	}
}

func clusterTiles() fakeTiles {
	return fakeTiles{
		"vaultwarden": testTile("vaultwarden", vol("vaultwarden-data", tileschema.BackupCritical, tileschema.QuiesceStop)),
		"paperless": testTile("paperless",
			vol("paperless-data", tileschema.BackupState, tileschema.QuiesceStop),
			vol("paperless-cache", tileschema.BackupCache, tileschema.QuiesceNone)),
		"immich": testTile("immich",
			vol("immich-upload", tileschema.BackupState, tileschema.QuiesceStop),
			vol("immich-library", tileschema.BackupBulk, tileschema.QuiesceNone)),
	}
}

// runFanOutHarness runs one backup to completion and hands back everything a
// case needs to look at: the job, the ledger row, and the manifest the agent
// was told to write beside the archive.
type fanOutRunResult struct {
	h        *runHarness
	jobID    string
	job      *jobs.Job
	row      *BackupRun
	manifest Manifest
	writeCmd proto.BackupWriteCmd
	ledger   string
}

func runWithApps(t *testing.T, opts runHarnessOpts) fanOutRunResult {
	t.Helper()
	agent := &fakeBackupAgent{}
	h := newRunHarness(t, agent, opts)
	jobID := h.submit(t, RunSpec{})
	j := h.waitTerminal(t, jobID)
	out := fanOutRunResult{h: h, jobID: jobID, job: j, row: h.run(t, jobID), ledger: h.ledgerText(t, jobID)}
	if cmd, ok := h.agent.lastWrite(); ok {
		out.writeCmd = cmd
		if err := json.Unmarshal([]byte(cmd.ManifestJSON), &out.manifest); err != nil {
			t.Fatalf("manifest is not parseable JSON: %v", err)
		}
	}
	return out
}

// record finds one volume's manifest row. A case that cannot find the row it is
// about has found the bug it was written for: a volume that vanished.
func (r fanOutRunResult) record(t *testing.T, app, volume string) VolumeRecord {
	t.Helper()
	for _, v := range r.manifest.AppVolumes.Volumes {
		if v.App == app && v.Volume == volume {
			return v
		}
	}
	t.Fatalf("%s/%s has no manifest record at all — a classified volume that is neither captured nor explained is the one outcome this phase forbids", app, volume)
	return VolumeRecord{}
}

// archiveMembers lists what is actually inside the sealed archive, decrypted
// with the test's private key. The manifest's claims are checked against THIS,
// never against the manifest.
func (r fanOutRunResult) archiveMembers(t *testing.T) map[string]string {
	t.Helper()
	sealed := r.h.agent.lastSealed()
	if len(sealed) == 0 {
		t.Fatal("the agent was never handed a sealed archive")
	}
	plain, _ := openSealed(t, sealed, r.h.key.priv)
	members := map[string]string{}
	tr := tar.NewReader(bytes.NewReader(plain))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read archive: %v", err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read %s: %v", hdr.Name, err)
		}
		members[hdr.Name] = string(body)
	}
	return members
}

// TestFanOutCapturesLocalVolumesAndNothingElse is the headline case: two local
// volumes go in, a `cache` volume is never even asked for, and the off-node and
// `bulk` volumes are recorded by name with their reasons.
func TestFanOutCapturesLocalVolumesAndNothingElse(t *testing.T) {
	r := runWithApps(t, runHarnessOpts{apps: clusterApps(), tiles: clusterTiles()})
	if r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("job failed: %s", r.job.Error)
	}

	// Exactly two staged, and in §4.2's order: `critical` before `state`.
	if got := r.h.agent.stagedOrder(); len(got) != 2 || got[0] != "vaultwarden-data" || got[1] != "paperless-data" {
		t.Errorf("staged %v; want [vaultwarden-data paperless-data] — critical first, then state, so a run that dies "+
			"part-way has already taken what costs most to lose", got)
	}
	// The `cache` volume is not refused, it is never ASKED for. §4.2 says it is
	// never copied, and sending a command the agent would refuse is a caller
	// bug rather than a policy.
	for _, name := range r.h.agent.stagedOrder() {
		if name == "paperless-cache" {
			t.Error("the fan-out asked the agent to stage a `cache` volume; §4.2 says those are never copied")
		}
	}
	// One staged copy at a time. §4.7's peak, observed rather than assumed.
	r.h.agent.mu.Lock()
	peak := r.h.agent.maxLiveStaged
	unstaged := len(r.h.agent.unstaged)
	r.h.agent.mu.Unlock()
	if peak > 1 {
		t.Errorf("%d staged copies existed at once; §4.7's whole point is that the peak is the largest single volume, not the sum", peak)
	}
	if unstaged != 2 {
		t.Errorf("%d staged copies were unstaged, want 2 — a staged file with no consumer is a permanent disk leak", unstaged)
	}
	if left := r.h.stagingEntries(t); len(left) != 0 {
		t.Errorf("the staging directory still holds %v", left)
	}

	// The manifest's claims, checked against the archive rather than against
	// themselves.
	members := r.archiveMembers(t)
	for _, want := range []string{"app-volumes/vaultwarden/vaultwarden-data.tar", "app-volumes/paperless/paperless-data.tar"} {
		if _, ok := members[want]; !ok {
			t.Errorf("the archive has no member %s; members are %v", want, keysOf(members))
		}
	}
	if _, ok := members["app-volumes/immich/immich-upload.tar"]; ok {
		t.Error("an off-node volume is in the archive, and nothing could have carried it there")
	}
	if got := r.manifest.AppVolumes.CapturedCount; got != 2 {
		t.Errorf("manifest claims %d captured, want 2", got)
	}
	if r.manifest.Complete {
		t.Error("complete is true with immich's volumes missing — the one field a hurried reader trusts")
	}
	if r.row.AppVolumesCaptured != 2 || r.row.AppVolumesSkipped != 2 || r.row.Complete {
		t.Errorf("ledger row = %d captured / %d skipped / complete %v, want 2/2/false",
			r.row.AppVolumesCaptured, r.row.AppVolumesSkipped, r.row.Complete)
	}

	// Per-volume, everything §4.5 and §4.7 make an operator's business.
	vw := r.record(t, "vaultwarden", "vaultwarden-data")
	if !vw.Captured || vw.Class != tileschema.BackupCritical || vw.Strategy != tileschema.QuiesceStop {
		t.Errorf("vaultwarden record = %+v", vw)
	}
	if vw.SHA256 == "" || vw.SizeBytes == 0 || vw.Path == "" || vw.FileCount == 0 {
		t.Errorf("a captured volume with no digest, size, path or file count: %+v", vw)
	}
	if !vw.ServiceInterrupting {
		t.Error("a `stop`-strategy volume is recorded as not service-interrupting; an operator cannot see that the app went down")
	}
	if !vw.AppRestored {
		t.Error("the app came back and the record says otherwise")
	}
}

// TestFanOutRecordsOffNodeVolumesByName is the promise this build makes in
// place of the one it cannot keep: a volume it could not take is named, with
// the reason, and the issues that will change it.
func TestFanOutRecordsOffNodeVolumesByName(t *testing.T) {
	r := runWithApps(t, runHarnessOpts{apps: clusterApps(), tiles: clusterTiles()})

	off := r.record(t, "immich", "immich-upload")
	if off.Captured {
		t.Fatal("an off-node volume is recorded as captured")
	}
	if off.Node != computeNodeID {
		t.Errorf("the record does not say which node holds it: %+v", off)
	}
	if !strings.Contains(off.Reason, "#295") || !strings.Contains(off.Reason, "#296") {
		t.Errorf("reason = %q; it must name what is holding this volume out of the archive", off.Reason)
	}

	bulk := r.record(t, "immich", "immich-library")
	if bulk.Captured {
		t.Fatal("a `bulk` volume is recorded as captured; §4.7 streams those direct and the stage verb refuses them")
	}
	if !strings.Contains(bulk.Reason, "bulk") {
		t.Errorf("bulk reason = %q", bulk.Reason)
	}

	// `cache` is excluded by design, not missed. It must NOT appear as a gap —
	// counting it would mean no archive could ever be complete.
	for _, v := range r.manifest.AppVolumes.Volumes {
		if v.Volume == "paperless-cache" {
			t.Error("a `cache` volume is recorded as a gap; §4.2 says it is never copied, which is an exclusion and not a miss")
		}
	}
	if !strings.Contains(strings.Join(r.manifest.Excluded, " "), "cache") {
		t.Error("the manifest's exclusion list does not mention `cache` volumes")
	}

	// And the run said it out loud while it was happening.
	if !strings.Contains(r.ledger, "immich-upload") {
		t.Error("the job feed never named the volume it could not capture")
	}
}

// TestFanOutCompleteWhenEverythingIsLocal is the other side of the same
// boolean. A cluster whose apps all live on the controlplane HAS had every
// classified volume captured, and saying otherwise would be its own dishonesty.
func TestFanOutCompleteWhenEverythingIsLocal(t *testing.T) {
	r := runWithApps(t, runHarnessOpts{
		apps: []*apps.App{testApp("app-vw", "vaultwarden", runNodeID, "vaultwarden")},
		tiles: fakeTiles{"vaultwarden": testTile("vaultwarden",
			vol("vaultwarden-data", tileschema.BackupCritical, tileschema.QuiesceStop),
			vol("vaultwarden-cache", tileschema.BackupCache, tileschema.QuiesceNone))},
	})
	if r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("job failed: %s", r.job.Error)
	}
	if !r.manifest.Complete || !r.row.Complete {
		t.Errorf("every classified volume on this cluster was captured and complete is manifest=%v row=%v",
			r.manifest.Complete, r.row.Complete)
	}
	if len(r.manifest.AppVolumes.BlockedBy) != 0 {
		t.Errorf("a complete archive names blockers: %v", r.manifest.AppVolumes.BlockedBy)
	}
	// The scope still says `controlplane-local`. It is the run's REACH, minted
	// before a volume was staged, and it does not become `full` because this
	// particular cluster happened to fit inside it.
	if r.manifest.Scope != proto.BackupScopeControlplaneLocal {
		t.Errorf("scope = %q", r.manifest.Scope)
	}
}

// TestFanOutFailsTheRunWhenAnAppIsLeftDown is §4.7's intolerable outcome.
//
// The archive is still written — throwing away a good backup would turn one
// problem into two — and the run still ends FAILED, with the app named, because
// #298's alert path is not built and the job feed is the only place this can be
// loud today.
func TestFanOutFailsTheRunWhenAnAppIsLeftDown(t *testing.T) {
	down := false
	r := runWithApps(t, runHarnessOpts{
		apps:  clusterApps(),
		tiles: clusterTiles(),
		stageOutcomes: map[string]stageOutcome{
			"vaultwarden-data": {appRestored: &down, interrupting: true, downtimeMillis: 4000},
		},
	})
	if r.job.Status != jobs.StatusFailed {
		t.Fatalf("job status = %s; an app left down by a backup must fail the run", r.job.Status)
	}
	if !strings.Contains(r.job.Error, "vaultwarden") {
		t.Errorf("job error = %q; it must NAME the app that is down", r.job.Error)
	}
	if !strings.Contains(strings.ToLower(r.job.Error), "down") {
		t.Errorf("job error = %q; it must say the app is down in words", r.job.Error)
	}
	if r.row.Status != RunFailed {
		t.Errorf("run row = %s, want failed", r.row.Status)
	}
	// The archive IS on the disk, and the row names it. An operator reading a
	// failed row that named no generation would conclude they had no backup
	// from tonight. They do.
	if r.h.agent.writeCount() != 1 {
		t.Errorf("the agent was asked to write %d time(s); the archive is worth having even though the run failed", r.h.agent.writeCount())
	}
	if r.row.GenerationID == "" {
		t.Error("the failed row names no generation, and there is one on the disk")
	}
	// The volume itself was still captured — the copy succeeded, the restart
	// did not.
	vw := r.record(t, "vaultwarden", "vaultwarden-data")
	if !vw.Captured {
		t.Error("the copy succeeded; the record says it did not")
	}
	if vw.AppRestored {
		t.Error("the record says the app came back and it did not")
	}
	if vw.DowntimeMillis != 4000 {
		t.Errorf("downtime = %dms, want 4000 — an operator should be able to see that the app was down for four seconds", vw.DowntimeMillis)
	}
	if !contains(r.manifest.AppVolumes.AppsLeftDown, "vaultwarden") {
		t.Errorf("appsLeftDown = %v", r.manifest.AppVolumes.AppsLeftDown)
	}
	if !strings.Contains(r.ledger, "APP LEFT DOWN") {
		t.Error("the job feed does not say, in words a human reads first, that an app is down")
	}
	// The rest of the fan-out still ran. One misbehaving app does not cost the
	// others their backup.
	if got := r.h.agent.stagedOrder(); len(got) != 2 {
		t.Errorf("staged %v; the fan-out stopped early because one app did not restart", got)
	}
}

// TestFanOutContinuesPastARefusal: a refused volume is recorded with the
// agent's own words and the next one is attempted.
func TestFanOutContinuesPastARefusal(t *testing.T) {
	r := runWithApps(t, runHarnessOpts{
		apps:  clusterApps(),
		tiles: clusterTiles(),
		stageOutcomes: map[string]stageOutcome{
			"vaultwarden-data": {refusal: proto.BackupRefusalVolumeNotFound, detail: "no volume rasp_vaultwarden_vaultwarden-data"},
		},
	})
	if r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("job failed: %s — one refused volume must not cost the run", r.job.Error)
	}
	vw := r.record(t, "vaultwarden", "vaultwarden-data")
	if vw.Captured {
		t.Fatal("a refused volume is recorded as captured")
	}
	if !strings.Contains(vw.Reason, string(proto.BackupRefusalVolumeNotFound)) || !strings.Contains(vw.Reason, "rasp_vaultwarden") {
		t.Errorf("reason = %q; it must carry the agent's own refusal and detail", vw.Reason)
	}
	// The next volume was still taken, and it is in the archive.
	pl := r.record(t, "paperless", "paperless-data")
	if !pl.Captured {
		t.Error("the fan-out gave up after the first refusal")
	}
	if _, ok := r.archiveMembers(t)["app-volumes/paperless/paperless-data.tar"]; !ok {
		t.Error("the volume the run says it captured is not in the archive")
	}
	if r.manifest.Complete {
		t.Error("complete is true with a refused volume")
	}
}

// TestFanOutRefusesADigestMismatch: the api re-hashes what it is about to read,
// and a copy that is not what the agent says it is does not go into an archive
// whose manifest would claim otherwise.
func TestFanOutRefusesADigestMismatch(t *testing.T) {
	r := runWithApps(t, runHarnessOpts{
		apps:  clusterApps(),
		tiles: clusterTiles(),
		stageOutcomes: map[string]stageOutcome{
			"vaultwarden-data": {digest: strings.Repeat("0", 64)},
		},
	})
	if r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("job failed: %s", r.job.Error)
	}
	vw := r.record(t, "vaultwarden", "vaultwarden-data")
	if vw.Captured {
		t.Fatal("a volume whose staged bytes do not match the agent's digest went into the archive")
	}
	if !strings.Contains(vw.Reason, "REFUSED") {
		t.Errorf("reason = %q; a digest mismatch is a refusal and must read as one", vw.Reason)
	}
	if _, ok := r.archiveMembers(t)["app-volumes/vaultwarden/vaultwarden-data.tar"]; ok {
		t.Error("the refused member is in the archive anyway")
	}
	if r.manifest.Complete {
		t.Error("complete is true with a refused volume")
	}
}

// TestScopeIsOnEverySurface is the honesty invariant, checked in one place.
//
// Six surfaces, one exported constant. Five of them are asserted here; the
// sixth — the UI banner — is `scopeHeadline` in ui/components/storage, which
// derives its text from the api's own scope for exactly this reason.
func TestScopeIsOnEverySurface(t *testing.T) {
	r := runWithApps(t, runHarnessOpts{apps: clusterApps(), tiles: clusterTiles()})
	scope := proto.BackupScopeControlplaneLocal

	// 1. The generation's directory name on the platter.
	if !strings.Contains(r.writeCmd.GenerationID, scope) {
		t.Errorf("generation id %q does not carry the scope — an operator listing the disk must see what an archive is without opening it", r.writeCmd.GenerationID)
	}
	// 2. The sealed header, where it is the AEAD's additional data and cannot
	//    be edited without breaking every chunk's tag.
	sealed := r.h.agent.lastSealed()
	if len(sealed) == 0 {
		t.Fatal("no sealed archive was written")
	}
	_, header := openSealed(t, sealed, r.h.key.priv)
	if header.Scope != scope {
		t.Errorf("sealed header scope = %q — the scope has to be INSIDE the seal, where nobody holding the disk can edit it", header.Scope)
	}
	// 3. The clear-text manifest.
	if r.manifest.Scope != scope {
		t.Errorf("manifest scope = %q", r.manifest.Scope)
	}
	// 4. The backup_runs row.
	if r.row.Scope != scope {
		t.Errorf("ledger row scope = %q", r.row.Scope)
	}
	// 5. The job's own log lines.
	if !strings.Contains(r.ledger, scope) {
		t.Error("the job feed never says the scope; an operator watching a run live must learn it there")
	}
	// And the standing caveat, which every surface renders, names it too.
	if !strings.Contains(AppVolumeFanOutReason(), scope) {
		t.Error("the exported caveat does not name the scope, so the UI banner and the manifest cannot agree by construction")
	}
}

// TestRunRefusesWhenItCannotEnumerateApps: an api that does not know what is
// installed would write an archive silently containing no app data. That is the
// precise failure this slice exists to make impossible, so it is refused at
// step 1 — before anything is snapshotted, staged or sealed.
func TestRunRefusesWhenItCannotEnumerateApps(t *testing.T) {
	r := runWithApps(t, runHarnessOpts{noAppSource: true})
	if r.job.Status != jobs.StatusFailed {
		t.Fatalf("job status = %s; an api that cannot enumerate apps must refuse", r.job.Status)
	}
	if !strings.Contains(r.job.Error, "silently contain no app data") {
		t.Errorf("job error = %q", r.job.Error)
	}
	if r.h.agent.writeCount() != 0 {
		t.Error("something was written despite the refusal")
	}
}

// TestFanOutRecordsAnUnclassifiedApp: a custom-compose app has no tile, so
// nothing knows which of its volumes matter. Recorded rather than skipped —
// "we did not look" and "there was nothing" must not render identically.
func TestFanOutRecordsAnUnclassifiedApp(t *testing.T) {
	r := runWithApps(t, runHarnessOpts{
		apps:  []*apps.App{testApp("app-x", "homebrew", runNodeID, "")},
		tiles: fakeTiles{},
	})
	if r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("job failed: %s", r.job.Error)
	}
	if len(r.manifest.AppVolumes.Volumes) != 1 {
		t.Fatalf("app-volume records = %+v", r.manifest.AppVolumes.Volumes)
	}
	rec := r.manifest.AppVolumes.Volumes[0]
	if rec.App != "homebrew" || rec.Captured || !strings.Contains(rec.Reason, "custom compose") {
		t.Errorf("record = %+v", rec)
	}
	if r.manifest.Complete {
		t.Error("complete is true for a cluster holding an app nothing knows how to back up")
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
