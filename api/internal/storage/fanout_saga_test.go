package storage

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/backupxfer/sealtest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The app-volume fan-out, end to end, over the fake agents on real NATS and
// the REAL ingest endpoint on a real socket writing to a real temp target —
// the protocol functional test for geekdojo-brain#295/#296 from the api's
// side.
//
// Every case here is about the same question asked from a different angle:
// does the generation on the disk, and the manifest beside it, say the truth
// about what is in it? The answers that would be WRONG are all quiet ones — a
// volume that vanished, a `complete` that is true, a captured count that
// includes something the target does not hold, an app left down that nobody
// mentions, a node that was off rendered as a skip.

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

// fanOutRunResult is everything a case needs to look at: the job, the ledger
// row, and the manifest the agent was told to write beside the archive.
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

// archiveMembers lists what is inside the sealed IDENTITY archive, decrypted
// with the test's private key.
func (r fanOutRunResult) archiveMembers(t *testing.T) map[string]string {
	t.Helper()
	sealed := r.h.agent.lastSealed()
	if len(sealed) == 0 {
		t.Fatal("the agent was never handed a sealed archive")
	}
	plain, _, err := sealtest.Open(sealed, r.h.key.priv)
	if err != nil {
		t.Fatalf("open identity archive: %v", err)
	}
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

// volumeMember opens one sealed volume member from the committed generation
// on the fake target and returns the tar inside it. The manifest's claims are
// checked against THIS, never against the manifest.
func (r fanOutRunResult) volumeMember(t *testing.T, member string) (plain []byte, header backupxfer.Header) {
	t.Helper()
	genID := r.writeCmd.GenerationID
	p := filepath.Join(r.h.generationDir(genID), filepath.FromSlash(member))
	sealed, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("member %s is not on the target: %v", member, err)
	}
	plain, header, err = sealtest.Open(sealed, r.h.key.priv)
	if err != nil {
		t.Fatalf("member %s does not open: %v", member, err)
	}
	return plain, header
}

// targetFiles lists every file in the committed generation, relative to it.
func (r fanOutRunResult) targetFiles(t *testing.T) []string {
	t.Helper()
	root := r.h.generationDir(r.writeCmd.GenerationID)
	var out []string
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			rel, _ := filepath.Rel(root, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	return out
}

// TestFanOutCapturesEveryNodeIntoOneGeneration is the headline case: two
// volumes on the controlplane and one on a compute node go in, each sealed on
// its own node and landed as its own member; a `cache` volume is never even
// asked for; the `bulk` volume is recorded by name. One generation, one
// layout, one index.
func TestFanOutCapturesEveryNodeIntoOneGeneration(t *testing.T) {
	r := runWithApps(t, runHarnessOpts{apps: clusterApps(), tiles: clusterTiles(), computeAgent: true})
	if r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("job failed: %s", r.job.Error)
	}

	// Three staged, in §4.2's order: `critical` first, then `state`, and
	// the compute node's volume through ITS agent.
	cp := r.h.agent.stagedOrder()
	comp := r.h.compute.stagedOrder()
	if len(cp) != 2 || cp[0] != "vaultwarden-data" || cp[1] != "paperless-data" {
		t.Errorf("controlplane staged %v; want [vaultwarden-data paperless-data]", cp)
	}
	if len(comp) != 1 || comp[0] != "immich-upload" {
		t.Errorf("compute staged %v; want [immich-upload]", comp)
	}
	for _, name := range append(cp, comp...) {
		if name == "paperless-cache" || name == "immich-library" {
			t.Errorf("the fan-out asked an agent to stage %s, which is never staged", name)
		}
	}
	// One staged copy at a time, per node, and everything unstaged.
	for _, a := range []*fakeBackupAgent{r.h.agent, r.h.compute} {
		a.mu.Lock()
		peak, unstaged, staged := a.maxLiveStaged, len(a.unstaged), len(a.staged)
		a.mu.Unlock()
		if peak > 1 {
			t.Errorf("%s: %d staged copies existed at once; §4.7's peak is one volume", a.nodeID, peak)
		}
		if unstaged != staged {
			t.Errorf("%s: %d staged, %d unstaged — a staged file with no consumer is a permanent disk leak", a.nodeID, staged, unstaged)
		}
		if left, _ := os.ReadDir(a.stagingRoot); len(left) != 0 {
			t.Errorf("%s: the staging root still holds %d entries", a.nodeID, len(left))
		}
	}

	// The generation on the target: the identity archive, the manifest, and
	// one sealed member per captured volume, exactly.
	files := r.targetFiles(t)
	want := map[string]bool{
		proto.BackupArchiveFile: false, proto.BackupManifestFile: false,
		"volumes/vaultwarden/vaultwarden-data.rasputin-archive": false,
		"volumes/paperless/paperless-data.rasputin-archive":     false,
		"volumes/immich/immich-upload.rasputin-archive":         false,
	}
	for _, f := range files {
		if _, ok := want[f]; !ok {
			t.Errorf("the generation holds %s, which nothing should have written", f)
		}
		want[f] = true
	}
	for f, seen := range want {
		if !seen {
			t.Errorf("the generation lacks %s; files are %v", f, files)
		}
	}
	// The identity archive holds NO app volumes: they are members, not
	// entries.
	for name := range r.archiveMembers(t) {
		if strings.HasPrefix(name, "app-volumes/") || strings.HasPrefix(name, "volumes/") {
			t.Errorf("the identity archive holds %s; volumes are members of the generation, not entries of the archive", name)
		}
	}

	// The manifest is the index, and every claim in it checks out against
	// the bytes on the target.
	if r.manifest.ManifestVersion != 2 {
		t.Errorf("manifest version = %d; the per-member layout is version 2", r.manifest.ManifestVersion)
	}
	// Not complete: the `bulk` volume is a lane this transport does not
	// carry, and an honest manifest says so rather than rounding up. The run
	// SUCCEEDED, because nothing it tried to take failed.
	if r.manifest.Complete || r.row.Complete || r.manifest.AppVolumes.CapturedCount != 3 || r.manifest.AppVolumes.NodesConsulted != 2 || r.manifest.AppVolumes.FailedCount != 0 {
		t.Errorf("manifest complete=%v captured=%d nodes=%d failed=%d; row complete=%v", r.manifest.Complete, r.manifest.AppVolumes.CapturedCount,
			r.manifest.AppVolumes.NodesConsulted, r.manifest.AppVolumes.FailedCount, r.row.Complete)
	}
	if r.row.AppVolumesCaptured != 3 || r.row.AppVolumesSkipped != 1 || r.row.AppVolumesFailed != 0 {
		t.Errorf("ledger row = %d captured / %d skipped / %d failed, want 3/1/0", r.row.AppVolumesCaptured, r.row.AppVolumesSkipped, r.row.AppVolumesFailed)
	}
	for _, c := range []struct{ app, vol, node string }{
		{"vaultwarden", "vaultwarden-data", runNodeID},
		{"paperless", "paperless-data", runNodeID},
		{"immich", "immich-upload", computeNodeID},
	} {
		rec := r.record(t, c.app, c.vol)
		if !rec.Captured || rec.Failed || rec.Member != proto.BackupMemberPath(c.app, c.vol) || rec.SealedBy != c.node || rec.KeyID != "key-1" {
			t.Errorf("%s/%s record = %+v", c.app, c.vol, rec)
		}
		if rec.SHA256 == "" || rec.SealedSHA256 == "" || rec.SizeBytes == 0 || rec.SealedSizeBytes == 0 || rec.FileCount == 0 {
			t.Errorf("%s/%s: a captured volume with no digests, sizes or file count: %+v", c.app, c.vol, rec)
		}
		plain, header := r.volumeMember(t, rec.Member)
		if string(plain) != "TAR-OF-"+c.vol {
			t.Errorf("%s opens to %q", rec.Member, plain)
		}
		if header.Scope != proto.BackupScopeFull || header.KeyID != "key-1" {
			t.Errorf("%s header = %+v; the scope and key are sealed into every member", rec.Member, header)
		}
		sealed, _ := os.ReadFile(filepath.Join(r.h.generationDir(r.writeCmd.GenerationID), filepath.FromSlash(rec.Member)))
		if uint64(len(sealed)) != rec.SealedSizeBytes {
			t.Errorf("%s: manifest says %d sealed bytes, target holds %d", rec.Member, rec.SealedSizeBytes, len(sealed))
		}
	}
	vw := r.record(t, "vaultwarden", "vaultwarden-data")
	if !vw.ServiceInterrupting || !vw.AppRestored || vw.Class != tileschema.BackupCritical {
		t.Errorf("vaultwarden record = %+v", vw)
	}
	bulk := r.record(t, "immich", "immich-library")
	if bulk.Captured || bulk.Failed || !strings.Contains(bulk.Reason, "bulk") {
		t.Errorf("bulk record = %+v; a bulk volume is a different lane, recorded and not failed", bulk)
	}
	for _, v := range r.manifest.AppVolumes.Volumes {
		if v.Volume == "paperless-cache" {
			t.Error("a `cache` volume is recorded as a gap; §4.2 says it is never copied")
		}
	}
	// The manifest on the platter is the same JSON the api assembled.
	onDisk, err := os.ReadFile(filepath.Join(r.h.generationDir(r.writeCmd.GenerationID), proto.BackupManifestFile))
	if err != nil || string(onDisk) != r.writeCmd.ManifestJSON {
		t.Error("the manifest on the target is not the one the api assembled")
	}
	// No credential anywhere in the ledger, and every transfer was on a
	// DIFFERENT one.
	seen := map[string]bool{}
	for _, a := range []*fakeBackupAgent{r.h.agent, r.h.compute} {
		for _, rec := range a.transferRecords() {
			if strings.Contains(r.ledger, rec.cmd.Credential) {
				t.Error("an upload credential is in the job ledger")
			}
			if seen[rec.cmd.Credential] {
				t.Error("two members were uploaded on one credential")
			}
			seen[rec.cmd.Credential] = true
		}
	}
}

// TestFanOutRecordsAnOfflineNodeAsFailed is §4.4's named case: the node
// hosting immich is not on the bus. Its volume is FAILED — not skipped — the
// generation is still written with everything else, and the run ends FAILED
// with the volume named.
func TestFanOutRecordsAnOfflineNodeAsFailed(t *testing.T) {
	r := runWithApps(t, runHarnessOpts{apps: clusterApps(), tiles: clusterTiles()}) // no compute agent
	if r.job.Status != jobs.StatusFailed {
		t.Fatalf("job status = %s; an offline node's volume must fail the run", r.job.Status)
	}
	for _, want := range []string{"immich/immich-upload", "FAILED"} {
		if !strings.Contains(r.job.Error, want) {
			t.Errorf("job error = %q; it must say %q", r.job.Error, want)
		}
	}
	off := r.record(t, "immich", "immich-upload")
	if off.Captured || !off.Failed {
		t.Fatalf("record = %+v; §4.4: failed, not skipped", off)
	}
	if !strings.Contains(off.Reason, "OFFLINE") || off.Node != computeNodeID {
		t.Errorf("reason = %q node = %q; it must say the node was offline", off.Reason, off.Node)
	}
	if r.row.Status != RunFailed || r.row.AppVolumesFailed != 1 || r.row.AppVolumesCaptured != 2 || r.row.Complete {
		t.Errorf("row = status %s captured %d failed %d complete %v", r.row.Status, r.row.AppVolumesCaptured, r.row.AppVolumesFailed, r.row.Complete)
	}
	// The generation IS on the target and the row names it: the other two
	// volumes are there and the operator can see so.
	if r.row.GenerationID == "" || r.h.agent.writeCount() != 1 {
		t.Error("the failed run wrote no generation; the volumes that DID land are worth having")
	}
	if !r.manifest.AppVolumes.Complete() == false && r.manifest.Complete {
		t.Error("complete is true over a failed volume")
	}
	if got := r.manifest.AppVolumes.Failed; len(got) != 1 || got[0] != "immich/immich-upload" {
		t.Errorf("manifest failed = %v", got)
	}
	// The manifest names the compute node's member NOWHERE, and the target
	// holds no file for it.
	for _, f := range r.targetFiles(t) {
		if strings.Contains(f, "immich") {
			t.Errorf("the target holds %s for a volume that never left an offline node", f)
		}
	}
	// And the feed said it in red.
	if !strings.Contains(r.ledger, "FAILED: immich/immich-upload") || !strings.Contains(r.ledger, "VOLUME FAILED") {
		t.Error("the job feed never said, in words a human reads first, that a volume failed")
	}
	// The partial generation directory was committed by the write, not left
	// behind: nothing `.partial-*` remains.
	ents, _ := os.ReadDir(filepath.Join(r.h.mountDir, proto.BackupGenerationsDir))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), proto.BackupPartialDirPrefix) {
			t.Errorf("a partial generation survived: %s", e.Name())
		}
	}
}

// TestFanOutReadsASilentNodeAgainstInventory is the e3bench 2026-09-04 case
// and its two neighbours. The compute node hosting immich has nobody on the
// bus for storage.backup_stage_volume in all three; what inventory says
// about the node decides what the manifest says. Offline: §4.4's OFFLINE
// wording. Online on an agent that predates the verb: the record names the
// verb and the release that answers it, and does NOT say offline. Online on
// an agent that should answer: a fault, named as one. FAILED in all three —
// the volume was not captured whichever it was.
func TestFanOutReadsASilentNodeAgainstInventory(t *testing.T) {
	minStage, ok := proto.VerbMinAgentVersion("storage.backup_stage_volume")
	if !ok {
		t.Fatal("storage.backup_stage_volume has no minimum agent version recorded in proto")
	}
	now := time.Now().UTC()
	cases := []struct {
		name string
		node *proto.Node
		want []string
		not  []string
	}{
		{
			name: "offline",
			node: &proto.Node{ID: computeNodeID, Role: proto.RoleCompute, Hostname: computeNodeID, AgentVersion: "2026.08.4-dev.130",
				FirstSeen: now.Add(-time.Hour), LastSeen: now.Add(-time.Hour)},
			want: []string{"node " + computeNodeID + " is OFFLINE", "§4.4"},
			not:  []string{"predates", "online"},
		},
		{
			name: "online, agent predates the verb",
			node: &proto.Node{ID: computeNodeID, Role: proto.RoleCompute, Hostname: computeNodeID, AgentVersion: "2026.08.4-dev.130",
				FirstSeen: now, LastSeen: now},
			want: []string{"node " + computeNodeID + " is online", "(v2026.08.4-dev.130) predates storage.backup_stage_volume",
				"update the node to ≥ v" + minStage, "FAILED, not skipped"},
			not: []string{"OFFLINE", "is offline"},
		},
		{
			name: "online, agent should answer",
			node: &proto.Node{ID: computeNodeID, Role: proto.RoleCompute, Hostname: computeNodeID, AgentVersion: minStage,
				FirstSeen: now, LastSeen: now},
			want: []string{"node " + computeNodeID + " is online", "(v" + minStage + ") should answer storage.backup_stage_volume", "did not", "FAILED, not skipped"},
			not:  []string{"OFFLINE", "is offline", "predates"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := runWithApps(t, runHarnessOpts{apps: clusterApps(), tiles: clusterTiles(), nodes: []*proto.Node{tc.node}}) // no compute agent
			if r.job.Status != jobs.StatusFailed {
				t.Fatalf("job status = %s; a silent node's volume must fail the run", r.job.Status)
			}
			rec := r.record(t, "immich", "immich-upload")
			if rec.Captured || !rec.Failed {
				t.Fatalf("record = %+v; failed, not skipped, whatever the reason", rec)
			}
			for _, w := range tc.want {
				if !strings.Contains(rec.Reason, w) {
					t.Errorf("reason %q does not say %q", rec.Reason, w)
				}
			}
			for _, w := range tc.not {
				if strings.Contains(rec.Reason, w) {
					t.Errorf("reason %q must not say %q", rec.Reason, w)
				}
			}
			// The same sentence reaches the job feed and the run's error.
			if !strings.Contains(r.ledger, tc.want[0]) {
				t.Errorf("the job feed never said %q", tc.want[0])
			}
			if !strings.Contains(r.job.Error, "immich/immich-upload") {
				t.Errorf("job error = %q; it must name the volume", r.job.Error)
			}
		})
	}
}

// TestFanOutRefusesASecondVolumeOnTheFirstsCredential: the compute agent
// uploads immich-upload on the credential minted for vaultwarden-data. The
// endpoint refuses, the volume is FAILED with the endpoint's code, and the
// credential's own member is untouched.
func TestFanOutRefusesASecondVolumeOnTheFirstsCredential(t *testing.T) {
	r := runWithApps(t, runHarnessOpts{
		apps: clusterApps(), tiles: clusterTiles(), computeAgent: true,
		stageOutcomes: map[string]stageOutcome{
			// The controlplane's vaultwarden-data is staged and transferred
			// FIRST (critical, alphabetical), so its credential exists by the
			// time immich-upload is asked for — but on another agent. Give
			// the compute agent the controlplane agent's credential by name.
			"immich-upload": {reuseCredentialOf: "vaultwarden-data"},
		},
	})
	if r.h.agent.credentials.get("vaultwarden-data") == "" {
		t.Fatal("no credential was minted for vaultwarden-data")
	}
	recs := r.h.compute.transferRecords()
	if len(recs) == 0 {
		t.Fatal("the compute agent was never asked to transfer")
	}
	// What the run recorded for the mis-scoped attempt: refused by the
	// endpoint with the scope code, and FAILED.
	im := r.record(t, "immich", "immich-upload")
	if im.Captured || !im.Failed || !strings.Contains(im.Reason, backupxfer.CodeCredentialScope) {
		t.Errorf("immich record = %+v; a credential for another member must be refused with the scope code", im)
	}
	if r.job.Status != jobs.StatusFailed {
		t.Errorf("job status = %s; a refused upload is a failed volume and a failed run", r.job.Status)
	}
	// vaultwarden-data itself landed, once, and is intact.
	vw := r.record(t, "vaultwarden", "vaultwarden-data")
	if !vw.Captured {
		t.Fatal("the credential's own member did not land")
	}
	if plain, _ := r.volumeMember(t, vw.Member); string(plain) != "TAR-OF-vaultwarden-data" {
		t.Error("the credential's own member was altered")
	}
}

// TestFanOutRefusesAReplayAfterLanding: the agent uploads for real and then
// uploads AGAIN on the same credential. The second is refused member-exists,
// the member is the first upload's bytes, and the run is unaffected.
func TestFanOutRefusesAReplayAfterLanding(t *testing.T) {
	outcomes := map[string]stageOutcome{"vaultwarden-data": {replay: true}}
	r := runWithApps(t, runHarnessOpts{
		apps:  []*apps.App{testApp("app-vw", "vaultwarden", runNodeID, "vaultwarden")},
		tiles: clusterTiles(), stageOutcomes: outcomes,
	})
	if r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("job failed: %s", r.job.Error)
	}
	r.h.agent.mu.Lock()
	again := outcomes["vaultwarden-data"].replayAck
	r.h.agent.mu.Unlock()
	if again == nil {
		t.Fatal("the replay never happened")
	}
	if again.OK || again.DestinationCode != backupxfer.CodeMemberExists {
		t.Errorf("replay = %+v; a credential reused after its member landed must be refused member-exists", again)
	}
	vw := r.record(t, "vaultwarden", "vaultwarden-data")
	if !vw.Captured || r.manifest.AppVolumes.CapturedCount != 1 {
		t.Errorf("record = %+v captured=%d", vw, r.manifest.AppVolumes.CapturedCount)
	}
	sealed, _ := os.ReadFile(filepath.Join(r.h.generationDir(r.writeCmd.GenerationID), filepath.FromSlash(vw.Member)))
	if uint64(len(sealed)) != vw.SealedSizeBytes {
		t.Error("the member on the target is not the first upload")
	}
}

// TestFanOutBelievesTheEndpointNotTheAck covers both directions of the
// api's rule that the endpoint's own record decides what landed:
//   - an agent that REPORTS landed without uploading gets a FAILED record;
//   - an agent that uploads and then answers unreadably (the lost ack) gets a
//     CAPTURED record from the endpoint's receipt.
func TestFanOutBelievesTheEndpointNotTheAck(t *testing.T) {
	r := runWithApps(t, runHarnessOpts{
		apps:  clusterApps(),
		tiles: clusterTiles(), computeAgent: true,
		stageOutcomes: map[string]stageOutcome{
			"vaultwarden-data": {lieLanded: true},
			"paperless-data":   {garbleAck: true},
		},
	})
	vw := r.record(t, "vaultwarden", "vaultwarden-data")
	if vw.Captured || !vw.Failed || !strings.Contains(vw.Reason, "no record") {
		t.Errorf("a lie about landing was believed: %+v", vw)
	}
	if _, err := os.Stat(filepath.Join(r.h.generationDir(r.writeCmd.GenerationID), "volumes", "vaultwarden")); err == nil {
		t.Error("a member exists for a volume that was never uploaded")
	}
	pl := r.record(t, "paperless", "paperless-data")
	if !pl.Captured || pl.SealedSHA256 == "" {
		t.Errorf("an upload whose ack was lost is not captured from the endpoint's record: %+v", pl)
	}
	if plain, _ := r.volumeMember(t, pl.Member); string(plain) != "TAR-OF-paperless-data" {
		t.Error("the lost-ack member is not what was staged")
	}
	if !strings.Contains(r.ledger, "reply was lost") {
		t.Error("the feed did not say the ack was lost and the endpoint's record was used")
	}
	if r.job.Status != jobs.StatusFailed {
		t.Errorf("job status = %s; the lie left a volume failed", r.job.Status)
	}
}

// TestFanOutFailsTheRunWhenAnAppIsLeftDown is §4.7's intolerable outcome.
func TestFanOutFailsTheRunWhenAnAppIsLeftDown(t *testing.T) {
	down := false
	r := runWithApps(t, runHarnessOpts{
		apps:  clusterApps(),
		tiles: clusterTiles(), computeAgent: true,
		stageOutcomes: map[string]stageOutcome{
			"vaultwarden-data": {appRestored: &down, interrupting: true, downtimeMillis: 4000},
		},
	})
	if r.job.Status != jobs.StatusFailed {
		t.Fatalf("job status = %s; an app left down by a backup must fail the run", r.job.Status)
	}
	if !strings.Contains(r.job.Error, "vaultwarden") || !strings.Contains(strings.ToLower(r.job.Error), "down") {
		t.Errorf("job error = %q; it must NAME the app and say it is down", r.job.Error)
	}
	if r.row.Status != RunFailed || r.row.GenerationID == "" || r.h.agent.writeCount() != 1 {
		t.Errorf("row = %+v writes=%d; the archive is worth having even though the run failed", r.row, r.h.agent.writeCount())
	}
	vw := r.record(t, "vaultwarden", "vaultwarden-data")
	if !vw.Captured || vw.AppRestored || vw.DowntimeMillis != 4000 {
		t.Errorf("record = %+v; the copy succeeded, the restart did not, and the downtime is recorded", vw)
	}
	if !contains(r.manifest.AppVolumes.AppsLeftDown, "vaultwarden") || !strings.Contains(r.ledger, "APP LEFT DOWN") {
		t.Error("the app left down is not named as a field and in the feed")
	}
	if got := r.h.agent.stagedOrder(); len(got) != 2 {
		t.Errorf("staged %v; the fan-out stopped early because one app did not restart", got)
	}
}

// TestFanOutContinuesPastARefusal: a refused volume is recorded FAILED with
// the agent's own words and the next one is attempted.
func TestFanOutContinuesPastARefusal(t *testing.T) {
	r := runWithApps(t, runHarnessOpts{
		apps:  clusterApps(),
		tiles: clusterTiles(), computeAgent: true,
		stageOutcomes: map[string]stageOutcome{
			"vaultwarden-data": {refusal: proto.BackupRefusalVolumeNotFound, detail: "no volume rasp_vaultwarden_vaultwarden-data"},
		},
	})
	if r.job.Status != jobs.StatusFailed {
		t.Fatalf("job status = %s — a refused volume is a failed backup for that app (§4.4)", r.job.Status)
	}
	vw := r.record(t, "vaultwarden", "vaultwarden-data")
	if vw.Captured || !vw.Failed || !strings.Contains(vw.Reason, string(proto.BackupRefusalVolumeNotFound)) || !strings.Contains(vw.Reason, "rasp_vaultwarden") {
		t.Errorf("record = %+v; it must carry the agent's own refusal and detail, and be failed", vw)
	}
	pl := r.record(t, "paperless", "paperless-data")
	im := r.record(t, "immich", "immich-upload")
	if !pl.Captured || !im.Captured {
		t.Error("the fan-out gave up after the first refusal")
	}
	if plain, _ := r.volumeMember(t, pl.Member); string(plain) != "TAR-OF-paperless-data" {
		t.Error("the volume the run says it captured is not on the target")
	}
	if r.manifest.Complete || r.row.AppVolumesFailed != 1 {
		t.Errorf("complete=%v failed=%d", r.manifest.Complete, r.row.AppVolumesFailed)
	}
}

// TestFanOutRefusesADigestMismatch: the agent's stage ack claims a digest the
// staged bytes do not have. The transfer re-hashes what it seals and refuses
// to call the member the described copy; the api records the volume FAILED
// and does not index it.
func TestFanOutRefusesADigestMismatch(t *testing.T) {
	r := runWithApps(t, runHarnessOpts{
		apps:  clusterApps(),
		tiles: clusterTiles(), computeAgent: true,
		stageOutcomes: map[string]stageOutcome{
			"vaultwarden-data": {digest: strings.Repeat("0", 64)},
		},
	})
	vw := r.record(t, "vaultwarden", "vaultwarden-data")
	if vw.Captured || !vw.Failed || !strings.Contains(vw.Reason, "REFUSED") {
		t.Fatalf("record = %+v; a digest mismatch is a refusal and must read as one", vw)
	}
	if r.manifest.Complete || r.job.Status != jobs.StatusFailed {
		t.Error("complete is true, or the run succeeded, with a refused volume")
	}
}

// TestScopeIsOnEverySurface is the honesty invariant, checked in one place.
func TestScopeIsOnEverySurface(t *testing.T) {
	r := runWithApps(t, runHarnessOpts{apps: clusterApps(), tiles: clusterTiles(), computeAgent: true})
	scope := proto.BackupScopeFull
	// 1. The generation's directory name on the platter.
	if !strings.Contains(r.writeCmd.GenerationID, scope) {
		t.Errorf("generation id %q does not carry the scope", r.writeCmd.GenerationID)
	}
	// 2. The sealed headers — the identity archive's AND every member's —
	//    where it is the AEAD's additional data.
	if _, header, err := sealtest.Open(r.h.agent.lastSealed(), r.h.key.priv); err != nil || header.Scope != scope {
		t.Errorf("identity archive header scope = %q (%v)", header.Scope, err)
	}
	for _, v := range r.manifest.AppVolumes.Volumes {
		if v.Captured {
			if _, header := r.volumeMember(t, v.Member); header.Scope != scope {
				t.Errorf("member %s header scope = %q", v.Member, header.Scope)
			}
		}
	}
	// 3. The clear-text manifest. 4. The backup_runs row. 5. The job feed.
	if r.manifest.Scope != scope || r.row.Scope != scope || !strings.Contains(r.ledger, scope) {
		t.Errorf("manifest %q row %q feed-has=%v", r.manifest.Scope, r.row.Scope, strings.Contains(r.ledger, scope))
	}
	if !strings.Contains(AppVolumeFanOutReason(), scope) {
		t.Error("the exported caveat does not name the scope")
	}
}

// TestRunRefusesWhenItCannotEnumerateApps and TestRunRefusesWithoutAnIngest
// are the two step-1 refusals for an api that could not do the fan-out.
func TestRunRefusesWhenItCannotEnumerateApps(t *testing.T) {
	r := runWithApps(t, runHarnessOpts{noAppSource: true})
	if r.job.Status != jobs.StatusFailed || !strings.Contains(r.job.Error, "silently contain no app data") {
		t.Fatalf("job = %s %q", r.job.Status, r.job.Error)
	}
	if r.h.agent.writeCount() != 0 {
		t.Error("something was written despite the refusal")
	}
}

func TestRunRefusesWithoutAnIngestEndpoint(t *testing.T) {
	r := runWithApps(t, runHarnessOpts{noIngest: true})
	if r.job.Status != jobs.StatusFailed || !strings.Contains(r.job.Error, "no backup ingest endpoint") {
		t.Fatalf("job = %s %q", r.job.Status, r.job.Error)
	}
	if r.h.agent.writeCount() != 0 {
		t.Error("something was written despite the refusal")
	}
}

// TestFanOutRecordsAnUnclassifiedApp: a custom-compose app has no tile, so
// nothing knows which of its volumes matter. Recorded rather than skipped,
// incomplete rather than failed — the run never tried, because it could not
// know what to try.
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
	if rec.App != "homebrew" || rec.Captured || rec.Failed || !strings.Contains(rec.Reason, "custom compose") {
		t.Errorf("record = %+v", rec)
	}
	if r.manifest.Complete {
		t.Error("complete is true for a cluster holding an app nothing knows how to back up")
	}
}

// TestAbandonedRunLeavesNoPartialGeneration: a run that dies after members
// landed but before the write leaves nothing on the target — the terminal
// hook removes `.partial-<gen>`.
func TestAbandonedRunLeavesNoPartialGeneration(t *testing.T) {
	agent := &fakeBackupAgent{
		write: func(cmd proto.BackupWriteCmd) proto.BackupWriteAck {
			return proto.BackupWriteAck{OK: false, Refusal: proto.StorageRefusalBackendError, Detail: "disk pulled"}
		},
	}
	h := newRunHarness(t, agent, runHarnessOpts{apps: clusterApps(), tiles: clusterTiles(), computeAgent: true})
	jobID := h.submit(t, RunSpec{})
	j := h.waitTerminal(t, jobID)
	if j.Status != jobs.StatusFailed {
		t.Fatalf("job = %s", j.Status)
	}
	ents, _ := os.ReadDir(filepath.Join(h.mountDir, proto.BackupGenerationsDir))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), proto.BackupPartialDirPrefix) {
			t.Errorf("a partial generation with landed members survived a failed run: %s", e.Name())
		}
	}
	if _, _, open := h.ingest.OpenGeneration(); open {
		t.Error("the ingest endpoint still has a generation open after the run ended")
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
