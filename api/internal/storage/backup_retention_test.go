package storage

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// geekdojo-brain#297's two behaviours, end to end over the fake agents on real
// NATS: the retention depth a run prunes to is the schedule setting read at
// the start of the run, and the target-side pre-flight sizes the whole
// generation — identity set plus the app volumes — learning each volume's size
// from the generation that last held it.

// TestBackupRunPrunesToTheScheduleDepth: an operator lowers the depth to two;
// the NEXT run hands the agent Keep=2 and says so in its log. Nothing is read
// at api start — the setting is written after the workflow is registered.
func TestBackupRunPrunesToTheScheduleDepth(t *testing.T) {
	agent := &fakeBackupAgent{generations: []string{"gen-1", "gen-2", "gen-3", "gen-4", "gen-5"}}
	h := newRunHarness(t, agent, runHarnessOpts{})
	ctx := context.Background()

	if _, err := SetBackupSchedule(ctx, h.settings, BackupSchedule{Enabled: true, Retain: 2}); err != nil {
		t.Fatalf("SetBackupSchedule: %v", err)
	}
	jobID := h.submit(t, RunSpec{})
	j := h.waitTerminal(t, jobID)
	if j.Status != jobs.StatusSucceeded {
		t.Fatalf("job failed: %s", j.Error)
	}
	pr, ok := h.agent.lastPrune()
	if !ok {
		t.Fatal("prune was never called")
	}
	if pr.Keep != 2 {
		t.Errorf("prune keep = %d, want the schedule's 2", pr.Keep)
	}
	row := h.run(t, jobID)
	if row.GenerationsKept != 2 {
		t.Errorf("the ledger recorded %d kept, want 2", row.GenerationsKept)
	}
	ledger := h.ledgerText(t, jobID)
	if !strings.Contains(ledger, "retention depth 2") {
		t.Error("the prune step did not log the depth it used")
	}
	if !strings.Contains(ledger, "retention keeps 2 generation(s)") {
		t.Error("step 1 did not record the depth the run intended before anything was written")
	}

	// Raised back to the default: the following run keeps four, from the same
	// registered workflow, with no restart.
	if _, err := SetBackupSchedule(ctx, h.settings, BackupSchedule{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	jobID = h.submit(t, RunSpec{})
	if j := h.waitTerminal(t, jobID); j.Status != jobs.StatusSucceeded {
		t.Fatalf("second job failed: %s", j.Error)
	}
	if pr, _ := h.agent.lastPrune(); pr.Keep != proto.BackupRetainGenerations {
		t.Errorf("after the setting was cleared, prune keep = %d, want the default %d", pr.Keep, proto.BackupRetainGenerations)
	}
}

// TestBackupRunEstimateCountsTheVolumes: the first run over a cluster has no
// recorded sizes and counts every volume at its class placeholder, NAMING
// them; the second run finds each volume's size in the first run's manifest
// and counts that instead. Both runs record the breakdown on their row.
func TestBackupRunEstimateCountsTheVolumes(t *testing.T) {
	h := newRunHarness(t, &fakeBackupAgent{}, runHarnessOpts{apps: clusterApps(), tiles: clusterTiles(), computeAgent: true})

	first := h.submit(t, RunSpec{})
	if j := h.waitTerminal(t, first); j.Status != jobs.StatusSucceeded {
		t.Fatalf("first run failed: %s", j.Error)
	}
	row := h.run(t, first)
	if row.Preflight == nil {
		t.Fatal("the run row carries no pre-flight estimate")
	}
	est := *row.Preflight
	// Three planned volumes: vaultwarden-data (critical), paperless-data and
	// immich-upload (state). cache is never staged and bulk is skipped.
	wantVolumes := proto.BackupUnknownVolumeBytesCritical + 2*proto.BackupUnknownVolumeBytesState
	if est.VolumeBytes != wantVolumes {
		t.Errorf("first run volumeBytes = %d, want %d (one critical and two state placeholders)", est.VolumeBytes, wantVolumes)
	}
	if got := strings.Join(est.UnknownVolumes, ","); got != "immich/immich-upload,paperless/paperless-data,vaultwarden/vaultwarden-data" {
		t.Errorf("first run unknownVolumes = %v; every volume was a guess and every guess must be named", est.UnknownVolumes)
	}
	if est.MarginBytes != proto.BackupTargetReserveBytes || est.EstimateBytes != est.IdentityBytes+est.VolumeBytes+est.MarginBytes {
		t.Errorf("first run breakdown does not add up: %+v", est)
	}
	// What went on the wire is identity + volumes; the agent adds the margin.
	h.agent.mu.Lock()
	cmds := append([]proto.BackupPreflightCmd(nil), h.agent.preflightCmds...)
	h.agent.mu.Unlock()
	if len(cmds) != 1 {
		t.Fatalf("%d preflight commands, want 1", len(cmds))
	}
	if cmds[0].EstimateBytes != est.IdentityBytes+est.VolumeBytes {
		t.Errorf("wire estimate = %d, want identity %d + volumes %d", cmds[0].EstimateBytes, est.IdentityBytes, est.VolumeBytes)
	}
	if est.IdentityBytes == 0 {
		t.Error("the identity set measured as zero")
	}
	ledger := h.ledgerText(t, first)
	if !strings.Contains(ledger, "counted at their class default") {
		t.Error("the preflight step did not say which volumes it guessed for")
	}

	// The sizes the first generation actually recorded.
	wcmd, _ := h.agent.lastWrite()
	var m Manifest
	if err := json.Unmarshal([]byte(wcmd.ManifestJSON), &m); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	recorded := map[string]uint64{}
	for _, v := range m.AppVolumes.Volumes {
		if v.Captured {
			recorded[v.App+"/"+v.Volume] = v.SealedSizeBytes
		}
	}
	if len(recorded) != 3 {
		t.Fatalf("the first run captured %d volumes, want 3: %+v", len(recorded), m.AppVolumes.Volumes)
	}

	second := h.submit(t, RunSpec{})
	if j := h.waitTerminal(t, second); j.Status != jobs.StatusSucceeded {
		t.Fatalf("second run failed: %s", j.Error)
	}
	est2 := h.run(t, second).Preflight
	if est2 == nil {
		t.Fatal("second run: no pre-flight estimate on the row")
	}
	if len(est2.UnknownVolumes) != 0 {
		t.Errorf("second run still guessed for %v after the first run recorded every size", est2.UnknownVolumes)
	}
	var sum uint64
	for _, term := range est2.Volumes {
		key := term.App + "/" + term.Volume
		if !term.Known {
			t.Errorf("%s: not known on the second run", key)
		}
		if term.Bytes != recorded[key] {
			t.Errorf("%s: estimated %d, the first generation recorded %d", key, term.Bytes, recorded[key])
		}
		if term.Generation != wcmd.GenerationID {
			t.Errorf("%s: size attributed to %q, want the first run's %s", key, term.Generation, wcmd.GenerationID)
		}
		sum += term.Bytes
	}
	if est2.VolumeBytes != sum || sum == 0 {
		t.Errorf("second run volumeBytes = %d, want the sum of recorded sizes %d", est2.VolumeBytes, sum)
	}
}

// TestBackupRunRefusalCarriesTheBreakdown: a target without room refuses
// before anything is staged, and the failure names both the agent's numbers
// and the api's breakdown — including the volume it had to guess for — so
// the operator can tell a full disk from a first run's placeholder.
func TestBackupRunRefusalCarriesTheBreakdown(t *testing.T) {
	agent := &fakeBackupAgent{
		preflight: func(cmd proto.BackupPreflightCmd) proto.BackupPreflightAck {
			return proto.BackupPreflightAck{
				OK: false, Present: true, PartUUID: cmd.PartUUID, MountPath: "/mnt/x",
				FreeBytes: 100 << 20, RequiredBytes: cmd.EstimateBytes + proto.BackupTargetReserveBytes, Sufficient: false,
				Refusal: proto.BackupRefusalInsufficientSpace,
				Detail:  "/mnt/x has 100.0 MiB free; this run needs more. Nothing was written",
			}
		},
	}
	h := newRunHarness(t, agent, runHarnessOpts{apps: clusterApps()[:1], tiles: clusterTiles()})
	jobID := h.submit(t, RunSpec{})
	j := h.waitTerminal(t, jobID)
	if j.Status != jobs.StatusFailed {
		t.Fatalf("job status = %s, want failed", j.Status)
	}
	for _, want := range []string{"insufficient-space", "100.0 MiB free", "identity set", "app volumes", "vaultwarden/vaultwarden-data", "class default"} {
		if !strings.Contains(j.Error, want) {
			t.Errorf("the refusal does not say %q: %s", want, j.Error)
		}
	}
	row := h.run(t, jobID)
	if row == nil || row.Status != RunFailed {
		t.Fatalf("run row = %+v, want a failed row", row)
	}
	if row.Preflight == nil || len(row.Preflight.UnknownVolumes) != 1 {
		t.Errorf("the refused run's row does not carry the estimate it was refused on: %+v", row.Preflight)
	}
	if h.agent.writeCount() != 0 {
		t.Error("a refused preflight reached the write verb")
	}
}
