package storage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The target-side estimate's composition (#297), without a runner: identity
// set plus each planned volume at its recorded size or its class placeholder,
// plus the margin — and the guessed volumes named.

// fakeSteps is a StepLister over canned assemble results, one per job.
type fakeSteps struct {
	manifests map[string]Manifest
	err       error
}

func (f fakeSteps) ListSteps(_ context.Context, jobID string) ([]*jobs.JobStep, error) {
	if f.err != nil {
		return nil, f.err
	}
	m, ok := f.manifests[jobID]
	if !ok {
		return nil, nil
	}
	raw, _ := m.JSON()
	res, _ := json.Marshal(runAssembleResult{ManifestJSON: string(raw)})
	return []*jobs.JobStep{
		{JobID: jobID, Seq: 1, Name: "preflight", Status: jobs.StepSucceeded},
		{JobID: jobID, Seq: 5, Name: "assemble", Status: jobs.StepSucceeded, Result: res},
	}, nil
}

func plannedVolumes() []PlannedVolume {
	return []PlannedVolume{
		{AppID: "app-vw", AppName: "vaultwarden", NodeID: runNodeID, Volume: "vaultwarden-data", Class: tileschema.BackupCritical},
		{AppID: "app-pl", AppName: "paperless", NodeID: runNodeID, Volume: "paperless-data", Class: tileschema.BackupState},
		{AppID: "app-im", AppName: "immich", NodeID: computeNodeID, Volume: "immich-upload", Class: tileschema.BackupState},
	}
}

func capturedRecord(app, volume string, sealed uint64) VolumeRecord {
	return VolumeRecord{App: app, Volume: volume, Captured: true, Member: proto.BackupMemberPath(app, volume), SealedSizeBytes: sealed, SizeBytes: sealed - 64}
}

func TestEstimateTargetPayloadComposition(t *testing.T) {
	plan := plannedVolumes()
	prior := map[string]PriorVolumeSize{
		plan[0].Member(): {Bytes: 40 << 20, Generation: "gen-a"},
		plan[1].Member(): {Bytes: 900 << 20, Generation: "gen-a"},
		// immich-upload has never been captured.
	}
	est := EstimateTargetPayload(10<<20, plan, prior)

	if est.IdentityBytes != 10<<20 {
		t.Errorf("identity = %d", est.IdentityBytes)
	}
	wantVolumes := uint64(40<<20) + uint64(900<<20) + proto.BackupUnknownVolumeBytesState
	if est.VolumeBytes != wantVolumes {
		t.Errorf("volumeBytes = %d, want %d (two recorded sizes plus one `state` placeholder)", est.VolumeBytes, wantVolumes)
	}
	if est.MarginBytes != proto.BackupTargetReserveBytes {
		t.Errorf("marginBytes = %d, want the target reserve", est.MarginBytes)
	}
	if est.EstimateBytes != est.IdentityBytes+est.VolumeBytes+est.MarginBytes {
		t.Errorf("estimateBytes = %d is not identity + volumes + margin", est.EstimateBytes)
	}
	// On the wire the margin is the agent's to add — sending it twice would
	// double it.
	if est.PayloadBytes() != est.IdentityBytes+est.VolumeBytes {
		t.Errorf("payloadBytes = %d includes the margin", est.PayloadBytes())
	}
	if len(est.Volumes) != 3 {
		t.Fatalf("volumes = %d, want 3", len(est.Volumes))
	}
	if !est.Volumes[0].Known || est.Volumes[0].Generation != "gen-a" || est.Volumes[0].Bytes != 40<<20 {
		t.Errorf("vaultwarden term = %+v, want the recorded 40 MiB from gen-a", est.Volumes[0])
	}
	if est.Volumes[2].Known || est.Volumes[2].Bytes != proto.BackupUnknownVolumeBytesState {
		t.Errorf("immich term = %+v, want the `state` placeholder, not known", est.Volumes[2])
	}
	if len(est.UnknownVolumes) != 1 || est.UnknownVolumes[0] != "immich/immich-upload" {
		t.Errorf("unknownVolumes = %v, want the one never-captured volume named", est.UnknownVolumes)
	}
	if !strings.Contains(est.Explain(), "immich/immich-upload") || !strings.Contains(est.Explain(), "class default") {
		t.Errorf("the explanation does not name the guessed volume: %s", est.Explain())
	}
}

func TestEstimateUsesTheCriticalPlaceholderForCritical(t *testing.T) {
	plan := plannedVolumes()
	est := EstimateTargetPayload(0, plan, nil)
	want := proto.BackupUnknownVolumeBytesCritical + 2*proto.BackupUnknownVolumeBytesState
	if est.VolumeBytes != want {
		t.Errorf("volumeBytes = %d, want %d (one critical + two state placeholders)", est.VolumeBytes, want)
	}
	if len(est.UnknownVolumes) != 3 {
		t.Errorf("unknownVolumes = %v, want all three", est.UnknownVolumes)
	}
	// Sorted, so two runs over the same cluster produce the same sentence.
	if est.UnknownVolumes[0] != "immich/immich-upload" || est.UnknownVolumes[2] != "vaultwarden/vaultwarden-data" {
		t.Errorf("unknownVolumes not sorted: %v", est.UnknownVolumes)
	}
}

func TestEstimateSaturatesRatherThanWrapping(t *testing.T) {
	plan := plannedVolumes()[:1]
	prior := map[string]PriorVolumeSize{plan[0].Member(): {Bytes: ^uint64(0) - 10}}
	est := EstimateTargetPayload(1<<20, plan, prior)
	if est.EstimateBytes != ^uint64(0) || est.PayloadBytes() != ^uint64(0) {
		t.Errorf("an overflowing estimate wrapped to %d / %d — a pre-flight that passes on a disk with no room", est.EstimateBytes, est.PayloadBytes())
	}
}

// TestPriorVolumeSizesReadsTheMostRecentCapture: newest run first, first
// captured record per member wins, a run that did not capture a volume does
// not shadow an older one that did, and a ledger that cannot be read
// contributes nothing rather than failing.
func TestPriorVolumeSizesReadsTheMostRecentCapture(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	plan := plannedVolumes()
	want := map[string]bool{}
	for _, p := range plan {
		want[p.Member()] = true
	}

	// Three runs, oldest first in time. The newest captured only vaultwarden
	// (paperless failed); the middle captured both; the oldest captured all
	// three.
	seed := func(jobID string, at time.Time) {
		if err := st.StartRun(ctx, jobID, ReasonScheduled, proto.BackupScopeFull, at); err != nil {
			t.Fatal(err)
		}
		if err := st.FinishRun(ctx, jobID, RunResult{GenerationID: "gen-" + jobID, At: at.Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	base := time.Now().Add(-3 * time.Hour).UTC()
	seed("old", base)
	seed("mid", base.Add(time.Hour))
	seed("new", base.Add(2*time.Hour))
	steps := fakeSteps{manifests: map[string]Manifest{
		"old": {GenerationID: "gen-old", AppVolumes: AppVolumeReport{Volumes: []VolumeRecord{
			capturedRecord("vaultwarden", "vaultwarden-data", 10<<20), capturedRecord("paperless", "paperless-data", 100<<20), capturedRecord("immich", "immich-upload", 5<<30),
		}}},
		"mid": {GenerationID: "gen-mid", AppVolumes: AppVolumeReport{Volumes: []VolumeRecord{
			capturedRecord("vaultwarden", "vaultwarden-data", 20<<20), capturedRecord("paperless", "paperless-data", 200<<20),
		}}},
		"new": {GenerationID: "gen-new", AppVolumes: AppVolumeReport{Volumes: []VolumeRecord{
			capturedRecord("vaultwarden", "vaultwarden-data", 30<<20),
			{App: "paperless", Volume: "paperless-data", Captured: false, Failed: true, Reason: "node offline"},
		}}},
	}}

	got := PriorVolumeSizes(ctx, st, steps, want)
	check := func(member string, bytes uint64, gen string) {
		t.Helper()
		ps, ok := got[member]
		if !ok {
			t.Errorf("%s: no prior size", member)
			return
		}
		if ps.Bytes != bytes || ps.Generation != gen {
			t.Errorf("%s: %d from %s, want %d from %s", member, ps.Bytes, ps.Generation, bytes, gen)
		}
	}
	check(plan[0].Member(), 30<<20, "gen-new")
	check(plan[1].Member(), 200<<20, "gen-mid")
	check(plan[2].Member(), 5<<30, "gen-old")

	// A ledger that cannot be read is not a reason to fail a run: the
	// estimate falls back to the placeholders and names them.
	if got := PriorVolumeSizes(ctx, st, fakeSteps{err: errors.New("locked")}, want); len(got) != 0 {
		t.Errorf("an unreadable ledger produced sizes: %v", got)
	}
	if got := PriorVolumeSizes(ctx, st, nil, want); len(got) != 0 {
		t.Errorf("a nil ledger produced sizes: %v", got)
	}
}
