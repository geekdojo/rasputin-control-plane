package storage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The backup.run saga, end to end, over a real jobs.Runner, a real SQLite
// database and a fake agent on an in-process NATS server.
//
// Like the claim saga's tests, most of these are about what does NOT happen:
// how many times the agent was asked to write, whether it was asked at all, and
// whether a refusal left the ledger honest. The one addition is a whole class
// of assertion the claim saga does not need — that nothing key-shaped escaped
// into the job ledger — because this saga is the one that handles the archive.

type runCase struct {
	name string
	opts runHarnessOpts
	spec RunSpec

	preflight func(cmd proto.BackupPreflightCmd) proto.BackupPreflightAck
	write     func(cmd proto.BackupWriteCmd) proto.BackupWriteAck
	prune     func(cmd proto.BackupPruneCmd) proto.BackupPruneAck
	// seedRunning puts an in-flight run in the ledger first.
	seedRunning bool

	wantJob jobs.Status
	// wantRunStatus is "" when the case must leave no run row at all — a
	// refusal that happens before the row is created.
	wantRunStatus   RunStatus
	wantErrContains string
	wantWriteCalls  int
	check           func(t *testing.T, h *runHarness, jobID string)
}

func TestBackupRunSaga(t *testing.T) {
	cases := []runCase{
		{
			name:           "a claimed, keyed target gets a sealed generation and a prune",
			wantJob:        jobs.StatusSucceeded,
			wantRunStatus:  RunSucceeded,
			wantWriteCalls: 1,
			check: func(t *testing.T, h *runHarness, jobID string) {
				row := h.run(t, jobID)
				if row.GenerationID == "" {
					t.Error("no generation recorded")
				}
				if !strings.Contains(row.GenerationID, proto.BackupScopeIdentityOnly) {
					t.Errorf("generation id %q does not carry the scope — an operator listing the disk "+
						"must be able to see what an archive is without opening it", row.GenerationID)
				}
				if row.Scope != proto.BackupScopeIdentityOnly {
					t.Errorf("scope = %q, want %q", row.Scope, proto.BackupScopeIdentityOnly)
				}
				if row.AppVolumesCaptured != 0 {
					t.Errorf("appVolumesCaptured = %d — this build captures none", row.AppVolumesCaptured)
				}
				if row.FinishedAt == nil {
					t.Error("a terminal row with no finish time renders as still-running")
				}
				if row.PartUUID != runPartUUID {
					t.Errorf("partUuid = %q, want the claimed target's", row.PartUUID)
				}

				// The digest the api recorded must be the digest the agent
				// computed over the bytes actually staged.
				cmd, ok := h.agent.lastWrite()
				if !ok {
					t.Fatal("no write command captured")
				}
				h.agent.mu.Lock()
				agentDigest := h.agent.writeDigests[len(h.agent.writeDigests)-1]
				h.agent.mu.Unlock()
				if agentDigest == "" {
					t.Fatal("the fake agent could not read the staged archive — the api did not stage it where it said it would")
				}
				if cmd.Digest != agentDigest {
					t.Errorf("the api claimed digest %s and the staged bytes hash to %s", cmd.Digest, agentDigest)
				}
				if row.Digest != agentDigest {
					t.Errorf("the ledger recorded digest %s, want %s", row.Digest, agentDigest)
				}
				if !proto.BackupValidStagingName(cmd.StagingName) {
					t.Errorf("staging name %q is not a plain file name; the agent would refuse it", cmd.StagingName)
				}

				// The manifest is the honest record, and its honesty is the
				// point of this whole slice.
				var m Manifest
				if err := json.Unmarshal([]byte(cmd.ManifestJSON), &m); err != nil {
					t.Fatalf("manifest is not parseable JSON: %v", err)
				}
				if m.Complete {
					t.Error("the manifest says the archive is complete; it contains no app data")
				}
				if m.Scope != proto.BackupScopeIdentityOnly {
					t.Errorf("manifest scope = %q", m.Scope)
				}
				if m.AppVolumes.CapturedCount != 0 || len(m.AppVolumes.Captured) != 0 {
					t.Errorf("manifest claims %d app volumes captured", m.AppVolumes.CapturedCount)
				}
				if m.AppVolumes.Reason == "" || len(m.AppVolumes.BlockedBy) == 0 {
					t.Error("the manifest's app-volume section does not say WHY nothing was captured, which is the one thing it exists to say")
				}
				if m.Warning == "" {
					t.Error("the manifest carries no warning; an operator reading it could take this for a complete backup")
				}
				// §4.5's identity set, all three parts.
				wantEntries := []string{"rasputin.db", "trust/mesh-ca.key", "trust/mesh-ca.pem", "mesh/headscale/config.yaml"}
				for _, want := range wantEntries {
					found := false
					for _, e := range m.Entries {
						if e.Path == want {
							found = true
							if e.SHA256 == "" || e.SizeBytes == 0 {
								t.Errorf("manifest entry %s has no digest or no size", want)
							}
						}
					}
					if !found {
						t.Errorf("§4.5 requires %s in the archive, and the manifest does not list it", want)
					}
				}

				// §4.4's retention reached the disk.
				pr, ok := h.agent.lastPrune()
				if !ok {
					t.Fatal("prune was never called")
				}
				if pr.Keep != proto.BackupRetainGenerations {
					t.Errorf("prune keep = %d, want §4.4's %d", pr.Keep, proto.BackupRetainGenerations)
				}
				if pr.ProtectGenerationID != row.GenerationID {
					t.Errorf("prune did not protect this run's own generation (%q vs %q)",
						pr.ProtectGenerationID, row.GenerationID)
				}

				// §4.7: nothing left staged. The sealed archive is deleted once
				// the agent confirms it landed, and the plaintext tar the
				// instant it was sealed.
				if left := h.stagingEntries(t); len(left) != 0 {
					t.Errorf("staging directory still holds %v — an orphaned staged archive is a permanent disk leak", left)
				}
			},
		},
		{
			name:            "no claimed target is a clean refusal, before any row exists",
			opts:            runHarnessOpts{noTarget: true},
			wantJob:         jobs.StatusFailed,
			wantRunStatus:   "",
			wantErrContains: "no backup target is claimed",
			wantWriteCalls:  0,
		},
		{
			name:            "a target with no §4.6 public key is refused rather than written in clear",
			opts:            runHarnessOpts{noKey: true},
			wantJob:         jobs.StatusFailed,
			wantRunStatus:   "",
			wantErrContains: "no archive public key",
			wantWriteCalls:  0,
			check: func(t *testing.T, h *runHarness, jobID string) {
				// The single most consequential refusal in the saga: writing in
				// clear here would put an unencrypted portable copy of every
				// secret in the cluster on a removable disk.
				if got := h.ledgerText(t, jobID); !strings.Contains(got, "will not write one in clear") {
					t.Error("the refusal does not say that an unencrypted archive was declined")
				}
			},
		},
		{
			name:            "a target whose public key is unusable is refused",
			opts:            runHarnessOpts{badKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
			wantJob:         jobs.StatusFailed,
			wantRunStatus:   "",
			wantErrContains: "unusable",
			wantWriteCalls:  0,
		},
		{
			name:            "a target with no partition UUID is refused",
			opts:            runHarnessOpts{noPartUUID: true},
			wantJob:         jobs.StatusFailed,
			wantRunStatus:   "",
			wantErrContains: "no partition UUID",
			wantWriteCalls:  0,
		},
		{
			name:            "a second run while one is in flight is refused",
			seedRunning:     true,
			wantJob:         jobs.StatusFailed,
			wantRunStatus:   "",
			wantErrContains: "a backup is already running",
			wantWriteCalls:  0,
		},
		{
			name: "the target refusing on low space stops the run before anything is staged",
			preflight: func(cmd proto.BackupPreflightCmd) proto.BackupPreflightAck {
				return proto.BackupPreflightAck{
					OK: false, Present: true, PartUUID: cmd.PartUUID,
					MountPath: "/mnt/rasputin-backup", TotalBytes: 8 << 30,
					FreeBytes: 900 << 20, RequiredBytes: 1500 << 20, Sufficient: false,
					Refusal: proto.BackupRefusalInsufficientSpace,
					Detail:  "/mnt/rasputin-backup has 900.0 MiB free; this run needs about 1.5 GiB",
				}
			},
			wantJob:         jobs.StatusFailed,
			wantRunStatus:   RunFailed,
			wantErrContains: string(proto.BackupRefusalInsufficientSpace),
			wantWriteCalls:  0,
			check: func(t *testing.T, h *runHarness, jobID string) {
				// §4.4 wants a refusal an operator can act on, so the numbers
				// have to survive into the ledger.
				if got := h.ledgerText(t, jobID); !strings.Contains(got, "900.0 MiB free") {
					t.Error("the refusal did not carry the free/required numbers into the ledger")
				}
				// Nothing was snapshotted, so nothing was staged.
				if left := h.stagingEntries(t); len(left) != 0 {
					t.Errorf("a refused preflight left %v in staging", left)
				}
			},
		},
		{
			name: "an unplugged target is named as unplugged, not as a backend failure",
			preflight: func(cmd proto.BackupPreflightCmd) proto.BackupPreflightAck {
				return proto.BackupPreflightAck{
					OK: true, Present: false, PartUUID: cmd.PartUUID,
					Refusal: proto.StorageRefusalNotFound,
					Detail:  "no attached disk carries that partition UUID",
				}
			},
			wantJob:         jobs.StatusFailed,
			wantRunStatus:   RunFailed,
			wantErrContains: "it was unplugged",
			wantWriteCalls:  0,
		},
		{
			name: "a write the agent refuses fails the run and leaves nothing recorded",
			write: func(cmd proto.BackupWriteCmd) proto.BackupWriteAck {
				return proto.BackupWriteAck{
					OK: false, PartUUID: cmd.PartUUID,
					Refusal: proto.BackupRefusalDigestMismatch,
					Detail:  "staged bytes do not match the digest the api computed",
				}
			},
			wantJob:         jobs.StatusFailed,
			wantRunStatus:   RunFailed,
			wantErrContains: string(proto.BackupRefusalDigestMismatch),
			// Called once and NOT retried: the step is Irreversible.
			wantWriteCalls: 1,
			check: func(t *testing.T, h *runHarness, jobID string) {
				row := h.run(t, jobID)
				if row.GenerationID != "" {
					t.Errorf("a refused write recorded generation %q", row.GenerationID)
				}
				if _, ok := h.agent.lastPrune(); ok {
					t.Error("prune ran after a failed write — retention must never advance on a run that wrote nothing")
				}
			},
		},
		{
			name: "a prune the agent refuses fails the run, but the generation is already safe",
			prune: func(cmd proto.BackupPruneCmd) proto.BackupPruneAck {
				return proto.BackupPruneAck{
					OK: false, PartUUID: cmd.PartUUID,
					Refusal: proto.StorageRefusalBackendError,
					Detail:  "could not remove the oldest generation",
				}
			},
			wantJob:         jobs.StatusFailed,
			wantRunStatus:   RunFailed,
			wantErrContains: "could not remove the oldest generation",
			wantWriteCalls:  1,
			check: func(t *testing.T, h *runHarness, jobID string) {
				// The ordering trade named in RunWorkflow's comment: prune runs
				// AFTER the write, so this failure leaves a complete, fresh
				// backup on the target and an over-retained set.
				if h.agent.writeCount() != 1 {
					t.Fatal("the generation was not written")
				}
				// Retried once, because prune is convergent — see the comment on
				// RunWorkflow for why it is deliberately not Irreversible.
				h.agent.mu.Lock()
				n := len(h.agent.pruneCmds)
				h.agent.mu.Unlock()
				if n < 2 {
					t.Errorf("prune was attempted %d time(s); a convergent step should have retried", n)
				}
				// And the row NAMES the generation that landed, even though the
				// run as a whole failed. Otherwise an operator reading
				// "failed, no generation" concludes they have no backup from
				// tonight — and they do.
				row := h.run(t, jobID)
				if row.GenerationID == "" {
					t.Error("a run that wrote a generation and then failed to prune records no generation at all")
				}
				if row.Digest == "" || row.SizeBytes == 0 {
					t.Error("the recorded generation has no digest or size, so nothing could verify it")
				}
				// It is still a FAILURE, and it is still not the last success.
				last, err := h.store.LastSuccess(context.Background())
				if err != nil {
					t.Fatalf("LastSuccess: %v", err)
				}
				if last != nil {
					t.Error("a run whose retention did not converge is being counted as a success")
				}
				// §4.7: the sealed archive does not linger in staging.
				if left := h.stagingEntries(t); len(left) != 0 {
					t.Errorf("staging still holds %v after a failed run", left)
				}
			},
		},
		{
			name: "prune keeps exactly four generations",
			// Five generations already on the target, then this run's makes six.
			prune: nil,
			check: func(t *testing.T, h *runHarness, jobID string) {
				pr, ok := h.agent.lastPrune()
				if !ok {
					t.Fatal("prune was never called")
				}
				if pr.Keep != 4 {
					t.Fatalf("prune keep = %d, want 4", pr.Keep)
				}
				h.agent.mu.Lock()
				gens := append([]string(nil), h.agent.generations...)
				h.agent.mu.Unlock()
				ack := defaultPruneAck(pr, gens)
				if len(ack.Kept) != 4 {
					t.Errorf("prune kept %d generation(s) (%v), want exactly 4", len(ack.Kept), ack.Kept)
				}
				if len(ack.Pruned) != len(gens)-4 {
					t.Errorf("prune removed %d of %d generations, want %d", len(ack.Pruned), len(gens), len(gens)-4)
				}
				// The run's own generation must be among the survivors.
				row := h.run(t, jobID)
				found := false
				for _, k := range ack.Kept {
					if k == row.GenerationID {
						found = true
					}
				}
				if !found {
					t.Error("prune did not keep the generation this run just wrote")
				}
			},
			wantJob:        jobs.StatusSucceeded,
			wantRunStatus:  RunSucceeded,
			wantWriteCalls: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agent := &fakeBackupAgent{
				preflight: tc.preflight, write: tc.write, prune: tc.prune,
			}
			if tc.name == "prune keeps exactly four generations" {
				// Five older generations already on the target.
				agent.generations = []string{"gen-1", "gen-2", "gen-3", "gen-4", "gen-5"}
			}
			h := newRunHarness(t, agent, tc.opts)
			if tc.seedRunning {
				if err := h.store.StartRun(context.Background(), "job-already-running",
					ReasonScheduled, proto.BackupScopeIdentityOnly, time.Now().UTC()); err != nil {
					t.Fatalf("seed running run: %v", err)
				}
			}

			jobID := h.submit(t, tc.spec)
			j := h.waitTerminal(t, jobID)

			if tc.wantJob != "" && j.Status != tc.wantJob {
				t.Errorf("job status = %s, want %s (error: %s)", j.Status, tc.wantJob, j.Error)
			}
			if tc.wantErrContains != "" && !strings.Contains(j.Error, tc.wantErrContains) {
				t.Errorf("job error = %q, want it to contain %q", j.Error, tc.wantErrContains)
			}
			if got := h.agent.writeCount(); got != tc.wantWriteCalls {
				t.Errorf("the agent was asked to write %d time(s), want %d", got, tc.wantWriteCalls)
			}

			row := h.run(t, jobID)
			if tc.wantRunStatus == "" {
				if row != nil {
					t.Errorf("a refusal before the run was recorded left a row: %+v", row)
				}
			} else {
				if row == nil {
					t.Fatal("no backup_runs row")
				}
				if row.Status != tc.wantRunStatus {
					t.Errorf("run status = %s, want %s", row.Status, tc.wantRunStatus)
				}
				if row.Status != RunRunning && row.FinishedAt == nil {
					t.Error("a terminal row with no finish time renders as still-running — the #53 shape")
				}
			}
			if tc.check != nil {
				tc.check(t, h, jobID)
			}
		})
	}
}

// TestBackupRunWriteIsIrreversible proves the runner will not repeat the one
// step that puts bytes on somebody's disk.
//
// Two halves. The workflow must DECLARE it — jobs.ValidateWorkflow rejects a
// step that is both Irreversible and retried, and Register panics on one — and
// the runner must ENFORCE it, which is what a refused write with a single call
// count shows above. This test covers the declaration, and it covers the whole
// workflow rather than the one step, so a later edit that adds Retries to write
// fails here rather than at api startup on somebody's appliance.
func TestBackupRunWriteIsIrreversible(t *testing.T) {
	wf := RunWorkflow(nil, RunConfig{})
	if err := jobs.ValidateWorkflow(wf); err != nil {
		t.Fatalf("the backup.run workflow is not valid: %v", err)
	}
	var write, prune *jobs.WorkflowStep
	for i := range wf.Steps {
		switch wf.Steps[i].Name {
		case "write":
			write = &wf.Steps[i]
		case "prune":
			prune = &wf.Steps[i]
		}
	}
	if write == nil || prune == nil {
		t.Fatal("the workflow is missing the write or prune step")
	}
	if !write.Irreversible {
		t.Error("the write step is not declared Irreversible: a retry would land a second generation")
	}
	if write.Retries != 0 {
		t.Errorf("the write step declares %d retries", write.Retries)
	}
	// The deliberate asymmetry. Prune deletes archives and is NOT Irreversible,
	// because the verb is convergent: a second call on a settled target finds
	// Keep generations and removes nothing. Marking it would leave a target
	// over-retained after any transient failure, which is §4.4's disk-fills
	// failure mode arrived at from the other direction.
	if prune.Irreversible {
		t.Error("the prune step is declared Irreversible; the verb is convergent, and refusing to retry it leaves the target over-retained after a transient failure — see RunWorkflow's comment")
	}
	if prune.Retries < 1 {
		t.Error("the prune step has no retry, so a lost ack on a slow USB disk permanently over-retains the target")
	}
	if wf.OnTerminal == nil {
		t.Error("the workflow has no OnTerminal hook, so a failed run's ledger row stays `running` forever (#53)")
	}
}

// TestBackupRunOnTerminalFinalizesTheRow is the #53 assertion, on the path that
// matters most: a run that fails AFTER its row exists.
//
// Without the hook the saga's error fails the JOB and nothing touches the row,
// so the Backups view renders a failed backup as one still in progress — which
// is the single appearance §4.4 says a failed backup must never be able to take.
func TestBackupRunOnTerminalFinalizesTheRow(t *testing.T) {
	agent := &fakeBackupAgent{
		preflight: func(cmd proto.BackupPreflightCmd) proto.BackupPreflightAck {
			return proto.BackupPreflightAck{
				OK: false, Present: true, PartUUID: cmd.PartUUID,
				Refusal: proto.BackupRefusalInsufficientSpace,
				Detail:  "the target is full",
			}
		},
	}
	h := newRunHarness(t, agent, runHarnessOpts{})
	jobID := h.submit(t, RunSpec{Reason: ReasonScheduled})
	j := h.waitTerminal(t, jobID)
	if j.Status != jobs.StatusFailed {
		t.Fatalf("job status = %s, want failed", j.Status)
	}
	row := h.run(t, jobID)
	if row == nil {
		t.Fatal("no backup_runs row: step 1 records the attempt before anything is staged")
	}
	if row.Status != RunFailed {
		t.Errorf("run status = %s, want failed — a row still `running` after its job failed is the #53 bug", row.Status)
	}
	if row.FinishedAt == nil {
		t.Error("the failed row has no finish time, so it renders as still-running")
	}
	if !strings.Contains(row.Error, "the target is full") {
		t.Errorf("the row's error is %q, which does not say why the backup failed", row.Error)
	}
	// And the run is not counted as a success anywhere.
	last, err := h.store.LastSuccess(context.Background())
	if err != nil {
		t.Fatalf("LastSuccess: %v", err)
	}
	if last != nil {
		t.Errorf("a failed run is being reported as the last success: %+v", last)
	}
}

// TestReconcileStrandedRunsFinalizesOrphans covers what the hook cannot reach:
// a row stranded by a process that died between failing the job and firing it.
func TestReconcileStrandedRunsFinalizesOrphans(t *testing.T) {
	h := newRunHarness(t, nil, runHarnessOpts{})
	ctx := context.Background()
	jobID := "job-orphan"
	if err := h.jobStore.CreateJob(ctx, &jobs.Job{
		ID: jobID, Kind: RunJobKind, Spec: json.RawMessage("{}"),
		Status: jobs.StatusQueued, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if err := h.jobStore.MarkJobFailed(ctx, jobID, "control plane restarted mid-job", time.Now().UTC()); err != nil {
		t.Fatalf("MarkJobFailed: %v", err)
	}
	if err := h.store.StartRun(ctx, jobID, ReasonScheduled, proto.BackupScopeIdentityOnly, time.Now().UTC()); err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	if err := ReconcileStrandedRuns(ctx, h.store, h.jobStore); err != nil {
		t.Fatalf("ReconcileStrandedRuns: %v", err)
	}
	row := h.run(t, jobID)
	if row.Status != RunFailed {
		t.Errorf("stranded run status = %s, want failed", row.Status)
	}
	if !strings.Contains(row.Error, "restarted mid-job") {
		t.Errorf("the reconciled row does not carry the job's reason: %q", row.Error)
	}
}

// TestBackupRunSpecCannotAimTheRun records the deliberate narrowness of the
// spec: everything a run decides is POLICY, and §4.1 puts policy on the control
// plane. A spec that could name a disk or a retention count would let a caller
// aim a run at a target the operator never claimed, or empty the retained set,
// through the job ledger.
func TestBackupRunSpecCannotAimTheRun(t *testing.T) {
	spec, err := ParseRunSpec(json.RawMessage(`{"reason":"scheduled","partUuid":"somewhere-else","retain":0}`))
	if err != nil {
		t.Fatalf("ParseRunSpec: %v", err)
	}
	if spec.Reason != ReasonScheduled {
		t.Errorf("reason = %q", spec.Reason)
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"partUuid", "somewhere-else", "retain"} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("the round-tripped spec carries %q: RunSpec has a field it should not", forbidden)
		}
	}
	// An unknown reason is normalised rather than refused — it is a label on a
	// row, and refusing a backup over one would be the wrong trade.
	spec, err = ParseRunSpec(json.RawMessage(`{"reason":"whatever"}`))
	if err != nil {
		t.Fatalf("ParseRunSpec: %v", err)
	}
	if spec.Reason != ReasonManual {
		t.Errorf("an unrecognised reason became %q, want %q", spec.Reason, ReasonManual)
	}
}

// TestBackupRunStagesWhereTheAgentSaysAndNowhereElse is the api-side half of
// the fix for the 2026-09-02 e3bench failure.
//
// The harness puts the agent's staging root under an `agent-state`
// subdirectory, mirroring the shipping image, where nothing the api is
// configured with points. So a run that completes has proved two things at
// once: the archive was staged where the agent reads, and the api invented no
// directory of its own. The old code would have sealed into
// <dataDir>/backup-staging and this would fail on the write, which is precisely
// what the bench saw and no test did.
func TestBackupRunStagesWhereTheAgentSaysAndNowhereElse(t *testing.T) {
	agent := &fakeBackupAgent{}
	h := newRunHarness(t, agent, runHarnessOpts{})
	jobID := h.submit(t, RunSpec{Reason: ReasonManual})
	j := h.waitTerminal(t, jobID)
	if j.Status != jobs.StatusSucceeded {
		t.Fatalf("job status = %s (%s)", j.Status, j.Error)
	}

	cmd, ok := h.agent.lastWrite()
	if !ok {
		t.Fatal("the agent was never asked to write")
	}
	// The fake agent re-hashes the file it finds under ITS staging root, and
	// leaves the digest empty when there is nothing there. A non-empty digest
	// that matches the api's is the whole handoff, proved on real bytes.
	h.agent.mu.Lock()
	digests := append([]string(nil), h.agent.writeDigests...)
	h.agent.mu.Unlock()
	if len(digests) != 1 || digests[0] == "" {
		t.Fatalf("the agent found nothing under its staging root %s — the api staged somewhere else", h.stagingDir)
	}
	if digests[0] != cmd.Digest {
		t.Errorf("the agent hashed %s, the api claimed %s", digests[0], cmd.Digest)
	}

	// And nothing was created under the api's own data directory. This is the
	// assertion that fails if an api-side derivation ever comes back.
	dataDir := filepath.Dir(h.dbPath)
	if _, err := os.Stat(filepath.Join(dataDir, "backup-staging")); err == nil {
		t.Error("the api created a staging directory of its own under its data dir — the two halves are deriving the path independently again")
	}

	// The root is in the ledger, because an operator debugging a
	// staged-archive-not-found needs both halves of the disagreement and this
	// is the api's half.
	if got := h.ledgerText(t, jobID); !strings.Contains(got, h.stagingDir) {
		t.Errorf("the ledger never names the staging root %s", h.stagingDir)
	}
}

// TestBackupRunRefusesWhenTheAgentNamesNoStagingRoot: an agent older than its
// api answers preflight without the field. The api must refuse THERE, at the
// cheapest point, rather than fall back to a guess — the guess is the bug.
func TestBackupRunRefusesWhenTheAgentNamesNoStagingRoot(t *testing.T) {
	agent := &fakeBackupAgent{
		preflight: func(cmd proto.BackupPreflightCmd) proto.BackupPreflightAck {
			return proto.BackupPreflightAck{
				OK: true, Present: true, PartUUID: cmd.PartUUID,
				MountPath: "/mnt/rasputin-backup", TotalBytes: 2 << 40,
				FreeBytes: 1 << 40, RequiredBytes: cmd.EstimateBytes, Sufficient: true,
				// No StagingRoot.
			}
		},
	}
	h := newRunHarness(t, agent, runHarnessOpts{})
	jobID := h.submit(t, RunSpec{Reason: ReasonScheduled})
	j := h.waitTerminal(t, jobID)
	if j.Status != jobs.StatusFailed {
		t.Fatalf("job status = %s, want failed", j.Status)
	}
	if !strings.Contains(j.Error, "did not say where its backup staging root is") {
		t.Errorf("job error = %q, want it to name the missing staging root", j.Error)
	}
	if got := h.agent.writeCount(); got != 0 {
		t.Errorf("the agent was asked to write %d time(s) with nowhere to stage", got)
	}
	if left := h.stagingEntries(t); len(left) != 0 {
		t.Errorf("a run that never learned a staging root left %v behind", left)
	}
	row := h.run(t, jobID)
	if row == nil || row.Status != RunFailed {
		t.Errorf("run row = %+v, want a failed row", row)
	}
}

// TestBackupRunSweepsOrphansBeforeSizingTheDisk covers §4.7's third discipline
// where it now lives.
//
// It used to run at api start, against a directory the api derived for itself.
// That directory was the wrong one, so the sweep swept nothing — and the sweep
// and the handoff were broken by the same mistake. It now runs at the top of
// the snapshot step, on the root the agent named, BEFORE the free-space guard
// sizes the run: an orphan is both a permanent disk leak and space this run
// would otherwise be refused for.
func TestBackupRunSweepsOrphansBeforeSizingTheDisk(t *testing.T) {
	agent := &fakeBackupAgent{}
	h := newRunHarness(t, agent, runHarnessOpts{})

	orphan := filepath.Join(h.stagingDir, "20260101T000000Z-old-identity-only.sealed")
	if err := os.WriteFile(orphan, []byte("a previous run died between sealing and writing"), 0o600); err != nil {
		t.Fatalf("seed orphan: %v", err)
	}

	jobID := h.submit(t, RunSpec{Reason: ReasonScheduled})
	if j := h.waitTerminal(t, jobID); j.Status != jobs.StatusSucceeded {
		t.Fatalf("job status = %s (%s)", j.Status, j.Error)
	}
	if _, err := os.Stat(orphan); err == nil {
		t.Error("the orphaned staged archive survived the run")
	}
	if got := h.ledgerText(t, jobID); !strings.Contains(got, "swept 1 orphaned staged archive") {
		t.Error("the sweep is not in the ledger, so an operator never learns a previous run died mid-seal")
	}
	if left := h.stagingEntries(t); len(left) != 0 {
		t.Errorf("staging is not empty after a successful run: %v", left)
	}
}

// TestBackupRunRefusesATargetOnAnotherNode: the staging root now arrives in the
// preflight ack, so the question of WHOSE ack the api will act on is a real
// one. Step 1 answers it — the target has to be on this node — and the refusal
// costs nothing, where the old failure cost a full snapshot, assemble and seal
// before the agent said it could not find the file.
func TestBackupRunRefusesATargetOnAnotherNode(t *testing.T) {
	h := newRunHarness(t, &fakeBackupAgent{}, runHarnessOpts{targetNodeID: "n-storage-2"})
	jobID := h.submit(t, RunSpec{Reason: ReasonManual})
	j := h.waitTerminal(t, jobID)
	if j.Status != jobs.StatusFailed {
		t.Fatalf("job status = %s, want failed", j.Status)
	}
	for _, want := range []string{"is on node n-storage-2", "runs on " + runNodeID, "no transfer to another node"} {
		if !strings.Contains(j.Error, want) {
			t.Errorf("job error = %q, want it to contain %q", j.Error, want)
		}
	}
	// Before any RPC at all: the agent was never even asked to preflight, so no
	// staging root from a node this api does not share a filesystem with ever
	// reached it.
	h.agent.mu.Lock()
	preflights := len(h.agent.preflightCmds)
	h.agent.mu.Unlock()
	if preflights != 0 {
		t.Errorf("the agent was preflighted %d time(s) for a target on another node", preflights)
	}
	if left := h.stagingEntries(t); len(left) != 0 {
		t.Errorf("a step-1 refusal staged %v", left)
	}
}

// TestBackupRunRefusesWhenTheApiDoesNotKnowItsOwnNode: with RASPUTIN_SELF_NODE_ID
// unset the co-location check cannot be made, and the answer is a refusal rather
// than "act on whichever agent answers".
func TestBackupRunRefusesWhenTheApiDoesNotKnowItsOwnNode(t *testing.T) {
	none := ""
	h := newRunHarness(t, &fakeBackupAgent{}, runHarnessOpts{selfNodeID: &none})
	jobID := h.submit(t, RunSpec{Reason: ReasonScheduled})
	j := h.waitTerminal(t, jobID)
	if j.Status != jobs.StatusFailed {
		t.Fatalf("job status = %s, want failed", j.Status)
	}
	if !strings.Contains(j.Error, "does not know which node it runs on") {
		t.Errorf("job error = %q", j.Error)
	}
	if got := h.agent.writeCount(); got != 0 {
		t.Errorf("the agent was asked to write %d time(s)", got)
	}
}

// TestBackupRunRefusesAMisshapenStagingRoot: the one value in this saga that
// comes off the wire is shape-checked before it reaches os.MkdirAll,
// CleanStaging or a file open. A relative path or one carrying `..` is not
// something any agent of ours resolves, so it is a bug or a corrupted reply and
// gets refused rather than normalised.
func TestBackupRunRefusesAMisshapenStagingRoot(t *testing.T) {
	for _, tc := range []struct{ name, root, want string }{
		{"relative", "var/lib/rasputin/backup-staging", "not an absolute path"},
		{"traversal", "/var/lib/rasputin/agent-state/../../../etc", "not a clean path"},
		{"trailing separator", "/var/lib/rasputin/backup-staging/", "not a clean path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := tc.root
			agent := &fakeBackupAgent{
				preflight: func(cmd proto.BackupPreflightCmd) proto.BackupPreflightAck {
					return proto.BackupPreflightAck{
						OK: true, Present: true, PartUUID: cmd.PartUUID,
						MountPath: "/mnt/rasputin-backup", TotalBytes: 2 << 40,
						FreeBytes: 1 << 40, RequiredBytes: cmd.EstimateBytes, Sufficient: true,
						StagingRoot: root,
					}
				},
			}
			h := newRunHarness(t, agent, runHarnessOpts{})
			jobID := h.submit(t, RunSpec{Reason: ReasonManual})
			j := h.waitTerminal(t, jobID)
			if j.Status != jobs.StatusFailed {
				t.Fatalf("job status = %s, want failed", j.Status)
			}
			if !strings.Contains(j.Error, tc.want) {
				t.Errorf("job error = %q, want it to contain %q", j.Error, tc.want)
			}
			if got := h.agent.writeCount(); got != 0 {
				t.Errorf("the agent was asked to write %d time(s)", got)
			}
		})
	}
}

// TestCheckStagingRootAcceptsWhatTheAgentActuallyResolves: the shape gate must
// not reject the real answers — the shipping default and a directory an
// operator pointed RASPUTIN_BACKUP_STAGING_DIR at.
func TestCheckStagingRootAcceptsWhatTheAgentActuallyResolves(t *testing.T) {
	for _, ok := range []string{
		"/var/lib/rasputin/agent-state/backup-staging",
		"/mnt/elsewhere/staging",
		"/tmp/x",
	} {
		if err := checkStagingRoot(ok); err != nil {
			t.Errorf("checkStagingRoot(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "relative/dir", "/a/../b", "/a//b", "/a/"} {
		if err := checkStagingRoot(bad); err == nil {
			t.Errorf("checkStagingRoot(%q) accepted a path this api must not write into", bad)
		}
	}
}
