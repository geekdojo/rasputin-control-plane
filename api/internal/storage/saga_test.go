package storage

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The backup.target.claim saga, end to end, over a real jobs.Runner and a fake
// agent on an in-process NATS server.
//
// The saga's whole design is its ORDER: the runner has no compensation, so
// every refusal has to happen before the mkfs rather than after it. These cases
// are therefore mostly about what does NOT happen — how many times the agent
// was asked to format, and whether it was asked at all.

type sagaCase struct {
	name string
	// spec mutates the base spec for this case.
	spec func(*ClaimSpec)
	// seedClaimed puts an already-claimed target in the ledger first.
	seedClaimed bool
	enumerate   func(call int) proto.StorageEnumerateAck
	claim       func(cmd proto.StorageClaimCmd) proto.StorageClaimAck
	inspect     func(cmd proto.StorageInspectCmd) proto.StorageInspectAck

	wantJob jobs.Status
	// wantTargetStatus is "" when the case must leave no row at all — a
	// refusal at step 1 happens before the attempt is recorded.
	wantTargetStatus TargetStatus
	wantErrContains  string
	wantClaimCalls   int
	wantInspectCalls int
	check            func(t *testing.T, h *harness, jobID string)
}

func TestClaimSaga(t *testing.T) {
	cases := []sagaCase{
		{
			name:             "a blank disk is formatted and recorded",
			enumerate:        func(int) proto.StorageEnumerateAck { return ackWith(blankCandidate()) },
			wantJob:          jobs.StatusSucceeded,
			wantTargetStatus: TargetClaimed,
			wantClaimCalls:   1,
			check: func(t *testing.T, h *harness, jobID string) {
				row := h.target(t, jobID)
				if row.PartUUID != "part-uuid-new" {
					t.Errorf("partUuid = %q — the partition UUID minted at format time is the target's only identifier", row.PartUUID)
				}
				if row.MountPath == "" {
					t.Error("mount path not recorded")
				}
				if row.Adopted {
					t.Error("a formatted disk is not an adopted one")
				}
				if row.ClaimedAt == nil {
					t.Error("a terminal row with no finish time renders as still-running")
				}
				// The post-format fingerprint DIFFERS from the confirmed one by
				// construction; recording it as drift would fail every good claim.
				if row.Fingerprint != "fp-after-format" {
					t.Errorf("fingerprint = %q, want the POST-format one the agent returned", row.Fingerprint)
				}
				cmd, ok := h.agent.lastClaim()
				if !ok {
					t.Fatal("no claim command captured")
				}
				if cmd.Fingerprint != testFingerpr {
					t.Errorf("claim carried fingerprint %q, want the one the operator confirmed", cmd.Fingerprint)
				}
				if cmd.ClusterID != "home1" {
					t.Errorf("claim carried clusterId %q — the marker is what tells a replacement controlplane whose archive a disk holds", cmd.ClusterID)
				}
			},
		},
		{
			name:             "step 1 refuses a claim with no fingerprint",
			spec:             func(s *ClaimSpec) { s.Fingerprint = "" },
			enumerate:        func(int) proto.StorageEnumerateAck { return ackWith(blankCandidate()) },
			wantJob:          jobs.StatusFailed,
			wantErrContains:  "fingerprint is required",
			wantTargetStatus: "",
			wantClaimCalls:   0,
		},
		{
			name:             "step 1 refuses an unknown node",
			spec:             func(s *ClaimSpec) { s.NodeID = "not-a-node" },
			wantJob:          jobs.StatusFailed,
			wantErrContains:  "not registered",
			wantTargetStatus: "",
			wantClaimCalls:   0,
		},
		{
			name:             "step 1 refuses a second target when replace is not set",
			seedClaimed:      true,
			enumerate:        func(int) proto.StorageEnumerateAck { return ackWith(blankCandidate()) },
			wantJob:          jobs.StatusFailed,
			wantErrContains:  "already has a claimed backup target",
			wantTargetStatus: "",
			wantClaimCalls:   0,
		},
		{
			name:             "step 1 accepts a second target when replace is set, and supersedes the old one",
			seedClaimed:      true,
			spec:             func(s *ClaimSpec) { s.Replace = true },
			enumerate:        func(int) proto.StorageEnumerateAck { return ackWith(blankCandidate()) },
			wantJob:          jobs.StatusSucceeded,
			wantTargetStatus: TargetClaimed,
			wantClaimCalls:   1,
			check: func(t *testing.T, h *harness, jobID string) {
				old := h.target(t, "seeded-job")
				if old == nil {
					t.Fatal("the superseded row was deleted — the disk it names may hold the only copy of an archive")
				}
				if old.Status != TargetReplaced {
					t.Errorf("previous target status = %q, want %q", old.Status, TargetReplaced)
				}
			},
		},
		{
			name:             "step 2 refuses a disk that is no longer attached",
			enumerate:        func(int) proto.StorageEnumerateAck { return ackWith() },
			wantJob:          jobs.StatusFailed,
			wantErrContains:  string(proto.StorageRefusalDeviceAbsent),
			wantTargetStatus: TargetFailed,
			wantClaimCalls:   0,
		},
		{
			name:             "step 2 refuses the disk holding the mounted boot and persistent partitions",
			enumerate:        func(int) proto.StorageEnumerateAck { return ackWith(protectedCandidate()) },
			wantJob:          jobs.StatusFailed,
			wantErrContains:  string(proto.StorageRefusalProtected),
			wantTargetStatus: TargetFailed,
			wantClaimCalls:   0,
		},
		{
			name: "step 2 refuses when the fingerprint drifted from what the operator confirmed",
			enumerate: func(int) proto.StorageEnumerateAck {
				c := blankCandidate()
				c.Fingerprint = testOtherFing // same path, different disk (or a changed table)
				return ackWith(c)
			},
			wantJob:          jobs.StatusFailed,
			wantErrContains:  string(proto.StorageRefusalFingerprintMismatch),
			wantTargetStatus: TargetFailed,
			wantClaimCalls:   0,
		},
		{
			name: "step 2 follows the disk when it moved to another device path",
			enumerate: func(int) proto.StorageEnumerateAck {
				c := blankCandidate()
				c.DevicePath = "/dev/sdd" // the kernel enumerated differently this boot
				return ackWith(c)
			},
			wantJob:          jobs.StatusSucceeded,
			wantTargetStatus: TargetClaimed,
			wantClaimCalls:   1,
			check: func(t *testing.T, h *harness, jobID string) {
				cmd, _ := h.agent.lastClaim()
				if cmd.DevicePath != "/dev/sdd" {
					t.Errorf("claim went to %q, want the path the disk has NOW — a device path is a handle for one moment, the fingerprint is the identity", cmd.DevicePath)
				}
			},
		},
		{
			name: "step 2 refuses when two attached disks carry the confirmed fingerprint",
			enumerate: func(int) proto.StorageEnumerateAck {
				a, b := blankCandidate(), blankCandidate()
				a.IdentityWeak, b.IdentityWeak = true, true
				b.DevicePath = "/dev/sdc"
				return ackWith(a, b)
			},
			wantJob:          jobs.StatusFailed,
			wantErrContains:  "carry the confirmed fingerprint",
			wantTargetStatus: TargetFailed,
			wantClaimCalls:   0,
		},
		{
			name:             "step 3 refuses a disk carrying a backup set when adopt is not chosen",
			enumerate:        func(int) proto.StorageEnumerateAck { return ackWith(backupSetCandidate()) },
			wantJob:          jobs.StatusFailed,
			wantErrContains:  string(proto.StorageRefusalBackupSetPresent),
			wantTargetStatus: TargetFailed,
			wantClaimCalls:   0,
		},
		{
			name:             "step 3 proceeds when adopt is chosen, and nothing is formatted",
			spec:             func(s *ClaimSpec) { s.Adopt = true },
			enumerate:        func(int) proto.StorageEnumerateAck { return ackWith(backupSetCandidate()) },
			wantJob:          jobs.StatusSucceeded,
			wantTargetStatus: TargetClaimed,
			wantClaimCalls:   0,
			wantInspectCalls: 1,
			check: func(t *testing.T, h *harness, jobID string) {
				row := h.target(t, jobID)
				if !row.Adopted {
					t.Error("row should record that this target was adopted, not formatted")
				}
				if row.PartUUID != "part-uuid-existing" {
					t.Errorf("partUuid = %q, want the marker's own — a disk that was formatted but never recorded is re-adopted by its own account", row.PartUUID)
				}
				if row.KeyID != "key-existing" {
					t.Errorf("keyId = %q, want the disk's own: its generations are encrypted under that key and no other", row.KeyID)
				}
			},
		},
		{
			name:             "step 3 refuses adopt on a disk that carries no backup set",
			spec:             func(s *ClaimSpec) { s.Adopt = true },
			enumerate:        func(int) proto.StorageEnumerateAck { return ackWith(blankCandidate()) },
			wantJob:          jobs.StatusFailed,
			wantErrContains:  "carries no Rasputin backup set",
			wantTargetStatus: TargetFailed,
			wantClaimCalls:   0,
		},
		{
			name: "step 3 refuses adopt when the marker is unreadable",
			enumerate: func(int) proto.StorageEnumerateAck {
				c := backupSetCandidate()
				c.BackupSet = nil // announced a set, could not read the marker
				return ackWith(c)
			},
			spec:             func(s *ClaimSpec) { s.Adopt = true },
			wantJob:          jobs.StatusFailed,
			wantErrContains:  "unreadable",
			wantTargetStatus: TargetFailed,
			wantClaimCalls:   0,
		},
		{
			name:      "step 3 refuses adopt with a key id the disk's generations are not under",
			enumerate: func(int) proto.StorageEnumerateAck { return ackWith(backupSetCandidate()) },
			spec: func(s *ClaimSpec) {
				s.Adopt = true
				s.ArchiveKey = &ArchiveKey{
					KeyID: "key-brand-new", Alg: "test", PublicKey: markerPublicKey,
					WrappedByPassphrase: "wrapped-a", WrappedByRecoveryCode: "wrapped-b",
				}
			},
			wantJob:          jobs.StatusFailed,
			wantErrContains:  "encrypted under key key-existing",
			wantTargetStatus: TargetFailed,
			wantClaimCalls:   0,
		},
		// ---- §4.8's second, separate choice: wipe ------------------------
		{
			// The refusal a disk carrying a set gets by default now names both
			// ways past it. Neither is a default; the disk is untouched.
			name:             "the default refusal offers adopt AND wipe",
			enumerate:        func(int) proto.StorageEnumerateAck { return ackWith(backupSetCandidate()) },
			wantJob:          jobs.StatusFailed,
			wantErrContains:  "`wipe` with the confirmation token",
			wantTargetStatus: TargetFailed,
			wantClaimCalls:   0,
		},
		{
			// An absent token is a refusal, never a default to wipe — and it is
			// caught at step 1, before the attempt is even recorded.
			name:             "a wipe with no confirmation token is refused",
			spec:             func(s *ClaimSpec) { s.Wipe = &WipeConfirmation{} },
			enumerate:        func(int) proto.StorageEnumerateAck { return ackWith(backupSetCandidate()) },
			wantJob:          jobs.StatusFailed,
			wantErrContains:  "wipe.token is required",
			wantTargetStatus: "",
			wantClaimCalls:   0,
		},
		{
			name:             "a wipe with the wrong confirmation token is refused",
			spec:             func(s *ClaimSpec) { s.Wipe = &WipeConfirmation{Token: "wipe-000000000000000000000000"} },
			enumerate:        func(int) proto.StorageEnumerateAck { return ackWith(backupSetCandidate()) },
			wantJob:          jobs.StatusFailed,
			wantErrContains:  "the wipe confirmation does not match this disk",
			wantTargetStatus: TargetFailed,
			wantClaimCalls:   0,
			check: func(t *testing.T, h *harness, jobID string) {
				// A refusal is not a how-to. The expected token must not appear
				// anywhere an operator could copy it from instead of looking at
				// the disk again.
				assertTokenNotPublished(t, h, jobID, CandidateWipeToken(ptr(backupSetCandidate())))
			},
		},
		{
			// Both are answers to "what about the set already on this disk?".
			// Neither is picked for the caller, because one of the two guesses
			// destroys an archive.
			name: "adopt and wipe together are refused",
			spec: func(s *ClaimSpec) {
				s.Adopt = true
				s.Wipe = &WipeConfirmation{Token: CandidateWipeToken(ptr(backupSetCandidate()))}
			},
			enumerate:        func(int) proto.StorageEnumerateAck { return ackWith(backupSetCandidate()) },
			wantJob:          jobs.StatusFailed,
			wantErrContains:  "opposite choices",
			wantTargetStatus: "",
			wantClaimCalls:   0,
		},
		{
			name:             "a wipe on a disk that carries no backup set is refused",
			spec:             wipeSpecFor(backupSetCandidate()),
			enumerate:        func(int) proto.StorageEnumerateAck { return ackWith(blankCandidate()) },
			wantJob:          jobs.StatusFailed,
			wantErrContains:  "carries no Rasputin backup set",
			wantTargetStatus: TargetFailed,
			wantClaimCalls:   0,
		},
		{
			name:             "a confirmed wipe formats the disk and records what it destroyed",
			spec:             wipeSpecFor(backupSetCandidate()),
			enumerate:        func(int) proto.StorageEnumerateAck { return ackWith(backupSetCandidate()) },
			wantJob:          jobs.StatusSucceeded,
			wantTargetStatus: TargetClaimed,
			wantClaimCalls:   1,
			// Never inspect: inspect is the ADOPT verb, and reaching it here
			// would mean the wipe took the non-destructive branch.
			wantInspectCalls: 0,
			check: func(t *testing.T, h *harness, jobID string) {
				row := h.target(t, jobID)
				if !row.Wiped {
					t.Error("the ledger must record that this claim destroyed an existing backup set")
				}
				if row.Adopted {
					t.Error("a wipe is not an adopt")
				}
				if row.PartUUID != "part-uuid-new" {
					t.Errorf("partUuid = %q, want the one minted by the format — the old set's UUID died with it", row.PartUUID)
				}
				cmd, ok := h.agent.lastClaim()
				if !ok {
					t.Fatal("no claim command captured")
				}
				// The heart of the safety argument: a wipe is byte-for-byte the
				// same command as an ordinary format. There is no wipe flag on
				// the wire, so there is no agent-side branch that could skip the
				// boot-device exclusion or the fingerprint re-check.
				if cmd != (proto.StorageClaimCmd{
					DevicePath: testDevice, Fingerprint: testFingerpr,
					Label: "backup disk", ClusterID: "home1",
				}) {
					t.Errorf("wipe sent a different command than an ordinary claim: %+v", cmd)
				}
			},
		},
		{
			// The dead end §4.8 left open: a disk that announces a set whose
			// marker cannot be parsed can be neither adopted (nothing to adopt
			// it by) nor claimed as blank (the backup-set refusal). It is
			// precisely the disk an operator most needs to reclaim.
			name: "a confirmed wipe reclaims a disk whose marker is unreadable",
			spec: wipeSpecFor(unreadableMarkerCandidate()),
			enumerate: func(int) proto.StorageEnumerateAck {
				return ackWith(unreadableMarkerCandidate())
			},
			wantJob:          jobs.StatusSucceeded,
			wantTargetStatus: TargetClaimed,
			wantClaimCalls:   1,
			wantInspectCalls: 0,
			check: func(t *testing.T, h *harness, jobID string) {
				if row := h.target(t, jobID); !row.Wiped {
					t.Error("the ledger must record the wipe")
				}
			},
		},
		{
			// The same disk, the same confirmed token, WITHOUT the wipe choice:
			// still the dead end, and the refusal now says how to get out of it.
			name:             "an unreadable marker is still a refusal for adopt, and names wipe as the way out",
			spec:             func(s *ClaimSpec) { s.Adopt = true },
			enumerate:        func(int) proto.StorageEnumerateAck { return ackWith(unreadableMarkerCandidate()) },
			wantJob:          jobs.StatusFailed,
			wantErrContains:  "choose `wipe` with the confirmation token",
			wantTargetStatus: TargetFailed,
			wantClaimCalls:   0,
		},
		{
			// THE HARD SAFETY RULE. A wipe changes which disks are eligible,
			// never which checks run: step 2's boot-medium refusal still fires,
			// and it fires before the token is even looked at.
			name:             "a confirmed wipe is still refused on the disk holding the mounted boot partitions",
			spec:             wipeSpecFor(protectedBackupSetCandidate()),
			enumerate:        func(int) proto.StorageEnumerateAck { return ackWith(protectedBackupSetCandidate()) },
			wantJob:          jobs.StatusFailed,
			wantErrContains:  string(proto.StorageRefusalProtected),
			wantTargetStatus: TargetFailed,
			wantClaimCalls:   0,
		},
		{
			// Likewise the fingerprint. A wipe cannot outrun step 2.
			name: "a confirmed wipe is still refused when the fingerprint drifted",
			spec: wipeSpecFor(backupSetCandidate()),
			enumerate: func(int) proto.StorageEnumerateAck {
				c := backupSetCandidate()
				c.Fingerprint = testOtherFing
				return ackWith(c)
			},
			wantJob:          jobs.StatusFailed,
			wantErrContains:  string(proto.StorageRefusalFingerprintMismatch),
			wantTargetStatus: TargetFailed,
			wantClaimCalls:   0,
		},
		{
			name:      "step 4 is not retried when the agent refuses the format",
			enumerate: func(int) proto.StorageEnumerateAck { return ackWith(blankCandidate()) },
			claim: func(proto.StorageClaimCmd) proto.StorageClaimAck {
				return proto.StorageClaimAck{
					OK: false, Refusal: proto.StorageRefusalFingerprintMismatch,
					Detail: "the partition table changed under us",
				}
			},
			wantJob:          jobs.StatusFailed,
			wantErrContains:  string(proto.StorageRefusalFingerprintMismatch),
			wantTargetStatus: TargetFailed,
			// Exactly one. The step is Irreversible, so the runner never
			// re-runs it — a retried mkfs is a second mkfs.
			wantClaimCalls: 1,
		},
		{
			name:      "step 4 refuses a success that names no partition UUID",
			enumerate: func(int) proto.StorageEnumerateAck { return ackWith(blankCandidate()) },
			claim: func(cmd proto.StorageClaimCmd) proto.StorageClaimAck {
				ack := defaultClaimAck(cmd)
				ack.PartUUID = ""
				ack.BackupSet = nil
				return ack
			},
			wantJob:          jobs.StatusFailed,
			wantErrContains:  "no partition UUID",
			wantTargetStatus: TargetFailed,
			wantClaimCalls:   1,
		},
		{
			name:      "the adopt path refuses when the target has been unplugged",
			spec:      func(s *ClaimSpec) { s.Adopt = true },
			enumerate: func(int) proto.StorageEnumerateAck { return ackWith(backupSetCandidate()) },
			inspect: func(cmd proto.StorageInspectCmd) proto.StorageInspectAck {
				return proto.StorageInspectAck{OK: true, Present: false, PartUUID: cmd.PartUUID}
			},
			wantJob:          jobs.StatusFailed,
			wantErrContains:  string(proto.StorageRefusalNotFound),
			wantTargetStatus: TargetFailed,
			wantClaimCalls:   0,
			wantInspectCalls: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, &fakeAgent{
				enumerate: tc.enumerate, claim: tc.claim, inspect: tc.inspect,
			})
			if tc.seedClaimed {
				seedClaimedTarget(t, h.store, "seeded-job")
			}
			spec := baseSpec()
			if tc.spec != nil {
				tc.spec(&spec)
			}
			jobID := h.submit(t, spec)
			done := h.waitTerminal(t, jobID)

			if done.Status != tc.wantJob {
				t.Errorf("job status = %q, want %q (error: %s)", done.Status, tc.wantJob, done.Error)
			}
			if tc.wantErrContains != "" && !strings.Contains(done.Error, tc.wantErrContains) {
				t.Errorf("job error = %q, want it to mention %q", done.Error, tc.wantErrContains)
			}
			row := h.target(t, jobID)
			switch {
			case tc.wantTargetStatus == "":
				if row != nil {
					t.Errorf("a refusal before the attempt was recorded must leave no row, got %+v", row)
				}
			case row == nil:
				t.Fatalf("no backup_targets row; want status %q", tc.wantTargetStatus)
			default:
				if row.Status != tc.wantTargetStatus {
					t.Errorf("target status = %q, want %q", row.Status, tc.wantTargetStatus)
				}
				// The #53 lesson: a row still pending after its job ended
				// renders as a claim that is still running, forever.
				if row.Status == TargetPending {
					t.Error("row left pending after a terminal job — OnTerminal did not fire")
				}
				if row.ClaimedAt == nil {
					t.Error("a terminal row must carry a finish time")
				}
			}
			if got := h.agent.claimCount(); got != tc.wantClaimCalls {
				t.Errorf("agent claim RPCs = %d, want %d", got, tc.wantClaimCalls)
			}
			if got := h.agent.inspectCount(); got != tc.wantInspectCalls {
				t.Errorf("agent inspect RPCs = %d, want %d", got, tc.wantInspectCalls)
			}
			if tc.check != nil {
				tc.check(t, h, jobID)
			}
			h.runner.Wait()
		})
	}
}

// seedClaimedTarget puts an already-claimed target in the ledger, the way a
// previous successful run would have.
func seedClaimedTarget(t *testing.T, store *Store, jobID string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Add(-time.Hour)
	if err := store.CreatePending(ctx, jobID, testNode, "/dev/sdz", "the old disk", now); err != nil {
		t.Fatalf("seed CreatePending: %v", err)
	}
	if err := store.MarkClaimed(ctx, jobID, ClaimResult{
		PartUUID: "part-uuid-old", DevicePath: "/dev/sdz", MountPath: "/mnt/old",
		FSType: "ext4", SizeBytes: 1 << 40, Fingerprint: "fp-old", At: now,
	}); err != nil {
		t.Fatalf("seed MarkClaimed: %v", err)
	}
}

// ============================================================================
// §4.6: what the job ledger, the step results and the live event stream may
// carry.
// ============================================================================

// The wrapped key blobs are ciphertext and the spec legitimately carries them —
// that is how they reach the store. What must NOT happen is their appearing in
// a STEP RESULT or a LOG LINE: StepCtx.Log writes to the job_events table AND
// publishes on the live NATS subject, so a log line is a broadcast, and step
// results are rendered in the Tasks view.
//
// The PRIVATE key is excluded structurally rather than by test: ClaimSpec has no
// field that could hold one, and the HTTP handler decodes with
// DisallowUnknownFields so a body carrying one is refused (see the api package).
// The public key is a different animal — it is in the spec, in the store and in
// the response on purpose, and §4.6's amendment turns on it being harmless
// there.
func TestClaimSaga_KeyMaterialNeverLeavesTheSpecAndTheStore(t *testing.T) {
	const (
		wrappedPass     = "SENTINEL-WRAPPED-BY-PASSPHRASE"
		wrappedRecovery = "SENTINEL-WRAPPED-BY-RECOVERY-CODE"
	)
	h := newHarness(t, &fakeAgent{
		enumerate: func(int) proto.StorageEnumerateAck { return ackWith(blankCandidate()) },
	})
	spec := baseSpec()
	spec.ArchiveKey = &ArchiveKey{
		KeyID: "key-2026-08", Alg: markerKeyAlg, PublicKey: markerPublicKey,
		WrappedByPassphrase: wrappedPass, WrappedByRecoveryCode: wrappedRecovery,
	}
	jobID := h.submit(t, spec)
	if done := h.waitTerminal(t, jobID); done.Status != jobs.StatusSucceeded {
		t.Fatalf("job failed: %s", done.Error)
	}
	ctx := context.Background()

	// Not vacuous: the blobs really are in the spec, which is how they got to
	// the store at all.
	j, _ := h.jobStore.GetJob(ctx, jobID)
	if !strings.Contains(string(j.Spec), wrappedPass) {
		t.Fatal("the wrapped blob is not in the spec — this test would prove nothing")
	}
	// And they really did land in the store.
	pass, recovery, err := h.store.GetWrappedKeys(ctx, jobID)
	if err != nil {
		t.Fatalf("GetWrappedKeys: %v", err)
	}
	if pass != wrappedPass || recovery != wrappedRecovery {
		t.Fatalf("wrapped blobs not persisted: %q / %q", pass, recovery)
	}

	steps, err := h.jobStore.ListSteps(ctx, jobID)
	if err != nil {
		t.Fatalf("ListSteps: %v", err)
	}
	if len(steps) != 5 {
		t.Fatalf("want 5 recorded steps, got %d", len(steps))
	}
	for _, st := range steps {
		for _, sentinel := range []string{wrappedPass, wrappedRecovery} {
			if strings.Contains(string(st.Result), sentinel) {
				t.Errorf("step %q result carries key material: %s", st.Name, st.Result)
			}
		}
	}

	events, err := h.jobStore.ListEvents(ctx, jobID)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	for _, ev := range events {
		// job.created echoes the whole job row, spec included; that is the
		// ledger carrying wrapped ciphertext, which is allowed. Every other
		// event type is the saga's own output and must be clean.
		if ev.Type == string(proto.JobCreated) {
			continue
		}
		for _, sentinel := range []string{wrappedPass, wrappedRecovery} {
			if strings.Contains(string(ev.Data), sentinel) {
				t.Errorf("event %q carries key material: %s", ev.Type, ev.Data)
			}
		}
	}

	// And the row an operator sees names the key without carrying it.
	row := h.target(t, jobID)
	if row.KeyID != "key-2026-08" || !row.HasWrappedKeys {
		t.Errorf("row should record the key id and that wrappings exist: %+v", row)
	}
	blob, err := json.Marshal(row)
	if err != nil {
		t.Fatalf("marshal row: %v", err)
	}
	for _, sentinel := range []string{wrappedPass, wrappedRecovery} {
		if strings.Contains(string(blob), sentinel) {
			t.Errorf("BackupTarget JSON carries key material: %s", blob)
		}
	}
	h.runner.Wait()
}

// A half-supplied key is refused rather than stored: a target with only the
// passphrase wrapping is one forgotten passphrase from an unreadable archive,
// and the operator would find out on the day they needed the backup.
func TestClaimSaga_RefusesAHalfSuppliedArchiveKey(t *testing.T) {
	h := newHarness(t, &fakeAgent{
		enumerate: func(int) proto.StorageEnumerateAck { return ackWith(blankCandidate()) },
	})
	spec := baseSpec()
	spec.ArchiveKey = &ArchiveKey{KeyID: "k", WrappedByPassphrase: "only-one"}
	jobID := h.submit(t, spec)
	done := h.waitTerminal(t, jobID)
	if done.Status != jobs.StatusFailed {
		t.Fatalf("want failed, got %q", done.Status)
	}
	if !strings.Contains(done.Error, "wrappedByRecoveryCode") {
		t.Errorf("error should name what is missing: %q", done.Error)
	}
	if h.agent.claimCount() != 0 {
		t.Error("nothing should have been formatted")
	}
	h.runner.Wait()
}

// The disk the operator confirmed can change between the picker and the saga —
// that window is the entire reason the fingerprint exists. Here the first
// enumeration (the picker's) shows a blank disk and the second (step 2's) shows
// a different one at the same path.
func TestClaimSaga_DriftBetweenThePickerAndTheSaga(t *testing.T) {
	h := newHarness(t, &fakeAgent{
		enumerate: func(call int) proto.StorageEnumerateAck {
			if call == 1 {
				return ackWith(blankCandidate())
			}
			c := blankCandidate()
			c.Fingerprint = testOtherFing
			c.Serial = "SOMEONE-ELSES"
			return ackWith(c)
		},
	})
	// Call 1 is the picker's read-only enumeration, exactly as the HTTP
	// handler would issue it.
	ack, err := Enumerate(context.Background(), h.nc, testNode)
	if err != nil {
		t.Fatalf("picker enumerate: %v", err)
	}
	if len(ack.Candidates) != 1 {
		t.Fatalf("picker saw %d candidates", len(ack.Candidates))
	}
	spec := baseSpec()
	spec.Fingerprint = ack.Candidates[0].Fingerprint

	jobID := h.submit(t, spec)
	done := h.waitTerminal(t, jobID)
	if done.Status != jobs.StatusFailed {
		t.Fatalf("want failed, got %q", done.Status)
	}
	if !strings.Contains(done.Error, string(proto.StorageRefusalFingerprintMismatch)) {
		t.Errorf("error = %q, want a fingerprint-mismatch refusal", done.Error)
	}
	if h.agent.claimCount() != 0 {
		t.Error("a drifted disk must never be formatted")
	}
	h.runner.Wait()
}

// Step 4 acts only on step 3's plan. It deliberately has no fallback that
// re-derives one — re-deriving is how a step ends up formatting a disk on the
// strength of evidence nothing checked.
func TestClaimStep_RefusesToClaimWithoutAPlan(t *testing.T) {
	nc := startNATS(t)
	agent := (&fakeAgent{nodeID: testNode}).start(t, nc)
	sc := stepCtx("j", baseSpec(), nc, nil)
	if _, err := claimClaim(Config{})(sc); err == nil {
		t.Fatal("want a refusal when check_existing left no plan")
	} else if !strings.Contains(err.Error(), "does not reconstruct its own authorization") {
		t.Errorf("error = %q", err)
	}
	if agent.claimCount() != 0 {
		t.Error("nothing should have reached the agent")
	}
}

// ============================================================================
// §4.8's wipe token: what it binds to, and who it is minted for.
// ============================================================================

// The token commits to ONE disk in ONE state. Here the picker shows the
// operator a disk holding four generations; by the time the saga runs, the disk
// holds five. Nothing about the disk's identity changed, so step 2 is happy —
// but what the operator confirmed destroying is not what is there now, and the
// wipe is refused rather than applied to a disk nobody looked at.
func TestWipe_TokenGoesStaleWhenTheDiskContentsChange(t *testing.T) {
	h := newHarness(t, &fakeAgent{
		enumerate: func(call int) proto.StorageEnumerateAck {
			c := backupSetCandidate()
			if call > 1 {
				c.BackupSet.Generations = 5 // a backup landed in between
			}
			return ackWith(c)
		},
	})
	// Call 1 is the picker's read-only enumeration, exactly as the HTTP handler
	// issues it, and the token comes from what it returned.
	ack, err := Enumerate(context.Background(), h.nc, testNode)
	if err != nil {
		t.Fatalf("picker enumerate: %v", err)
	}
	token := CandidateWipeToken(&ack.Candidates[0])
	if token == "" {
		t.Fatal("the picker minted no token for a wipe-eligible disk")
	}

	spec := baseSpec()
	spec.Wipe = &WipeConfirmation{Token: token}
	jobID := h.submit(t, spec)
	done := h.waitTerminal(t, jobID)

	if done.Status != jobs.StatusFailed {
		t.Fatalf("want failed, got %q", done.Status)
	}
	if !strings.Contains(done.Error, "does not match this disk as it is NOW") {
		t.Errorf("error = %q, want a stale-confirmation refusal", done.Error)
	}
	if h.agent.claimCount() != 0 {
		t.Error("a disk whose contents changed since the operator looked must not be wiped")
	}
	h.runner.Wait()
}

// The picker mints a token only for a disk that is genuinely eligible to be
// wiped. Its absence is the answer, not an omission: a UI handed no token has
// nothing to put in the field and therefore no wipe control to render.
func TestCandidateWipeToken_MintedOnlyForAWipeableDisk(t *testing.T) {
	cases := []struct {
		name string
		cand proto.StorageCandidate
		want bool
	}{
		{"a disk carrying a backup set", backupSetCandidate(), true},
		{"a disk whose marker is unreadable", unreadableMarkerCandidate(), true},
		{"a blank disk needs no second choice", blankCandidate(), false},
		{"the boot medium is never wipeable", protectedBackupSetCandidate(), false},
		{"the boot medium, blank", protectedCandidate(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CandidateWipeToken(&tc.cand)
			if (got != "") != tc.want {
				t.Fatalf("token = %q, want minted = %v", got, tc.want)
			}
			if tc.want && !strings.HasPrefix(got, "wipe-") {
				t.Errorf("token %q should be recognisable as one in a log line", got)
			}
		})
	}
	if CandidateWipeToken(nil) != "" {
		t.Error("no candidate is not a wipeable candidate")
	}
}

// A token names one disk and one state. Two disks must never share one, or the
// confirmation for the blank spare would authorise wiping the archive.
func TestWipeToken_BindsToTheDiskAndItsContents(t *testing.T) {
	base := backupSetCandidate()
	token := CandidateWipeToken(&base)

	if again := CandidateWipeToken(ptr(backupSetCandidate())); again != token {
		t.Fatalf("the same disk in the same state minted two different tokens: %q vs %q", token, again)
	}

	mutations := map[string]func(*proto.StorageCandidate){
		"a different fingerprint":   func(c *proto.StorageCandidate) { c.Fingerprint = testOtherFing },
		"a different serial":        func(c *proto.StorageCandidate) { c.Serial = "SOMEONE-ELSES" },
		"a different wwn":           func(c *proto.StorageCandidate) { c.WWN = "0x9999" },
		"a different size":          func(c *proto.StorageCandidate) { c.SizeBytes = 1 << 40 },
		"another cluster's archive": func(c *proto.StorageCandidate) { c.BackupSet.ClusterID = "someone-else" },
		"a different partition uuid": func(c *proto.StorageCandidate) {
			c.BackupSet.PartUUID = "part-uuid-other"
		},
		"another generation retained": func(c *proto.StorageCandidate) { c.BackupSet.Generations = 5 },
		"an unreadable marker":        func(c *proto.StorageCandidate) { c.BackupSet = nil },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			c := backupSetCandidate()
			mutate(&c)
			if got := CandidateWipeToken(&c); got == token {
				t.Errorf("%s minted the SAME token — a confirmation for one disk would authorise wiping another", name)
			}
		})
	}
}

// check_existing may re-issue the enumeration when step 2's result is not
// cached — it only reads, so the fallback is safe there in a way it would not
// be at step 4.
func TestCheckExistingStep_FallsBackToAFreshEnumeration(t *testing.T) {
	nc := startNATS(t)
	agent := &fakeAgent{
		nodeID:    testNode,
		enumerate: func(int) proto.StorageEnumerateAck { return ackWith(backupSetCandidate()) },
	}
	agent.start(t, nc)
	sc := stepCtx("j", baseSpec(), nc, nil)
	if _, err := claimCheckExisting()(sc); err == nil {
		t.Fatal("want the backup-set-present refusal")
	} else if !strings.Contains(err.Error(), string(proto.StorageRefusalBackupSetPresent)) {
		t.Errorf("error = %q", err)
	}
	agent.mu.Lock()
	calls := agent.enumerateCalls
	agent.mu.Unlock()
	if calls != 1 {
		t.Errorf("enumerate calls = %d, want 1 (the fallback)", calls)
	}
}
