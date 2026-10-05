package storage

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// TC-825-35: a claim posted with a valid archive key, converted once by
// NewArchiveKey as the handler converts it, runs on the real Runner. The
// wrappings reach the claim command, the staging row and the target row; the
// stored spec carries only archiveKeyId; ClaimSpec holds no secret.Value; and
// an ArchiveKey marshals with no wrapping field.
func TestClaim_WrappingsAreValuesFromRequestToRows(t *testing.T) {
	const pass, recovery = "WRAPPED-BY-PASSPHRASE-825", "WRAPPED-BY-RECOVERY-825"
	var (
		mu         sync.Mutex
		stagedPass string
		stagedRec  string
	)
	var h *harness
	h = newHarness(t, &fakeAgent{
		enumerate: func(int) proto.StorageEnumerateAck { return ackWith(blankCandidate()) },
		// The staging row is read while the claim is in flight: it is
		// discarded once the job ends.
		claim: func(cmd proto.StorageClaimCmd) proto.StorageClaimAck {
			ctx := context.Background()
			ids, _ := h.store.StagedClaimKeyJobs(ctx)
			if len(ids) == 1 {
				if k, err := h.store.StagedClaimKey(ctx, ids[0]); err == nil && k != nil {
					mu.Lock()
					stagedPass, stagedRec = string(k.WrappedByPassphrase.Reveal()), string(k.WrappedByRecoveryCode.Reveal())
					mu.Unlock()
					k.Destroy()
				}
			}
			return defaultClaimAck(cmd)
		},
	})
	key, err := NewArchiveKey(&ArchiveKeyInput{
		KeyID: "ak-825", Alg: markerKeyAlg, PublicKey: markerPublicKey,
		WrappedByPassphrase: pass, WrappedByRecoveryCode: recovery,
	})
	if err != nil {
		t.Fatalf("NewArchiveKey: %v", err)
	}
	defer key.Destroy()

	jobID := h.submitKeyed(t, baseSpec(), key)
	if done := h.waitTerminal(t, jobID); done.Status != jobs.StatusSucceeded {
		t.Fatalf("claim failed: %s", done.Error)
	}
	cmd, ok := h.agent.lastClaim()
	if !ok || cmd.WrappedByPassphrase != pass || cmd.WrappedByRecoveryCode != recovery {
		t.Errorf("claim command wrappings = %q / %q (sent=%v), want the posted ones", cmd.WrappedByPassphrase, cmd.WrappedByRecoveryCode, ok)
	}
	mu.Lock()
	if stagedPass != pass || stagedRec != recovery {
		t.Errorf("staging row = %q / %q, want the posted wrappings", stagedPass, stagedRec)
	}
	mu.Unlock()
	gotPass, gotRec, err := h.store.GetWrappedKeys(context.Background(), jobID)
	if err != nil || gotPass != pass || gotRec != recovery {
		t.Errorf("target row = %q / %q (err %v), want the posted wrappings", gotPass, gotRec, err)
	}
	j, err := h.jobStore.GetJob(context.Background(), jobID)
	if err != nil || j == nil {
		t.Fatalf("GetJob: %v", err)
	}
	var spec map[string]any
	if err := json.Unmarshal(j.Spec, &spec); err != nil {
		t.Fatalf("decode spec: %v", err)
	}
	if spec["archiveKeyId"] != "ak-825" || strings.Contains(string(j.Spec), pass) || strings.Contains(string(j.Spec), recovery) {
		t.Errorf("stored spec = %s, want archiveKeyId and neither wrapping", j.Spec)
	}
	if secret.Contains(ClaimSpec{}) {
		t.Error("ClaimSpec holds a secret.Value: the key must travel beside the spec, not in it")
	}
	b, err := json.Marshal(ArchiveKey{KeyID: "k", PublicKey: markerPublicKey, WrappedByPassphrase: wrapping(pass), WrappedByRecoveryCode: wrapping(recovery)})
	if err != nil {
		t.Fatalf("marshal ArchiveKey: %v", err)
	}
	if strings.Contains(string(b), "wrapped") || strings.Contains(string(b), pass) {
		t.Errorf("ArchiveKey marshals a wrapping: %s", b)
	}
}

// TC-825-35: NewArchiveKey refuses a key missing either wrapping, a
// whitespace-only wrapping included, and treats no key as no key.
func TestNewArchiveKey_RefusesAMissingWrapping(t *testing.T) {
	whole := func() *ArchiveKeyInput {
		return &ArchiveKeyInput{KeyID: "k", PublicKey: markerPublicKey, WrappedByPassphrase: "a", WrappedByRecoveryCode: "b"}
	}
	for name, mutate := range map[string]func(*ArchiveKeyInput){
		"no passphrase wrapping":     func(in *ArchiveKeyInput) { in.WrappedByPassphrase = "" },
		"no recovery wrapping":       func(in *ArchiveKeyInput) { in.WrappedByRecoveryCode = "" },
		"blank recovery wrapping":    func(in *ArchiveKeyInput) { in.WrappedByRecoveryCode = "   " },
		"a public key that is wrong": func(in *ArchiveKeyInput) { in.PublicKey = "AAEC" },
	} {
		in := whole()
		mutate(in)
		if k, err := NewArchiveKey(in); err == nil || k != nil {
			t.Errorf("%s: key=%v err=%v, want a refusal and no key", name, k, err)
		}
	}
	for name, in := range map[string]*ArchiveKeyInput{"nil": nil, "empty": {}} {
		if k, err := NewArchiveKey(in); err != nil || k != nil {
			t.Errorf("%s: key=%v err=%v, want no key and no error", name, k, err)
		}
	}
	k, err := NewArchiveKey(whole())
	if err != nil {
		t.Fatalf("whole key: %v", err)
	}
	if string(k.WrappedByPassphrase.Reveal()) != "a" || string(k.WrappedByRecoveryCode.Reveal()) != "b" {
		t.Error("NewArchiveKey changed the wrappings")
	}
	k.Destroy()
	if k.WrappedByPassphrase.Len() != 0 || k.WrappedByRecoveryCode.Len() != 0 {
		t.Error("ArchiveKey.Destroy left a wrapping")
	}
	var none *ArchiveKey
	none.Destroy() // nil-safe
}

// TC-825-36: adopt compares the claim's revealed wrappings with the disk
// marker's. A match adopts; a mismatch in either wrapping is refused, and the
// target row records no wrapping.
func TestAdopt_ChecksCustodyOnRevealedWrappings(t *testing.T) {
	cases := []struct {
		name        string
		pass, rec   string
		wantAdopted bool
	}{
		{name: "match", pass: markerWrappedPass, rec: markerWrappedRecovery, wantAdopted: true},
		{name: "passphrase wrapping differs", pass: "OTHER-PASS", rec: markerWrappedRecovery},
		{name: "recovery wrapping differs", pass: markerWrappedPass, rec: "OTHER-RECOVERY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, &fakeAgent{
				enumerate: func(int) proto.StorageEnumerateAck { return ackWith(keyedBackupSetCandidate()) },
			})
			spec := baseSpec()
			spec.Adopt = true
			key := markerKey()
			key.WrappedByPassphrase = wrapping(tc.pass)
			key.WrappedByRecoveryCode = wrapping(tc.rec)
			jobID := h.submitKeyed(t, spec, key)
			done := h.waitTerminal(t, jobID)
			gotPass, gotRec, err := h.store.GetWrappedKeys(context.Background(), jobID)
			if err != nil {
				t.Fatalf("GetWrappedKeys: %v", err)
			}
			if tc.wantAdopted {
				if done.Status != jobs.StatusSucceeded || !h.target(t, jobID).Adopted {
					t.Fatalf("a matching key did not adopt: %s", done.Error)
				}
				if gotPass != markerWrappedPass || gotRec != markerWrappedRecovery {
					t.Errorf("adopted row = %q / %q, want the disk's wrappings", gotPass, gotRec)
				}
				return
			}
			if done.Status != jobs.StatusFailed || !strings.Contains(done.Error, "not the one on the disk") {
				t.Fatalf("status %q error %q, want the custody refusal", done.Status, done.Error)
			}
			if gotPass != "" || gotRec != "" {
				t.Errorf("a refused adopt recorded wrappings %q / %q", gotPass, gotRec)
			}
		})
	}
}
