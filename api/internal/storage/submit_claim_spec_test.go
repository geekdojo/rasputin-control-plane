package storage

import (
	"context"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-825-24: SubmitClaim submits the typed ClaimSpec with the archive key
// beside it. The stored spec is the previous release's bytes: the key named by
// archiveKeyId, never carried as archiveKey. A claim ParseClaimSpec refuses
// returns its error, persists no job and stages no key.
func TestSubmitClaim_StoresTheTypedSpecAndRefusesBeforePersisting(t *testing.T) {
	h := newHarness(t, &fakeAgent{
		enumerate: func(int) proto.StorageEnumerateAck { return ackWith(blankCandidate()) },
	})
	ctx := context.Background()
	key := &ArchiveKey{KeyID: "k", PublicKey: markerPublicKey, WrappedByPassphrase: wrapping("a"), WrappedByRecoveryCode: wrapping("b")}
	j, err := SubmitClaim(ctx, h.runner, h.store, baseSpec(), key, "test")
	if err != nil {
		t.Fatalf("SubmitClaim: %v", err)
	}
	got, err := h.jobStore.GetJob(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"nodeId":"` + testNode + `","devicePath":"` + testDevice + `","fingerprint":"` + testFingerpr +
		`","label":"backup disk","archiveKeyId":"k"}`
	if string(got.Spec) != want {
		t.Errorf("stored spec %s, want %s", got.Spec, want)
	}
	if strings.Contains(string(got.Spec), "archiveKey\"") {
		t.Errorf("stored spec carries the key: %s", got.Spec)
	}
	h.waitTerminal(t, j.ID)
	h.runner.Wait()

	before, err := h.jobStore.ListJobsByKind(ctx, ClaimJobKind, 10)
	if err != nil {
		t.Fatal(err)
	}
	refused := baseSpec()
	refused.Fingerprint = "" // ParseClaimSpec: a claim with no fingerprint names no disk
	refusedKey := &ArchiveKey{KeyID: "k2", PublicKey: markerPublicKey, WrappedByPassphrase: wrapping("a"), WrappedByRecoveryCode: wrapping("b")}
	if j, err := SubmitClaim(ctx, h.runner, h.store, refused, refusedKey, "test"); err == nil || !strings.Contains(err.Error(), "fingerprint is required") {
		t.Fatalf("SubmitClaim(no fingerprint) = (%v, %v), want the ParseClaimSpec refusal", j, err)
	}
	after, err := h.jobStore.ListJobsByKind(ctx, ClaimJobKind, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Errorf("a refused claim persisted a job: %d before, %d after", len(before), len(after))
	}
	if left, err := h.store.StagedClaimKeyJobs(ctx); err != nil || len(left) != 0 {
		t.Errorf("staged keys left = %v (err %v), want none", left, err)
	}
}
