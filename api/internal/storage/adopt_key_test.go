package storage

import (
	"context"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// design/storage.md §4.6 on the ADOPT path.
//
// Adopting used to do nothing with the key: correctly, it did not mint a fresh
// one — the generations on the disk are already sealed under the key its marker
// names — but it stopped there, which left a replacement controlplane holding a
// target whose data key was sealed and whose custody nobody had been asked for.
//
// The disk now carries both sealed copies itself (proto.StorageBackupSet), the
// operator opens one in the browser, and the SAME blobs come back in the claim.
// What the api owns is the shape of that: the key must arrive, it must be the
// disk's own, and it must be unchanged.

const (
	markerWrappedPass     = "MARKER-WRAPPED-BY-PASSPHRASE"
	markerWrappedRecovery = "MARKER-WRAPPED-BY-RECOVERY-CODE"
	markerKeyAlg          = "AES-256-GCM;pp=argon2id-m65536-t3-p1;rc=hkdf-sha256"
)

// keyedBackupSetCandidate is what a disk claimed by a working §4.6 flow looks
// like from the picker: a marker naming its key AND carrying both sealed copies
// of it. backupSetCandidate is the older shape — a key id and nothing to open.
func keyedBackupSetCandidate() proto.StorageCandidate {
	c := backupSetCandidate()
	c.BackupSet.KeyAlg = markerKeyAlg
	c.BackupSet.WrappedByPassphrase = markerWrappedPass
	c.BackupSet.WrappedByRecoveryCode = markerWrappedRecovery
	return c
}

// markerKey is the ArchiveKey the browser sends back after unlocking: the
// disk's own wrappings, verbatim.
func markerKey() *ArchiveKey {
	return &ArchiveKey{
		KeyID:                 "key-existing",
		Alg:                   markerKeyAlg,
		WrappedByPassphrase:   markerWrappedPass,
		WrappedByRecoveryCode: markerWrappedRecovery,
	}
}

func TestAdopt_CarriesTheDisksOwnSealedKeyIntoTheLedger(t *testing.T) {
	h := newHarness(t, &fakeAgent{
		enumerate: func(int) proto.StorageEnumerateAck { return ackWith(keyedBackupSetCandidate()) },
	})
	spec := baseSpec()
	spec.Adopt = true
	spec.ArchiveKey = markerKey()

	jobID := h.submit(t, spec)
	if done := h.waitTerminal(t, jobID); done.Status != jobs.StatusSucceeded {
		t.Fatalf("adopt failed: %s", done.Error)
	}
	if h.agent.claimCount() != 0 {
		t.Fatal("adopt formatted something")
	}

	row := h.target(t, jobID)
	if !row.Adopted {
		t.Error("row should record that this target was adopted")
	}
	// The disk's marker is the authority on which key its generations are
	// under, and the row must agree with it.
	if row.KeyID != "key-existing" {
		t.Errorf("keyId = %q, want the disk's own", row.KeyID)
	}
	if !row.HasWrappedKeys {
		t.Error("an adopted keyed target must record that both wrappings are on file — that is the whole difference this makes")
	}
	pass, recovery, err := h.store.GetWrappedKeys(context.Background(), jobID)
	if err != nil {
		t.Fatalf("GetWrappedKeys: %v", err)
	}
	if pass != markerWrappedPass || recovery != markerWrappedRecovery {
		t.Fatalf("the stored wrappings are not the disk's: %q / %q", pass, recovery)
	}
	h.runner.Wait()
}

// The refusal this issue exists to produce. Without it the operator gets a
// target that lists as claimed, cannot have a generation written to it, and
// says neither thing.
func TestAdopt_RefusesAKeyedDiskWithNoKeySupplied(t *testing.T) {
	h := newHarness(t, &fakeAgent{
		enumerate: func(int) proto.StorageEnumerateAck { return ackWith(keyedBackupSetCandidate()) },
	})
	spec := baseSpec()
	spec.Adopt = true

	jobID := h.submit(t, spec)
	done := h.waitTerminal(t, jobID)
	if done.Status != jobs.StatusFailed {
		t.Fatalf("want failed, got %q", done.Status)
	}
	for _, want := range []string{"sealed", "recovery code"} {
		if !strings.Contains(done.Error, want) {
			t.Errorf("the refusal should tell the operator what to do; it does not mention %q: %s", want, done.Error)
		}
	}
	if h.agent.claimCount() != 0 || h.agent.inspectCount() != 0 {
		t.Error("the refusal must land before the agent is asked to do anything")
	}
	if h.target(t, jobID).Status != TargetFailed {
		t.Error("the row should be terminal")
	}
	h.runner.Wait()
}

// Adopt preserves; it never re-wraps. A re-wrap that reached the database and
// not the marker would leave the restore path — which, in the case §4.6 exists
// for, has only the disk — holding the OLD wrapping and a passphrase the
// operator was told to forget.
func TestAdopt_RefusesAReWrappedKey(t *testing.T) {
	h := newHarness(t, &fakeAgent{
		enumerate: func(int) proto.StorageEnumerateAck { return ackWith(keyedBackupSetCandidate()) },
	})
	spec := baseSpec()
	spec.Adopt = true
	k := markerKey()
	k.WrappedByPassphrase = "RE-WRAPPED-UNDER-A-NEW-PASSPHRASE"
	spec.ArchiveKey = k

	jobID := h.submit(t, spec)
	done := h.waitTerminal(t, jobID)
	if done.Status != jobs.StatusFailed {
		t.Fatalf("want failed, got %q", done.Status)
	}
	if !strings.Contains(done.Error, "not the one on the disk") {
		t.Errorf("job error = %q", done.Error)
	}
	if h.agent.claimCount() != 0 || h.agent.inspectCount() != 0 {
		t.Error("nothing should have reached the agent")
	}
	h.runner.Wait()
}

// A disk whose marker names a key but carries no sealed copy of it is every
// disk claimed before the marker learned to carry them. There is nothing to
// unlock, so demanding a secret would only strand it — it adopts, and the saga
// says out loud that the key it names cannot be produced from the disk.
func TestAdopt_AKeyedDiskWithNoWrappingsStillAdopts(t *testing.T) {
	h := newHarness(t, &fakeAgent{
		enumerate: func(int) proto.StorageEnumerateAck { return ackWith(backupSetCandidate()) },
	})
	spec := baseSpec()
	spec.Adopt = true

	jobID := h.submit(t, spec)
	if done := h.waitTerminal(t, jobID); done.Status != jobs.StatusSucceeded {
		t.Fatalf("adopt failed: %s", done.Error)
	}
	row := h.target(t, jobID)
	if !row.Adopted || row.KeyID != "key-existing" {
		t.Errorf("row = %+v", row)
	}
	if row.HasWrappedKeys {
		t.Error("nothing supplied a wrapping, so the row must not claim to have one")
	}

	events, err := h.jobStore.ListEvents(context.Background(), jobID)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	warned := false
	for _, ev := range events {
		if strings.Contains(string(ev.Data), "carries no wrapped copies") {
			warned = true
		}
	}
	if !warned {
		t.Error("adopting a disk whose key cannot be produced should say so on the live stream")
	}
	h.runner.Wait()
}

// The format path's other half: the wrapped blobs have to reach the AGENT, or
// they never reach the platter, and the disk this claim creates is one no
// replacement controlplane could ever adopt-and-open.
func TestClaim_SendsTheWrappedBlobsToTheAgentForTheMarker(t *testing.T) {
	h := newHarness(t, &fakeAgent{
		enumerate: func(int) proto.StorageEnumerateAck { return ackWith(blankCandidate()) },
	})
	spec := baseSpec()
	spec.ArchiveKey = &ArchiveKey{
		KeyID: "ak-fresh", Alg: markerKeyAlg,
		WrappedByPassphrase: markerWrappedPass, WrappedByRecoveryCode: markerWrappedRecovery,
	}

	jobID := h.submit(t, spec)
	if done := h.waitTerminal(t, jobID); done.Status != jobs.StatusSucceeded {
		t.Fatalf("claim failed: %s", done.Error)
	}
	cmd, ok := h.agent.lastClaim()
	if !ok {
		t.Fatal("the agent was never asked to claim")
	}
	if cmd.KeyID != "ak-fresh" || cmd.KeyAlg != markerKeyAlg {
		t.Errorf("claim cmd = %+v", cmd)
	}
	if cmd.WrappedByPassphrase != markerWrappedPass || cmd.WrappedByRecoveryCode != markerWrappedRecovery {
		t.Error("the claim command must carry both sealed copies, or the marker cannot hold them")
	}
	h.runner.Wait()
}

// checkAdoptedKeyCustody in isolation, including the cases the saga cannot
// easily stage.
func TestCheckAdoptedKeyCustody(t *testing.T) {
	keyed := keyedBackupSetCandidate().BackupSet
	legacy := backupSetCandidate().BackupSet

	t.Run("a marker with no wrappings gates nothing", func(t *testing.T) {
		if err := checkAdoptedKeyCustody("/dev/sdb", legacy, nil); err != nil {
			t.Errorf("want nil, got %v", err)
		}
		if err := checkAdoptedKeyCustody("/dev/sdb", nil, nil); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})

	t.Run("a keyed marker with a matching key passes", func(t *testing.T) {
		if err := checkAdoptedKeyCustody("/dev/sdb", keyed, markerKey()); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})

	t.Run("a keyed marker with no key is refused", func(t *testing.T) {
		if err := checkAdoptedKeyCustody("/dev/sdb", keyed, nil); err == nil {
			t.Error("want a refusal")
		}
	})

	t.Run("a changed algorithm is refused", func(t *testing.T) {
		k := markerKey()
		k.Alg = "AES-256-GCM;pp=argon2id-m131072-t4-p1;rc=hkdf-sha256"
		if err := checkAdoptedKeyCustody("/dev/sdb", keyed, k); err == nil {
			t.Error("want a refusal — a different alg means the blobs were rebuilt")
		}
	})

	t.Run("a changed recovery wrapping is refused", func(t *testing.T) {
		k := markerKey()
		k.WrappedByRecoveryCode = "different"
		if err := checkAdoptedKeyCustody("/dev/sdb", keyed, k); err == nil {
			t.Error("want a refusal")
		}
	})

	// One wrapping on the disk is not custody: an archive readable by exactly
	// one of the two paths is one forgotten passphrase from unreadable, and
	// §4.6 refuses to create that state anywhere else either.
	t.Run("a marker with only one wrapping does not gate", func(t *testing.T) {
		half := *keyed
		half.WrappedByRecoveryCode = ""
		if markerCarriesWrappings(&half) {
			t.Error("one wrapping must not count as custody material")
		}
		if err := checkAdoptedKeyCustody("/dev/sdb", &half, nil); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})
}
