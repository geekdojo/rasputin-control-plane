package storage

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// design/storage.md §4.6 on the ADOPT path.
//
// Adopting used to do nothing with the key: correctly, it did not mint a fresh
// one — the generations on the disk are already sealed to the key its marker
// names — but it stopped there, which left a replacement controlplane holding a
// target whose private key was sealed and whose custody nobody had been asked
// for.
//
// The disk now carries its public key and both sealed copies of its private key
// (proto.StorageBackupSet), the operator opens one in the browser, and the SAME
// material comes back in the claim. What the api owns is the shape of that: the
// key must arrive, it must be the disk's own, and it must be unchanged.
//
// The 2026-09-02 amendment changed the REASON for the first of those without
// changing the rule. Adopting no longer needs the private key to write a
// generation — the public key is enough, and it is on the disk in clear — so
// this gate is no longer about capability. It is about not accumulating four
// generations sealed to a key nobody has proved they can open. See
// checkAdoptedKeyCustody.

const (
	markerWrappedPass     = "MARKER-WRAPPED-BY-PASSPHRASE"
	markerWrappedRecovery = "MARKER-WRAPPED-BY-RECOVERY-CODE"
	markerKeyAlg          = "X25519;wrap=AES-256-GCM;pp=argon2id-m65536-t3-p1;rc=hkdf-sha256"
	// A real X25519 public key, base64url of 32 raw bytes — validate() checks
	// it against crypto/ecdh, so a placeholder string would not do.
	markerPublicKey = "b_37bCmEzeukYs4me3p4ghNn39YLqNC3LAmTdAA_zEo"
	// A DIFFERENT real public key, for the case where a claim's key and the
	// disk's disagree about what the generations are sealed to.
	otherPublicKey = "oPy5r5u-Jdv0dEnWseQjfGpakCnzdbP5Mz6_clxmOi8"
	// The symmetric-era alg string, on the two bench disks and nowhere else.
	legacySymmetricKeyAlg = "AES-256-GCM;pp=argon2id-m65536-t3-p1;rc=hkdf-sha256"
)

// keyedBackupSetCandidate is what a disk claimed by a working §4.6 flow looks
// like from the picker: a marker naming its key, carrying its public key in
// clear AND both sealed copies of the private key. backupSetCandidate is the
// older shape — a key id and nothing to open.
func keyedBackupSetCandidate() proto.StorageCandidate {
	c := backupSetCandidate()
	c.BackupSet.KeyAlg = markerKeyAlg
	c.BackupSet.PublicKey = markerPublicKey
	c.BackupSet.WrappedByPassphrase = markerWrappedPass
	c.BackupSet.WrappedByRecoveryCode = markerWrappedRecovery
	return c
}

// symmetricEraCandidate is the shape the two bench disks have: both wrappings,
// no public key, because there was no public key. Unadoptable by this build.
func symmetricEraCandidate() proto.StorageCandidate {
	c := keyedBackupSetCandidate()
	c.BackupSet.KeyAlg = legacySymmetricKeyAlg
	c.BackupSet.PublicKey = ""
	return c
}

// markerKey is the ArchiveKey the browser sends back after unlocking: the
// disk's own public key and wrappings, verbatim.
func markerKey() *ArchiveKey {
	return &ArchiveKey{
		KeyID:                 "key-existing",
		Alg:                   markerKeyAlg,
		PublicKey:             markerPublicKey,
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
	// The public key is what #290's backup.run will seal to, so an adopted row
	// that does not carry it is a target that cannot be backed up at all.
	if row.PublicKey != markerPublicKey {
		t.Errorf("publicKey = %q, want the disk's own %q", row.PublicKey, markerPublicKey)
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
		KeyID: "ak-fresh", Alg: markerKeyAlg, PublicKey: markerPublicKey,
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
	// Without this the marker has no public key, and a replacement controlplane
	// adopting the disk later would find nothing to encrypt a new generation to
	// — the exact hole the 2026-09-02 amendment closes.
	if cmd.PublicKey != markerPublicKey {
		t.Errorf("the claim command must carry the public key; got %q", cmd.PublicKey)
	}
	h.runner.Wait()
}

// §4.6 as amended 2026-09-02, on the two disks that already exist.
//
// A symmetric-era marker carries both wrappings and no public key. Its blobs
// seal one shared 32-byte data key, and this build's seal a 32-byte X25519
// private key — same length, same cipher, same KDFs, nothing in the bytes to
// tell them apart. So the operator's real passphrase WOULD open it, yielding
// something that is not a private key for anything, and with no public key on
// the disk there is nothing to catch that. The refusal has to be explicit, and
// it has to say what to do instead.
func TestAdopt_RefusesASymmetricEraDisk(t *testing.T) {
	h := newHarness(t, &fakeAgent{
		enumerate: func(int) proto.StorageEnumerateAck { return ackWith(symmetricEraCandidate()) },
	})
	spec := baseSpec()
	spec.Adopt = true

	jobID := h.submit(t, spec)
	done := h.waitTerminal(t, jobID)
	if done.Status != jobs.StatusFailed {
		t.Fatalf("want failed, got %q", done.Status)
	}
	for _, want := range []string{"symmetric", "X25519", "claim it fresh"} {
		if !strings.Contains(done.Error, want) {
			t.Errorf("the refusal must explain itself; it does not mention %q: %s", want, done.Error)
		}
	}
	if h.agent.claimCount() != 0 || h.agent.inspectCount() != 0 {
		t.Error("the refusal must land before the agent is asked to do anything")
	}
	h.runner.Wait()
}

// And it is refused even when the operator's browser somehow supplies a
// matching key — because the browser refuses first, and a request that got past
// it did not come from the drawer. The gate is ordered ahead of the custody
// check so this is the message that comes back, not "the key is not the disk's".
func TestAdopt_RefusesASymmetricEraDiskEvenWithAKeySupplied(t *testing.T) {
	h := newHarness(t, &fakeAgent{
		enumerate: func(int) proto.StorageEnumerateAck { return ackWith(symmetricEraCandidate()) },
	})
	spec := baseSpec()
	spec.Adopt = true
	k := markerKey()
	k.Alg = legacySymmetricKeyAlg
	spec.ArchiveKey = k

	jobID := h.submit(t, spec)
	done := h.waitTerminal(t, jobID)
	if done.Status != jobs.StatusFailed {
		t.Fatalf("want failed, got %q", done.Status)
	}
	if !strings.Contains(done.Error, "symmetric") {
		t.Errorf("job error = %q, want the symmetric-era refusal", done.Error)
	}
	h.runner.Wait()
}

// A symmetric-era disk is not a dead end: §4.8's second, separate choice still
// reclaims it, and that is the exit the refusal above names.
func TestWipe_ReclaimsASymmetricEraDisk(t *testing.T) {
	c := symmetricEraCandidate()
	h := newHarness(t, &fakeAgent{
		enumerate: func(int) proto.StorageEnumerateAck { return ackWith(c) },
	})
	spec := baseSpec()
	spec.Wipe = &WipeConfirmation{Token: CandidateWipeToken(&c)}
	spec.ArchiveKey = markerKey()
	spec.ArchiveKey.KeyID = "ak-fresh"

	jobID := h.submit(t, spec)
	if done := h.waitTerminal(t, jobID); done.Status != jobs.StatusSucceeded {
		t.Fatalf("wipe failed: %s", done.Error)
	}
	row := h.target(t, jobID)
	if !row.Wiped || row.PublicKey != markerPublicKey {
		t.Errorf("row = %+v, want a wiped row carrying the freshly minted public key", row)
	}
	h.runner.Wait()
}

func TestCheckLegacySymmetricKey(t *testing.T) {
	t.Run("a marker with a public key is not legacy", func(t *testing.T) {
		if err := checkLegacySymmetricKey("/dev/sdb", keyedBackupSetCandidate().BackupSet); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})
	t.Run("a marker with no wrappings is not legacy", func(t *testing.T) {
		// Every disk claimed before the marker carried custody material at all.
		// There is nothing on it that could be a symmetric wrapping, so this
		// gate says nothing and the softer warning path handles it.
		if err := checkLegacySymmetricKey("/dev/sdb", backupSetCandidate().BackupSet); err != nil {
			t.Errorf("want nil, got %v", err)
		}
		if err := checkLegacySymmetricKey("/dev/sdb", nil); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})
	t.Run("wrappings with no public key are legacy", func(t *testing.T) {
		if err := checkLegacySymmetricKey("/dev/sdb", symmetricEraCandidate().BackupSet); err == nil {
			t.Error("want a refusal")
		}
	})
}

// ArchiveKey.validate on the one field the api can actually check. The
// wrappings are opaque by design and the private key is not here at all, so the
// public key is the whole of this api's ability to notice §4.6 material that
// would produce unreadable archives.
func TestArchiveKey_ValidatePublicKey(t *testing.T) {
	whole := func() *ArchiveKey { return markerKey() }

	t.Run("a real X25519 public key passes", func(t *testing.T) {
		if err := whole().validate(); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})

	t.Run("a missing public key is refused", func(t *testing.T) {
		k := whole()
		k.PublicKey = ""
		err := k.validate()
		if err == nil || !strings.Contains(err.Error(), "publicKey") {
			t.Errorf("err = %v, want it to name publicKey", err)
		}
	})

	t.Run("a public key that is not base64url is refused", func(t *testing.T) {
		k := whole()
		k.PublicKey = "not base64!!"
		if err := k.validate(); err == nil {
			t.Error("want a refusal")
		}
	})

	t.Run("a public key of the wrong length is refused", func(t *testing.T) {
		k := whole()
		k.PublicKey = base64.RawURLEncoding.EncodeToString(make([]byte, 16))
		err := k.validate()
		if err == nil || !strings.Contains(err.Error(), "32") {
			t.Errorf("err = %v, want it to name the expected length", err)
		}
	})

	// The one public key with a catastrophic property: every exchange against
	// it yields zero, so every archive sealed to it is readable by anyone. It
	// is also exactly what a zeroed or truncated marker field decodes to.
	t.Run("an all-zero public key is refused", func(t *testing.T) {
		k := whole()
		k.PublicKey = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		err := k.validate()
		if err == nil || !strings.Contains(err.Error(), "all zeroes") {
			t.Errorf("err = %v, want the all-zeroes refusal", err)
		}
	})

	t.Run("no key at all is still fine — encryption is optional at claim time", func(t *testing.T) {
		var k *ArchiveKey
		if err := k.validate(); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})
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

	// The claim and the disk must agree about what the generations are sealed
	// TO, not only about the sealed blobs. A row recording one public key while
	// the disk's marker names another is a target whose next generation goes
	// somewhere its own restore path will not look.
	t.Run("a different public key is refused", func(t *testing.T) {
		k := markerKey()
		k.PublicKey = otherPublicKey
		if err := checkAdoptedKeyCustody("/dev/sdb", keyed, k); err == nil {
			t.Error("want a refusal — the claim's public key is not the disk's")
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
