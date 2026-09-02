package storage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// claimCmd is the ordinary, key-less claim command most tests want — the three
// strings Claim used to take positionally. Tests that care about the §4.6
// marker fields build the command themselves.
func claimCmd(devicePath, fingerprint, label string) proto.StorageClaimCmd {
	return proto.StorageClaimCmd{DevicePath: devicePath, Fingerprint: fingerprint, Label: label}
}

// The §4.6 material a keyed claim carries, as amended 2026-09-02: an X25519
// PUBLIC key in clear plus the two wrapped copies of the private key. The blob
// strings stand in for base64url ciphertext — nothing here parses them, which
// is the point. testPublicKey is a real X25519 public key, because the api
// validates it as one before any of this is reached.
const (
	testKeyAlg    = "X25519;wrap=AES-256-GCM;pp=argon2id-m65536-t3-p1;rc=hkdf-sha256"
	testPublicKey = "b_37bCmEzeukYs4me3p4ghNn39YLqNC3LAmTdAA_zEo"
	testWrappedPP = "eyJ2IjoyLCJwcCI6ImJsb2IifQ"
	testWrappedRC = "eyJ2IjoyLCJyYyI6ImJsb2IifQ"
)

// keyedClaimCmd is a claim carrying design/storage.md §4.6's key material.
func keyedClaimCmd(devicePath, fingerprint, label string) proto.StorageClaimCmd {
	return proto.StorageClaimCmd{
		DevicePath:            devicePath,
		Fingerprint:           fingerprint,
		Label:                 label,
		ClusterID:             "bitscope",
		KeyID:                 "ak-DEADBEEF",
		KeyAlg:                testKeyAlg,
		PublicKey:             testPublicKey,
		WrappedByPassphrase:   testWrappedPP,
		WrappedByRecoveryCode: testWrappedRC,
	}
}

// assertMarkerCarriesCustody is the assertion both backends have to satisfy.
//
// It is the regression test for a bug that shipped: the backends wrote a marker
// holding only MarkerVersion / PartUUID / Label / CreatedAt, and the NATS
// handler then stamped ClusterID and KeyID onto the ACK. The reply looked
// right; the platter carried neither. Every §4.8 claim of the disk-is-the-
// record contract, and every §4.6 hope of adopting a disk on a replacement
// controlplane, rests on this file being complete.
func assertMarkerCarriesCustody(t *testing.T, set *proto.StorageBackupSet, partUUID string) {
	t.Helper()
	if set == nil {
		t.Fatal("no marker was written")
	}
	if set.MarkerVersion != proto.StorageMarkerVersion {
		t.Errorf("marker version = %d, want %d", set.MarkerVersion, proto.StorageMarkerVersion)
	}
	if set.PartUUID != partUUID {
		t.Errorf("marker partUuid = %q, want %q", set.PartUUID, partUUID)
	}
	if set.ClusterID != "bitscope" {
		t.Errorf("marker clusterId = %q — the disk cannot say which cluster wrote it", set.ClusterID)
	}
	if set.KeyID != "ak-DEADBEEF" {
		t.Errorf("marker keyId = %q — a restore cannot tell which key it needs", set.KeyID)
	}
	if set.KeyAlg != testKeyAlg {
		t.Errorf("marker keyAlg = %q", set.KeyAlg)
	}
	// The 2026-09-02 amendment: without the public key on the platter, a
	// replacement controlplane that adopts this disk has nothing to encrypt the
	// next generation TO — and unlocking has nothing to check a recovered
	// private key against. It is not a secret; it is the load-bearing one.
	if set.PublicKey != testPublicKey {
		t.Errorf("marker publicKey = %q, want %q — a controlplane that adopts this disk cannot write to it", set.PublicKey, testPublicKey)
	}
	if set.WrappedByPassphrase != testWrappedPP || set.WrappedByRecoveryCode != testWrappedRC {
		t.Errorf("marker is missing a §4.6 wrapping: %+v — a controlplane that adopts this disk has nothing to ask the operator to unlock", set)
	}
}

func TestBlockDev_ClaimWritesTheCustodyMaterialOntoThePlatter(t *testing.T) {
	sh := &fakeShell{lsblkJSON: twoNVMeLsblk, afterJSON: claimedLsblk, partUUID: "9d0f4a2b-01"}
	b := newTestBlockDev(t, sh)
	spare := bdCandidate(t, mustEnumerate(t, b), "/dev/nvme1n1")

	ack, err := b.Claim(context.Background(), keyedClaimCmd("/dev/nvme1n1", spare.Fingerprint, "weekly archive"))
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	// Read it back off the "disk", not out of the ack. The ack was never the
	// thing that was wrong.
	set, err := readMarker(ack.MountPath)
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	assertMarkerCarriesCustody(t, set, ack.PartUUID)
	assertMarkerCarriesCustody(t, ack.BackupSet, ack.PartUUID)
}

func TestMock_ClaimWritesTheCustodyMaterialOntoThePlatter(t *testing.T) {
	m := newTestMock(t, defaultMockMachine())
	spare := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002")

	ack, err := m.Claim(context.Background(), keyedClaimCmd(spare.DevicePath, spare.Fingerprint, "weekly archive"))
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	assertMarkerCarriesCustody(t, ack.BackupSet, ack.PartUUID)

	// And it survives a re-enumeration, which is how the adopt flow meets it:
	// the picker lists the disk, and the browser unwraps what the marker holds.
	again := enumerate(t, m)
	var found *proto.StorageBackupSet
	for i := range again.Candidates {
		if again.Candidates[i].DevicePath == spare.DevicePath {
			found = again.Candidates[i].BackupSet
		}
	}
	assertMarkerCarriesCustody(t, found, ack.PartUUID)

	insp, err := m.Inspect(context.Background(), ack.PartUUID)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	assertMarkerCarriesCustody(t, insp.BackupSet, ack.PartUUID)
}

// The marker holds ciphertext, identifiers and a PUBLIC key. It must never hold
// the private key, the passphrase or the recovery code — the disk is the one
// place §4.6 says the wrapped copies belong AND the one place a plaintext
// private key would be worst.
func TestMarker_HoldsNothingInTheClear(t *testing.T) {
	m := newTestMock(t, defaultMockMachine())
	spare := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002")
	ack, err := m.Claim(context.Background(), keyedClaimCmd(spare.DevicePath, spare.Fingerprint, "weekly archive"))
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	b, err := json.Marshal(ack.BackupSet)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{"dataKey", "plaintext", "\"secret\""} {
		if containsFold(string(b), forbidden) {
			t.Errorf("the marker contains %q: %s", forbidden, b)
		}
	}
	// The real invariant, and the one a future field has to get past: an exact
	// whitelist of what may appear on the disk. "wrappedByPassphrase" is a
	// legitimate name for ciphertext; "passphrase" would not be, and it is the
	// whitelist rather than a substring scan that can tell the two apart.
	raw := map[string]any{}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	allowed := map[string]bool{
		"markerVersion": true, "clusterId": true, "partUuid": true, "keyId": true,
		// publicKey is in clear and belongs here — §4.6 as amended 2026-09-02.
		// It is the one field on this whitelist that is key material AND not a
		// secret, which is exactly why it needed a decision rather than a
		// default.
		"keyAlg": true, "publicKey": true, "wrappedByPassphrase": true, "wrappedByRecoveryCode": true,
		"label": true, "createdAt": true, "generations": true,
	}
	for k := range raw {
		if !allowed[k] {
			t.Errorf("StorageBackupSet grew field %q — anything key-shaped needs a decision, not a default", k)
		}
	}
}

// A marker written before the custody fields existed still parses, and adopting
// such a disk is a decision the api makes rather than a crash here.
func TestMarker_OldMarkersWithoutCustodyStillParse(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"markerVersion":1,"partUuid":"aaaa-1","label":"old","createdAt":"2026-08-30T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(dir, proto.StorageMarkerFile), []byte(legacy), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	set, err := readMarker(dir)
	if err != nil {
		t.Fatalf("readMarker: %v", err)
	}
	if set.PartUUID != "aaaa-1" {
		t.Errorf("partUuid = %q", set.PartUUID)
	}
	if set.WrappedByPassphrase != "" || set.WrappedByRecoveryCode != "" || set.KeyID != "" {
		t.Errorf("an old marker invented custody material: %+v", set)
	}
	// The 2026-09-02 amendment added publicKey to this struct. A marker written
	// before it must read back with the field EMPTY, because that absence is
	// what the api's adopt gate uses to recognise a symmetric-era disk — a
	// default here would silently make such a disk look adoptable.
	if set.PublicKey != "" {
		t.Errorf("an old marker invented a public key: %q", set.PublicKey)
	}
}
