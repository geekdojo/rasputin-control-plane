package storage

import (
	"context"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

func sampleCandidate() proto.StorageCandidate {
	return proto.StorageCandidate{
		DevicePath: "/dev/nvme1n1",
		Model:      "CT2000P3SSD8",
		Serial:     "SN-SPARE-0002",
		WWN:        "eui.0002",
		SizeBytes:  2000398934016,
		Transport:  proto.StorageTransportNVMe,
		Partitions: []proto.StoragePartition{
			{DevicePath: "/dev/nvme1n1p1", PartUUID: "p-1", FSType: "ext4", Label: "RASPUTIN-BACKUP", SizeBytes: 2000397885440},
		},
	}
}

func TestFingerprint_IsStable(t *testing.T) {
	c := sampleCandidate()
	first := Fingerprint(&c)
	if first == "" {
		t.Fatal("empty fingerprint")
	}
	if second := Fingerprint(&c); second != first {
		t.Errorf("not deterministic: %s != %s", first, second)
	}
}

// The two fields that MUST NOT move the fingerprint. A reboot renames the disk
// and a background automounter mounts it; neither is a different disk, and a
// fingerprint that changed for either would refuse claims the operator cannot
// do anything about.
func TestFingerprint_IgnoresPathAndMountpoint(t *testing.T) {
	base := sampleCandidate()
	want := Fingerprint(&base)

	renamed := sampleCandidate()
	renamed.DevicePath = "/dev/nvme0n1"
	renamed.Partitions[0].DevicePath = "/dev/nvme0n1p1"
	if got := Fingerprint(&renamed); got != want {
		t.Errorf("a rename changed the fingerprint: %s -> %s", short(want), short(got))
	}

	mounted := sampleCandidate()
	mounted.Partitions[0].Mountpoint = "/mnt/somewhere"
	if got := Fingerprint(&mounted); got != want {
		t.Errorf("a mount changed the fingerprint: %s -> %s", short(want), short(got))
	}

	// Nor does the derived Protected flag, which is enforced by its own
	// re-resolution and must not be smuggled into a hash.
	prot := sampleCandidate()
	prot.Protected = true
	prot.ProtectedReason = "holds the mounted root filesystem (/)"
	if got := Fingerprint(&prot); got != want {
		t.Errorf("the protected flag changed the fingerprint: %s -> %s", short(want), short(got))
	}
}

// Everything that means "a different disk", or "the same disk, changed".
func TestFingerprint_ChangesOnIdentityAndPartitionTable(t *testing.T) {
	base := sampleCandidate()
	want := Fingerprint(&base)

	mutations := map[string]func(*proto.StorageCandidate){
		"different serial": func(c *proto.StorageCandidate) { c.Serial = "SN-OTHER" },
		"different wwn":    func(c *proto.StorageCandidate) { c.WWN = "eui.9999" },
		"different model":  func(c *proto.StorageCandidate) { c.Model = "Samsung 990" },
		"different size":   func(c *proto.StorageCandidate) { c.SizeBytes++ },
		"partition added": func(c *proto.StorageCandidate) {
			c.Partitions = append(c.Partitions, proto.StoragePartition{PartUUID: "p-2"})
		},
		"partition removed":      func(c *proto.StorageCandidate) { c.Partitions = nil },
		"partition uuid changed": func(c *proto.StorageCandidate) { c.Partitions[0].PartUUID = "p-9" },
		"filesystem changed":     func(c *proto.StorageCandidate) { c.Partitions[0].FSType = "xfs" },
		"label changed":          func(c *proto.StorageCandidate) { c.Partitions[0].Label = "OTHER" },
		"partition resized":      func(c *proto.StorageCandidate) { c.Partitions[0].SizeBytes-- },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			c := sampleCandidate()
			mutate(&c)
			if got := Fingerprint(&c); got == want {
				t.Errorf("%s did not change the fingerprint — the TOCTOU guard is blind to it", name)
			}
		})
	}
}

// Reordering two otherwise-identical partitions is a different partition table.
func TestFingerprint_IsOrderSensitive(t *testing.T) {
	a := sampleCandidate()
	a.Partitions = []proto.StoragePartition{{PartUUID: "x", SizeBytes: 1}, {PartUUID: "y", SizeBytes: 2}}
	b := sampleCandidate()
	b.Partitions = []proto.StoragePartition{{PartUUID: "y", SizeBytes: 2}, {PartUUID: "x", SizeBytes: 1}}
	if Fingerprint(&a) == Fingerprint(&b) {
		t.Error("partition order does not affect the fingerprint")
	}
}

func TestFingerprint_IdentityWeak(t *testing.T) {
	c := sampleCandidate()
	if identityWeak(&c) {
		t.Error("a disk with a WWN and a serial is not weakly identified")
	}
	c.WWN, c.Serial = "", ""
	if !identityWeak(&c) {
		t.Error("a disk with neither WWN nor serial must be flagged — two identical blank sticks fingerprint the same")
	}
	c.Serial = "  "
	if !identityWeak(&c) {
		t.Error("a whitespace-only serial is not a serial")
	}
	stampFingerprint(&c)
	if !c.IdentityWeak {
		t.Error("stampFingerprint did not set IdentityWeak")
	}
}

func TestFingerprint_NilIsEmpty(t *testing.T) {
	if Fingerprint(nil) != "" {
		t.Error("Fingerprint(nil) should be empty, not a hash of nothing that could match a real disk")
	}
}

// The two backends must produce the same fingerprint for the same facts. They
// do not exchange fingerprints today, but the moment a target claimed on a dev
// box with the mock is inspected by the real backend — or the reverse during a
// bench bring-up — a divergence would read as "the disk changed" and refuse.
func TestFingerprint_BothBackendsAgreeOnTheSameDisk(t *testing.T) {
	sh := &fakeShell{lsblkJSON: twoNVMeLsblk}
	bd := newTestBlockDev(t, sh)
	real := bdCandidate(t, mustEnumerate(t, bd), "/dev/nvme1n1")

	// The same disk, described to the mock.
	machine := &mockState{
		Disks: []mockDisk{
			{Family: "sd", Model: "root", SizeBytes: 1 << 30, Transport: proto.StorageTransportSATA,
				Partitions: []mockPartition{{PartUUID: "r-1", FSType: "ext4", SizeBytes: 1 << 30}}},
			{
				Family: "nvme", Model: real.Model, Serial: real.Serial, WWN: real.WWN,
				SizeBytes: real.SizeBytes, Transport: proto.StorageTransportNVMe,
			},
		},
		Mounts: []mockMount{{MountPoint: "/", PartUUID: "r-1"}},
	}
	m := newTestMock(t, machine)
	ack, err := m.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	mocked := candidateBySerial(t, ack, real.Serial)

	if mocked.Fingerprint != real.Fingerprint {
		t.Errorf("the backends disagree on the same disk:\n  blockdev %s\n  mock     %s",
			real.Fingerprint, mocked.Fingerprint)
	}
	// And their device paths differ, which is exactly why the fingerprint is
	// the thing that gets compared.
	if mocked.DevicePath == real.DevicePath {
		t.Log("note: the paths happened to match; the assertion above is still the meaningful one")
	}
}
