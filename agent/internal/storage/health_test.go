package storage

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The write probe (#398): passes on a writable mount, names the failing
// operation on one that is not, leaves nothing behind, and only runs when
// storage.inspect is asked for it.

func TestWriteProbe_PassesOnAWritableMountAndLeavesNothing(t *testing.T) {
	mount := t.TempDir()
	res := WriteProbe(context.Background(), mount)
	if !res.OK {
		t.Fatalf("probe failed on a writable directory: %s", res.Detail)
	}
	if !strings.Contains(res.Detail, proto.StorageHealthProbeDir) {
		t.Errorf("detail %q does not say where it wrote", res.Detail)
	}
	ents, err := os.ReadDir(filepath.Join(mount, proto.StorageHealthProbeDir))
	if err != nil {
		t.Fatalf("probe dir: %v", err)
	}
	if len(ents) != 0 {
		t.Errorf("probe left %d file(s) behind", len(ents))
	}
	// The probe dir is a dot-directory at the mount root and nowhere near
	// generations/, so the archive walker cannot mistake it for a generation.
	if _, err := os.Stat(filepath.Join(mount, GenerationsDir)); !os.IsNotExist(err) {
		t.Errorf("the probe touched %s", GenerationsDir)
	}
}

func TestWriteProbe_SweepsALeftoverFromAnInterruptedProbe(t *testing.T) {
	mount := t.TempDir()
	dir := filepath.Join(mount, proto.StorageHealthProbeDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "probe-deadbeef"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := WriteProbe(context.Background(), mount); !res.OK {
		t.Fatalf("probe failed: %s", res.Detail)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 0 {
		t.Errorf("leftover not swept: %d file(s) remain", len(ents))
	}
}

func TestWriteProbe_NamesTheFailingOperation(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a directory the process cannot write to")
	}
	mount := t.TempDir()
	if err := os.Chmod(mount, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(mount, 0o700) })
	res := WriteProbe(context.Background(), mount)
	if res.OK {
		t.Fatal("probe passed on a read-only directory")
	}
	if !strings.Contains(res.Detail, "create") {
		t.Errorf("detail %q does not name the operation that failed", res.Detail)
	}
}

func TestWriteProbe_EmptyMountIsAFinding(t *testing.T) {
	res := WriteProbe(context.Background(), "")
	if res.OK || res.Detail == "" {
		t.Errorf("probe of nothing = %+v, want a failure with a reason", res)
	}
}

// storage.inspect probes only when asked, so the read-only callers (adopt,
// the restore surfaces) stay read-only.
func TestHandlers_InspectProbesOnlyWhenAsked(t *testing.T) {
	nc, m, _ := registered(t)
	spare := candidateBySerial(t, enumerate(t, m), "SN-SPARE-0002")
	claim, err := m.Claim(context.Background(), claimCmd(spare.DevicePath, spare.Fingerprint, "backup"))
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}

	var plain proto.StorageInspectAck
	requestInto(t, nc, proto.StorageInspectSubject("node-1"), proto.StorageInspectCmd{PartUUID: claim.PartUUID}, &plain)
	if !plain.OK || !plain.Present {
		t.Fatalf("inspect ack = %+v", plain)
	}
	if plain.WriteProbe != nil {
		t.Errorf("an inspect that did not ask for a probe got one: %+v", plain.WriteProbe)
	}

	var probed proto.StorageInspectAck
	requestInto(t, nc, proto.StorageInspectSubject("node-1"), proto.StorageInspectCmd{PartUUID: claim.PartUUID, Probe: true}, &probed)
	if !probed.OK || !probed.Present {
		t.Fatalf("probed inspect ack = %+v", probed)
	}
	if probed.WriteProbe == nil || !probed.WriteProbe.OK {
		t.Fatalf("write probe = %+v, want a passing probe on the mock's mount", probed.WriteProbe)
	}
	if ents, _ := os.ReadDir(filepath.Join(probed.MountPath, proto.StorageHealthProbeDir)); len(ents) != 0 {
		t.Errorf("probe left %d file(s) on the target", len(ents))
	}

	// A target that is not attached gets no probe and says so with Present.
	var absent proto.StorageInspectAck
	requestInto(t, nc, proto.StorageInspectSubject("node-1"), proto.StorageInspectCmd{PartUUID: "no-such-part", Probe: true}, &absent)
	if !absent.OK || absent.Present || absent.WriteProbe != nil {
		t.Errorf("absent target ack = %+v; want OK, not present, no probe", absent)
	}
}
