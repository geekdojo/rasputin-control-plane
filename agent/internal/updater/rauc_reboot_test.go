package updater

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestRebootArgs verifies the post-install reboot picks the tryboot one-shot
// only when the Pi tryboot marker (autoboot.txt) is present, and a plain reboot
// otherwise (n100/GRUB).
func TestRebootArgs(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "autoboot.txt")

	orig := trybootMarker
	t.Cleanup(func() { trybootMarker = orig })
	trybootMarker = marker

	// Marker absent → plain reboot (n100/GRUB).
	if got := rebootArgs(); !slices.Equal(got, []string{"reboot"}) {
		t.Fatalf("no marker: got %v, want [reboot]", got)
	}

	// Marker present → arm the Pi firmware tryboot one-shot.
	if err := os.WriteFile(marker, []byte("[all]\ntryboot_a_b=1\nboot_partition=2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := rebootArgs(); !slices.Equal(got, []string{"reboot", "0 tryboot"}) {
		t.Fatalf("marker present: got %v, want [reboot, \"0 tryboot\"]", got)
	}
}
