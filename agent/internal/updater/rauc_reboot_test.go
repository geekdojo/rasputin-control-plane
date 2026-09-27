package updater

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/system"
)

// TestRebootMode verifies the post-install reboot asks for the tryboot one-shot
// only when the Pi tryboot marker (autoboot.txt) is present, and a plain reboot
// otherwise (n100/GRUB). What each mode runs is system.Rebooter's business.
func TestRebootMode(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "autoboot.txt")

	orig := trybootMarker
	t.Cleanup(func() { trybootMarker = orig })
	trybootMarker = marker

	// Marker absent → plain reboot (n100/GRUB).
	if got := rebootMode(); got != system.RebootPlain {
		t.Fatalf("no marker: got %q, want plain", got)
	}

	// Marker present → arm the Pi firmware tryboot one-shot.
	if err := os.WriteFile(marker, []byte("[all]\ntryboot_a_b=1\nboot_partition=2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := rebootMode(); got != system.RebootTryboot {
		t.Fatalf("marker present: got %q, want tryboot", got)
	}
}
