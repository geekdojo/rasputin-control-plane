//go:build linux

package updater

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// UnixModuleLoader loads a kernel module from a file with finit_module(2).
//
// It takes a path rather than a module name on purpose: the repair loads the
// legacy FAT modules bundled under /boot/legacy-kmods, which kmodloader would
// never find, because it looks only under /lib/modules/$(uname -r).
type UnixModuleLoader struct{}

// Load loads the module at path. A module that is already loaded is success:
// the goal is the module in the kernel, and it is there.
func (UnixModuleLoader) Load(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("load module: %w", err)
	}
	defer f.Close()
	if err := unix.FinitModule(int(f.Fd()), "", 0); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("load module %s: %w", path, err)
	}
	return nil
}
