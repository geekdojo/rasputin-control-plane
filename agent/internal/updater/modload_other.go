//go:build !linux

package updater

import "fmt"

// UnixModuleLoader loads kernel modules on Linux. On any other OS it refuses,
// so a development build never reports a module as loaded.
type UnixModuleLoader struct{}

// Load refuses: this OS has no Linux kernel modules.
func (UnixModuleLoader) Load(path string) error {
	return fmt.Errorf("load module %s: kernel modules can only be loaded on Linux", path)
}
