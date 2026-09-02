//go:build !unix

package storage

import "errors"

// FreeBytes has no implementation off unix, and says so rather than returning a
// large number.
//
// Fail-closed on purpose. The one caller is §4.7's source-side guard, whose
// entire job is to refuse a run that would fill the partition it is protecting;
// a stub that answered "plenty free" would turn that guard off silently on any
// platform it had not been ported to. Rasputin's api runs on Linux, so this
// path exists only to keep the build honest.
func FreeBytes(string) (uint64, error) {
	return 0, errors.New("storage: free-space checks are not implemented on this platform, so a backup cannot be staged safely here")
}
