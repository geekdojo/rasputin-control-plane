//go:build !unix

package storeaudit

import "io/fs"

// inodeOf has no implementation off unix, and says so. Without an inode the
// rotator cannot tell the store's new file from the copy, so every rotation
// fails and rolls back rather than guessing. Rasputin's api runs on Linux;
// this file keeps the build honest, as storage.FreeBytes's does.
func inodeOf(fs.FileInfo) (uint64, bool) { return 0, false }
