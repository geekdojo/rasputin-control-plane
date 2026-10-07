package main

import (
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
)

// legacyCollectorLeafDir is where an earlier release kept the collector
// client leaves under dataDir.
func legacyCollectorLeafDir(dataDir string) string {
	return filepath.Join(dataDir, "tls", "collectors")
}

// removeLegacyCollectorLeaves deletes dir — dataDir/tls/collectors, where an
// earlier release kept a controlplane-CA client leaf and its private key for each
// node's collector. Nothing mints, renews, places or admits one any more: a
// collector presents its node's own registered key. The keys are the
// controlplane's own, so they are removed rather than left on disk, and the
// identity archive carries no tls/ directory (storage/assemble.go), so a
// restore cannot bring them back.
//
// It runs once at start. An absent directory is the steady state and writes
// nothing. A directory that cannot be read or removed is a WARN, and start-up
// continues: nothing verifies a Mesh client chain, so a leaf left behind
// admits no one.
//
// Lifetime: delete this function and its call once every known cluster has
// started an api of a release that carries it. That is a checkable fact, the
// same shape as the transfer capability's floor, recorded in the auth
// methodology §7.
func removeLegacyCollectorLeaves(logger *slog.Logger, dir string) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		logger.Warn("legacy collector leaves: cannot read the directory; leaving it", "dir", dir, "err", err.Error())
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		logger.Warn("legacy collector leaves: cannot remove the directory; leaving it", "dir", dir, "err", err.Error())
		return
	}
	logger.Info("legacy collector leaves: removed the controlplane-CA client leaves an earlier release minted", "dir", dir, "removed", len(entries))
}
