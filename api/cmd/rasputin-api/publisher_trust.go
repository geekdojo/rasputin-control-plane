package main

import (
	"bytes"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/geekdojo/rasputin-control-plane/api/internal/catalogsync"
	"github.com/geekdojo/rasputin-control-plane/api/internal/updater"
	"github.com/geekdojo/rasputin-control-plane/artifactsig"
)

// One publisher trust root (geekdojo/geekdojo-brain#529). main resolves it once
// through artifactsig.TrustRootPath, the same resolver the node's agent uses,
// and hands that one file to both verifiers built here: the updater's (OS
// bundles, the signed release manifest, the baked firewall descriptor) and the
// catalog's. <trustDir>/root-ca.pem is never used for trust.

// wirePublisherTrust builds the OS-update verifier and the catalog verifier on
// the one publisherRoot. A root that does not load leaves the updater verifier
// unavailable (wireBundleVerifier logs why), and the catalog verifier refuses
// every fetch because it reads the same file, so the floor or the last good
// catalog stays in effect. Neither exits the process (#89).
func wirePublisherTrust(logger *slog.Logger, publisherRoot string) (*updater.Verifier, catalogsync.Verifier) {
	return wireBundleVerifier(logger, publisherRoot), catalogsync.NewVerifier(publisherRoot)
}

// ignoredOnReleaseReason is the reason every "setting ignored" entry carries.
const ignoredOnReleaseReason = "publisher trust and the app catalog are fixed on Rasputin OS"

// warnIgnoredReleaseSettings writes one WARN per development setting a release
// build ignores and finds set: RASPUTIN_TRUST_ROOT and the two catalog-source
// variables. The value is never logged; node.env is operator-controlled. A
// non-release build honours them and writes nothing.
//
// Only the api warns. The firewall's init script sets RASPUTIN_TRUST_ROOT to
// the baked path on every start, so the same warning from the agent would be a
// standing false alarm on every firewall.
func warnIgnoredReleaseSettings(logger *slog.Logger, release bool, getenv func(string) string) {
	if !release {
		return
	}
	for _, name := range setVars(getenv, artifactsig.TrustRootEnv, catalogRepoEnv, catalogAPIBaseEnv) {
		logger.Warn("setting ignored on a release build", "var", name, "reason", ignoredOnReleaseReason)
	}
}

// legacyTrustRootName is the publisher root's file name in the trust dir,
// where the api read it before #529.
const legacyTrustRootName = "root-ca.pem"

// warnLegacyTrustRoot writes one WARN when <trustDir>/root-ca.pem is a regular
// file whose bytes differ from the publisher root. Before #529 such a file
// re-pointed the api's publisher trust; now it is never used for trust, and
// this entry is the only sign an operator who placed it gets.
//
// It uses Lstat, so the OS image's tmpfiles symlink to the baked root is never
// opened, and a symlink, a directory or an absent path writes nothing. The
// file's bytes are compared and dropped: they are never logged and never reach
// a verifier.
func warnLegacyTrustRoot(logger *slog.Logger, trustDir, publisherRoot string) {
	legacy := filepath.Join(trustDir, legacyTrustRootName)
	info, err := os.Lstat(legacy)
	if err != nil {
		// Absent is the normal shape on a dev box. Any other failure only
		// costs this advisory: the file is not used for trust either way.
		if !errors.Is(err, fs.ErrNotExist) {
			logger.Debug("legacy trust root not checked", "path", legacy, "err", err.Error())
		}
		return
	}
	if !info.Mode().IsRegular() {
		return
	}
	got, err := os.ReadFile(legacy)
	if err != nil {
		logger.Debug("legacy trust root not checked", "path", legacy, "err", err.Error())
		return
	}
	// An unreadable publisher root compares as empty, so the legacy file is
	// still reported as ignored; wireBundleVerifier logs the root's own fault
	// at ERROR.
	want, _ := os.ReadFile(publisherRoot)
	if bytes.Equal(got, want) {
		return
	}
	logger.Warn("trust root file at the legacy path is ignored",
		"path", legacy, "root", publisherRoot,
		"reason", "publisher trust comes only from the root the OS image bakes")
}
