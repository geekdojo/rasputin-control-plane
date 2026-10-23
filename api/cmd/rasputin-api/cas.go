package main

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/logkit"
)

// ensureCAs ensures both CA instances in trustDir, through the one tlsca code
// path, and returns them.
//
// The two fail differently because they are needed differently. The
// controlplane CA signs every HTTPS leaf this api serves and is shipped to
// every node, so a start without it cannot do anything a node or a browser
// can trust: FATAL, then exit(1), as it always was. The store CA has no
// consumer yet that the api cannot start without, so a store CA that will not
// load is one ERROR record and a nil store CA, and the start carries on.
// exit is os.Exit in main; the nils returned after it are never used.
//
// tlsca.Ensure logs the load or create itself; neither record here carries key
// material, because tlsca's errors name the file and the failure only.
//
// The store CA guard (#765, S15 part 8): with both store CA files absent and
// the store's data present (storeDataPresent, which reads an unreadable
// directory as present), no CA is created. A new CA would let the api log in
// to nothing the data's roles pin and would hide that the CA was lost; one
// ERROR names it, the store CA is nil, and the store wiring turns the store
// off as a configfault, so readiness raises secret-store:unreachable.
func ensureCAs(ctx context.Context, logger *slog.Logger, exit func(int), trustDir, installName string, deps tlsca.Deps,
	storeDataDir string, storeDataPresent bool) (controlplane, store *tlsca.CA) {
	controlplane, err := tlsca.Ensure(tlsca.ControlplaneConfig(), trustDir, installName, deps)
	if err != nil {
		logger.Log(ctx, logkit.LevelFatal, "rasputin-api: controlplane CA did not load", "ca", tlsca.ControlplaneConfig().Name, "err", err.Error())
		exit(1)
		return nil, nil
	}
	if storeDataPresent && absent(filepath.Join(trustDir, tlsca.StoreKeyFile)) && absent(filepath.Join(trustDir, tlsca.StoreCertFile)) {
		logger.ErrorContext(ctx, "store CA refused: store data present without its CA",
			"event", "tlsca.store_ca_refused", "ca", tlsca.StoreConfig().Name, "store_data_dir", storeDataDir)
		return controlplane, nil
	}
	store, err = tlsca.Ensure(tlsca.StoreConfig(), trustDir, installName, deps)
	if err != nil {
		logger.ErrorContext(ctx, "store CA unavailable", "ca", tlsca.StoreConfig().Name, "err", err.Error())
		return controlplane, nil
	}
	return controlplane, store
}

// absent reports whether nothing is at path.
func absent(path string) bool {
	_, err := os.Lstat(path)
	return errors.Is(err, fs.ErrNotExist)
}

// nodeTrustBundle is the bundle every node is given (nodetrust), on every mesh
// backend: the controlplane CA, then the operator's CA when mw is the external
// Headscale and RASPUTIN_HEADSCALE_CA_FILE named one. The self-hosted, mock
// and unavailable backends carry no operator CA, so their bundle is the
// controlplane CA alone — byte-identical to what self-hosted shipped before
// (tlsca.Bundle's golden test) — and never empty, which nodetrust.New refuses.
func nodeTrustBundle(cp *tlsca.CA, mw meshWiring) []byte {
	return tlsca.Bundle(cp.CertPEM, mw.operatorCA)
}
