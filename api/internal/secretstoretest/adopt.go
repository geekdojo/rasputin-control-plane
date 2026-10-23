package secretstoretest

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"

	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
)

// Restored is a restore's staged store members, by path: the data tree, the
// seal key and fragment, and the store CA pair (geekdojo/geekdojo-brain#765).
type Restored struct {
	DataDir string
	SealKey string
	SealHCL string
	CAKey   string
	CACert  string
}

// currentKeyIDRE reads current_key_id from a fragment in the shape
// rasputin-seal-key.sh writes. A line, not a parser: the harness only ever
// adopts fragments the backup captured.
var currentKeyIDRE = regexp.MustCompile(`(?m)^[ \t]*current_key_id[ \t]*=[ \t]*"(rasputin-[0-9a-f-]{36})"[ \t]*$`)

// Adopt makes a stopped store this restore's: it plays #766's store-unit
// apply step and the api's leaf re-mint. It swaps the restored data in for
// the store's own, writes the restored seal key under a fragment naming the
// restored key id at this store's seal path, loads the restored store CA,
// re-mints the server and client leaves from it, and restarts the store,
// returning once it answers 200 unsealed. It needs Config.ExternalSeal, and
// refuses a running store.
func (s *Store) Adopt(ctx context.Context, r Restored) error {
	if s.Running() {
		return errors.New("secretstoretest: Adopt: the store is still running; Stop it first")
	}
	if s.sealDir == "" {
		return errors.New("secretstoretest: Adopt: the store has no external seal (Config.ExternalSeal)")
	}
	frag, err := os.ReadFile(r.SealHCL)
	if err != nil {
		return fmt.Errorf("secretstoretest: Adopt: %w", err)
	}
	m := currentKeyIDRE.FindSubmatch(frag)
	if m == nil {
		return errors.New("secretstoretest: Adopt: the restored fragment names no rasputin key id")
	}
	data := filepath.Join(s.root, "data")
	if err := os.RemoveAll(data); err != nil {
		return fmt.Errorf("secretstoretest: Adopt: remove the store's data: %w", err)
	}
	if err := copyTree(r.DataDir, data); err != nil {
		return fmt.Errorf("secretstoretest: Adopt: %w", err)
	}
	if err := copySecretFile(r.SealKey, s.sealKey); err != nil {
		return err
	}
	if err := atrest.WriteSecretFile(filepath.Join(s.sealDir, "seal.hcl"), renderSealFragment(string(m[1]), s.sealKey)); err != nil {
		return fmt.Errorf("secretstoretest: Adopt: seal fragment: %w", err)
	}
	caDir := filepath.Join(s.root, "ca")
	if err := copySecretFile(r.CAKey, filepath.Join(caDir, tlsca.StoreKeyFile)); err != nil {
		return err
	}
	if err := copySecretFile(r.CACert, filepath.Join(caDir, tlsca.StoreCertFile)); err != nil {
		return err
	}
	ca, err := tlsca.Ensure(tlsca.StoreConfig(), caDir, "secretstoretest",
		tlsca.Deps{Now: s.h.cfg.Now, Rand: s.h.cfg.Rand, Log: s.h.cfg.Logger})
	if err != nil {
		return fmt.Errorf("secretstoretest: Adopt: load the restored store CA: %w", err)
	}
	if _, err := ca.MintLeafToDisk(filepath.Join(s.root, "server"), tlsca.LeafSpec{
		Usage: tlsca.UsageServer, CommonName: "secretstoretest server", IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}); err != nil {
		return fmt.Errorf("secretstoretest: Adopt: server leaf: %w", err)
	}
	client, err := ca.MintLeafToDisk(filepath.Join(s.root, "client"), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: ClientRole})
	if err != nil {
		return fmt.Errorf("secretstoretest: Adopt: client leaf: %w", err)
	}
	clientTLS, err := secretstore.NewTLSConfig(ca.CertPEM, client.CertPath, client.KeyPath)
	if err != nil {
		return fmt.Errorf("secretstoretest: Adopt: client TLS: %w", err)
	}
	s.leafMu.Lock()
	s.ca, s.clientLeaf, s.clientTLS = ca, client, clientTLS
	s.leaves = map[string]tlsca.LeafPaths{ClientRole: client}
	s.leafMu.Unlock()
	return s.Restart(ctx)
}

// copySecretFile copies src to dst, 0600.
func copySecretFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("secretstoretest: Adopt: %w", err)
	}
	defer clear(b)
	if err := atrest.WriteSecretFile(dst, b); err != nil {
		return fmt.Errorf("secretstoretest: Adopt: %w", err)
	}
	return nil
}

// copyTree copies the regular files under src to dst, owner-only.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return atrest.EnsureSecretDir(target)
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", p)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return atrest.WriteSecretFile(target, b)
	})
}
