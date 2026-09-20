// Package nodekeys holds the node's own long-lived TLS keys: one the agent
// presents to the control plane, one it hands to the per-node observability
// collector (geekdojo/geekdojo-brain#514).
//
// The keys are generated ONCE, on the node, and never leave it. What leaves is
// the SHA-256 of each key's public half, reported in registration metadata
// (proto.MetadataNodeKeys) and only over a pinned TLS bus connection. The
// control plane records those hashes and admits an HTTPS connection by
// comparing the peer's key against them — no CA issues anything here.
//
// The files live under the agent's state directory, which is persistent on
// both images: /var/lib/rasputin/agent-state on Rasputin OS, and
// /etc/rasputin/agent-state on the firewall, which keep.d already preserves
// across a sysupgrade (fw/files/lib/upgrade/keep.d/rasputin). So a reboot or an
// image update keeps a node's keys, and only a reflash changes them — which is
// what makes the control plane's "node key changed" alert a rare event worth
// looking at rather than noise.
//
// An existing file that does not parse is an error, never a reason to
// generate: replacing a key the control plane has recorded would take the node
// off HTTPS until an operator noticed, and silently minting a new identity is
// exactly what the key-change alert exists to make visible.
package nodekeys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Dir is the directory holding the node's keys under a state dir.
func Dir(stateDir string) string { return filepath.Join(stateDir, "keys") }

// KeyPath is where one purpose's private key lives. PEM, PKCS#8, 0600 —
// PEM rather than the bus key's one-line base64 because this file is only ever
// read by Go and, for the collector, handed to Alloy, which wants PEM.
func KeyPath(stateDir string, p proto.NodeKeyPurpose) string {
	return filepath.Join(Dir(stateDir), string(p)+".key")
}

// Keys is the node's loaded key set.
type Keys struct {
	stateDir string
	signers  map[proto.NodeKeyPurpose]crypto.Signer
	hashes   proto.NodeKeys
}

// Ensure loads the node's keys from stateDir, generating and persisting any
// that are missing. generated names the purposes that were created in this
// call, so the caller can log a first generation — the one moment the node's
// HTTPS identity comes into being.
//
// Every key is written 0600 inside a 0700 directory, staged and renamed so a
// power cut leaves the old file or the new one and never half of one.
func Ensure(stateDir string) (keys *Keys, generated []proto.NodeKeyPurpose, err error) {
	if stateDir == "" {
		return nil, nil, errors.New("nodekeys: state dir required")
	}
	dir := Dir(stateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("nodekeys: create %s: %w", dir, err)
	}
	// An existing directory from an earlier release, or one a restore put
	// back with a wider mode, is tightened rather than left open.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("nodekeys: %s could not be made 0700: %w", dir, err)
	}
	k := &Keys{
		stateDir: stateDir,
		signers:  map[proto.NodeKeyPurpose]crypto.Signer{},
		hashes:   proto.NodeKeys{},
	}
	for _, p := range proto.NodeKeyPurposes() {
		path := KeyPath(stateDir, p)
		signer, made, err := ensureOne(path)
		if err != nil {
			return nil, nil, err
		}
		if made {
			generated = append(generated, p)
		}
		hash, err := proto.NodeKeySPKIHash(signer.Public())
		if err != nil {
			return nil, nil, fmt.Errorf("nodekeys: %s: %w", path, err)
		}
		k.signers[p] = signer
		k.hashes[p] = hash
	}
	return k, generated, nil
}

// ensureOne loads path, or generates and persists a key when there is none.
func ensureOne(path string) (signer crypto.Signer, generated bool, err error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		s, perr := parse(data)
		if perr != nil {
			return nil, false, fmt.Errorf("nodekeys: %s exists but is not a usable key (refusing to replace it — the control plane has recorded this key): %w", path, perr)
		}
		// A key restored or copied with a wider mode is tightened rather
		// than refused: it is still the key the control plane recorded.
		if cerr := os.Chmod(path, 0o600); cerr != nil {
			return nil, false, fmt.Errorf("nodekeys: %s could not be made 0600: %w", path, cerr)
		}
		return s, false, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, false, fmt.Errorf("nodekeys: read %s: %w", path, err)
	}

	// ECDSA P-256 for the same reasons the bus key uses it (bustls.GenerateKey):
	// every Go TLS stack and every openssl an operator debugs with speaks it,
	// and the handshake is cheap on a Pi 4 with no crypto extensions.
	fresh, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, false, fmt.Errorf("nodekeys: generate %s: %w", path, err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(fresh)
	if err != nil {
		return nil, false, fmt.Errorf("nodekeys: marshal %s: %w", path, err)
	}
	blob := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := writeSecret(path, blob); err != nil {
		return nil, false, err
	}
	return fresh, true, nil
}

// parse reads the PEM PKCS#8 form Ensure writes. An EC PRIVATE KEY block is
// accepted too, for a key an operator made with openssl.
func parse(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no decodable PEM block")
	}
	if block.Type == "EC PRIVATE KEY" {
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse EC private key: %w", err)
		}
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported key type %T", k)
	}
	return s, nil
}

// writeSecret stages data beside path with mode 0600, fsyncs it, and renames
// it into place, then fsyncs the directory. O_EXCL on the final rename is not
// available, so a concurrent first start could race; the agent is a single
// process per node and starts this before anything else reads a key.
func writeSecret(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".key-*")
	if err != nil {
		return fmt.Errorf("nodekeys: stage %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("nodekeys: stage %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("nodekeys: write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("nodekeys: sync %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("nodekeys: close %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("nodekeys: install %s: %w", path, err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Signer returns the private key for a purpose, or nil when there is none.
func (k *Keys) Signer(p proto.NodeKeyPurpose) crypto.Signer {
	if k == nil {
		return nil
	}
	return k.signers[p]
}

// Hashes returns the SPKI hashes to report, as an independent copy. nil
// receiver returns nil, so a caller with no keys reports nothing rather than
// having to guard.
func (k *Keys) Hashes() proto.NodeKeys {
	if k == nil {
		return nil
	}
	return k.hashes.Clone()
}

// Path is where a purpose's key file is, for a caller that must hand the path
// to something other than Go.
func (k *Keys) Path(p proto.NodeKeyPurpose) string {
	if k == nil {
		return ""
	}
	return KeyPath(k.stateDir, p)
}
