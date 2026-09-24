package appsecret

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
)

// SeedFileName is the app-secret seed, in trustDir — /var/lib/rasputin/trust on
// an appliance, beside mesh-ca.key. ADR-0006 Decision 11a puts it there on
// purpose: that partition is the one the mesh CA already depends on surviving
// an A/B image switch and a rollback, so the seed inherits a property that has
// been exercised rather than one that has been assumed.
const SeedFileName = "app-secret.seed"

// seedFileMagic opens the seed file's single line. The line is
//
//	rasputin-app-secret-seed/<derivationVersion> <base64url(seed)>
//
// ONE FILE, not a seed file and a version file beside it, and the reason is the
// restore path. The derivation version is not metadata about the seed, it is
// half of the key: deriving 32 bytes with the wrong one produces a valid-looking
// credential that no app has ever seen. Two files can be separated — a restore
// that carries one and not the other, a create that crashes between them — and
// each of those is a way to hold half a key while believing it holds a whole
// one. In one file the pair cannot come apart: atrest.CreateSecretFile links it
// into place whole, and the identity archive captures it as a single member with
// a single digest.
//
// Text rather than raw bytes for the same reason it is one file: the version has
// to be readable without this binary. An operator or an agent debugging an
// appliance can cat the file and see which derivation a cluster's secrets were
// minted under. The secrecy is the 0600 mode and the partition, exactly as it is
// for issuer.nk, and an encoding does not add to it.
const seedFileMagic = "rasputin-app-secret-seed/"

// EnsureSeed loads the app-secret seed from dir/app-secret.seed, generating and
// persisting a fresh one (0600) on first run.
//
// Deliberately the same shape as busauth.EnsureIssuer, down to the recursion on
// fs.ErrExist, because it has the same create-once requirement: a value that has
// been handed out must never be replaced. For the issuer seed a replacement
// invalidates nothing at rest — the JWTs it signs are minted per connection. For
// THIS seed a replacement is unrecoverable: every app secret on the cluster is a
// function of it, the old value survives inside the app's data volume, and there
// is nothing to re-derive from.
func EnsureSeed(dir string) (*Seed, error) {
	if dir == "" {
		return nil, errors.New("appsecret: EnsureSeed: dir required")
	}
	// The trust dir holds the mesh CA's private key and now this: owner-only,
	// existing installs included.
	if err := atrest.EnsureSecretDir(dir); err != nil {
		return nil, fmt.Errorf("appsecret: %w", err)
	}
	path := filepath.Join(dir, SeedFileName)

	raw, err := os.ReadFile(path)
	if err == nil {
		seed, perr := parseSeedFile(raw)
		if perr != nil {
			// NOT repaired and NOT replaced. A seed file we cannot read is
			// either a newer release's or a damaged one, and in both cases
			// minting a fresh seed over it destroys every app secret on the
			// cluster with no way back. Refusing to start is the recoverable
			// outcome: the file is still there to be restored or rolled back to.
			return nil, fmt.Errorf("appsecret: read seed %s: %w", path, perr)
		}
		return seed, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("appsecret: read seed %s: %w", path, err)
	}

	// First run: mint a seed under the version this build derives with.
	key := make([]byte, SeedLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("appsecret: generate seed: %w", err)
	}
	// Exclusive: two api processes racing a first start must not each persist a
	// different seed, because the loser's apps would already hold credentials
	// derived from it. The loser adopts the winner's.
	if err := atrest.CreateSecretFile(path, formatSeedFile(key, DerivationVersion)); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return EnsureSeed(dir)
		}
		return nil, fmt.Errorf("appsecret: write seed %s: %w", path, err)
	}
	return NewSeed(key, DerivationVersion)
}

// formatSeedFile renders the one line the seed file holds.
func formatSeedFile(key []byte, derivationVersion int) []byte {
	return []byte(seedFileMagic + strconv.Itoa(derivationVersion) + " " +
		base64.RawURLEncoding.EncodeToString(key) + "\n")
}

// parseSeedFile reads the one line back, strictly. Every refusal names what it
// found: this file is read once per api start and a bad one stops the boot, so
// the message is the whole of what an operator has to work from.
func parseSeedFile(raw []byte) (*Seed, error) {
	line, _, _ := strings.Cut(strings.TrimRight(string(raw), "\n"), "\n")
	if !strings.HasPrefix(line, seedFileMagic) {
		return nil, fmt.Errorf("does not begin with %q — this is not an app-secret seed file", seedFileMagic)
	}
	rest := strings.TrimPrefix(line, seedFileMagic)
	versionText, keyText, ok := strings.Cut(rest, " ")
	if !ok {
		return nil, errors.New("holds a derivation version with no seed after it")
	}
	derivationVersion, err := strconv.Atoi(versionText)
	if err != nil {
		return nil, fmt.Errorf("derivation version %q is not a number", versionText)
	}
	key, err := base64.RawURLEncoding.DecodeString(keyText)
	if err != nil {
		return nil, fmt.Errorf("seed is not unpadded base64url: %w", err)
	}
	return NewSeed(key, derivationVersion)
}
