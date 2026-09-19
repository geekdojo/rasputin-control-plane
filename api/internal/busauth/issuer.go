// Package busauth implements NATS auth-callout for the embedded bus: external
// agents present a per-node join token (NATS username=node-id, password=token),
// an in-process responder validates it against the token store, and mints a
// short-lived user JWT scoped to that node's subjects. The api's own
// in-process connection bypasses the callout as a configured AuthUser. The
// controlplane's co-located agent is not special: loopback is trusted no
// further than any other address, and the agent presents a join token like
// every other node — one the api mints for it at start (agenttoken.go,
// geekdojo-brain#140).
//
// See the bus-auth design (plan) and architecture.md §5.4. Mechanism verified
// against nats-server v2.11.17: auth callout + JetStream coexist on the global
// account in non-operator mode.
package busauth

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/nats-io/nkeys"

	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
)

// IssuerFileName is the account signing seed the callout responder uses to
// sign minted user JWTs; the public key is configured as the server's
// AuthCallout.Issuer. Persisted so the issuer identity is stable across api
// restarts (an unstable issuer would invalidate nothing at rest — JWTs are
// minted per-connection — but a stable seed keeps logs/debugging sane and
// matches the EnsureMeshCA persistence idiom).
const IssuerFileName = "issuer.nk"

// Issuer is the account keypair that signs callout responses + the user JWTs
// embedded in them.
type Issuer struct {
	kp     nkeys.KeyPair
	pubKey string
}

// PublicKey is the account public key to set as server Options AuthCallout.Issuer.
func (i *Issuer) PublicKey() string { return i.pubKey }

// KeyPair is the signing keypair (account NKey) used to encode JWTs.
func (i *Issuer) KeyPair() nkeys.KeyPair { return i.kp }

// EnsureIssuer loads the account signing seed from dir/issuer.nk, generating
// and persisting a fresh one (0600) on first run. Mirrors mesh.EnsureMeshCA.
func EnsureIssuer(dir string) (*Issuer, error) {
	if dir == "" {
		return nil, errors.New("busauth: EnsureIssuer: dir required")
	}
	// The bus directory holds this seed, the bus key, the controlplane
	// agent's token and the tombstones: owner-only, existing installs
	// included.
	if err := atrest.EnsureSecretDir(dir); err != nil {
		return nil, fmt.Errorf("busauth: %w", err)
	}
	path := filepath.Join(dir, IssuerFileName)

	seed, err := os.ReadFile(path)
	if err == nil {
		kp, err := nkeys.FromSeed(seed)
		if err != nil {
			return nil, fmt.Errorf("busauth: load issuer seed %s: %w", path, err)
		}
		return issuerFrom(kp)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("busauth: read issuer seed %s: %w", path, err)
	}

	// First run: generate + persist an account keypair.
	kp, err := nkeys.CreateAccount()
	if err != nil {
		return nil, fmt.Errorf("busauth: create account key: %w", err)
	}
	newSeed, err := kp.Seed()
	if err != nil {
		return nil, fmt.Errorf("busauth: encode seed: %w", err)
	}
	// Exclusive: two api processes racing a first start must not each
	// persist a different seed. The loser adopts the winner's.
	if err := atrest.CreateSecretFile(path, newSeed); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return EnsureIssuer(dir)
		}
		return nil, fmt.Errorf("busauth: write issuer seed %s: %w", path, err)
	}
	return issuerFrom(kp)
}

func issuerFrom(kp nkeys.KeyPair) (*Issuer, error) {
	pub, err := kp.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("busauth: issuer public key: %w", err)
	}
	return &Issuer{kp: kp, pubKey: pub}, nil
}
