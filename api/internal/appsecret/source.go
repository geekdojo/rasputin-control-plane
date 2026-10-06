package appsecret

import (
	"context"
	"errors"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// errNoSeed is HKDFSource's refusal when it has no seed to derive from.
var errNoSeed = errors.New("appsecret: HKDF source has no seed")

// HKDFSource resolves an app's compose by deriving every ${secret:<name>}
// token from the cluster's app-secret seed (Resolve). It satisfies the secret
// source the apps package declares for its push step, and adds nothing of its
// own: no Reveal, no rendering, no other policy than the rotation version.
//
// Rotation always derives at InitialVersion for now: nothing stores a per-app
// counter yet (see InitialVersion).
type HKDFSource struct {
	seed *Seed
}

// NewHKDFSource returns the source over seed. It refuses a nil seed.
func NewHKDFSource(seed *Seed) (*HKDFSource, error) {
	if seed == nil {
		return nil, errors.New("appsecret: an HKDF source needs a seed")
	}
	return &HKDFSource{seed: seed}, nil
}

// ResolveCompose returns Resolve(compose, appID, seed, InitialVersion).
//
// A nil receiver, or one with no seed (the zero HKDFSource), refuses every
// compose, token-free included, with the zero Value: a source with no seed is
// broken wiring, and it says so on the first deploy rather than only on the
// first one that carries a token.
func (s *HKDFSource) ResolveCompose(_ context.Context, appID, compose string) (secret.Value, error) {
	if s == nil || s.seed == nil {
		return secret.Value{}, errNoSeed
	}
	return Resolve(compose, appID, s.seed, InitialVersion)
}
