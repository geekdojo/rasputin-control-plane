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
// It is the deploy family's source when no store backend is requested, as in
// every release before geekdojo/geekdojo-brain#762; with one requested, main
// wires StoreSource behind the readiness Gate instead. Rotation always derives
// at InitialVersion for now (see InitialVersion).
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

// ResolveCompose returns Resolve(compose, appID, seed, InitialVersion): the
// compose with interpolation references in place of its tokens, and the map of
// their values.
//
// A nil receiver, or one with no seed (the zero HKDFSource), refuses every
// compose, token-free included, with the zero Value and a nil map: a source with no seed is
// broken wiring, and it says so on the first deploy rather than only on the
// first one that carries a token.
func (s *HKDFSource) ResolveCompose(_ context.Context, appID, compose string) (secret.Value, map[string]secret.Value, error) {
	if s == nil || s.seed == nil {
		return secret.Value{}, nil, errNoSeed
	}
	return Resolve(compose, appID, s.seed, InitialVersion)
}
