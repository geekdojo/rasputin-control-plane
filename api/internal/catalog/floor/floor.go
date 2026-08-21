// Package floor holds the offline catalog floor: the published catalog as of
// this build, embedded in the binary.
//
// ADR-0006 Decision 6. The baked catalog is no longer THE catalog — it is what
// a cluster has before it has ever completed a verified fetch: first boot, an
// airgapped install, a WAN outage on day one. Resolution is stated once and
// has no third case: the effective catalog is the most recent verified fetch,
// or this. Never a union, never a merge.
//
// WHERE VERIFICATION HAPPENS, AND WHY NOT HERE. scripts/embed-catalog.sh
// verifies the signature against the Rasputin root CA before writing these
// files, and CI re-verifies the committed pair. It is deliberately NOT
// re-checked at runtime: this bundle lives inside the binary, so anyone able
// to alter it can equally alter the code that would check it. A runtime check
// on embedded content is theatre, and worse, it would make the api refuse to
// start on a dev machine with no root CA installed. The signature is committed
// alongside anyway, so the claim stays auditable after the fact.
package floor

import (
	_ "embed"
	"fmt"

	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

//go:embed catalog.json
var bundleJSON []byte

//go:embed catalog.json.sig
var bundleSig []byte

// Load parses and validates the embedded floor.
//
// An invalid floor is a BUILD defect, not a runtime condition — it means the
// embed script wrote something the reader rejects, and every cluster from this
// image would inherit it. Callers should treat the error as fatal at startup.
func Load() (tileschema.Bundle, error) {
	b, err := tileschema.ParseBundle(bundleJSON)
	if err != nil {
		return tileschema.Bundle{}, fmt.Errorf("embedded catalog floor: %w", err)
	}
	return b, nil
}

// Signature returns the detached CMS signature the floor was embedded with, so
// the claim "this was verified before it went in" can be re-checked by anyone
// holding the public root CA rather than taken on trust.
func Signature() []byte { return bundleSig }

// Raw returns the embedded bundle bytes, which is what the signature covers.
func Raw() []byte { return bundleJSON }
