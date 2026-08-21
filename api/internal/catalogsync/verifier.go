package catalogsync

import (
	"github.com/geekdojo/rasputin-control-plane/artifactsig"
)

// catalogVerifier is the one production Verifier: the shared artifactsig,
// permanently bound to the CATALOG purpose.
//
// The purpose is baked in rather than passed by the caller on purpose. A
// signature check that takes "which purpose?" as an argument is one refactor
// away from being handed the release OID, and the two are indistinguishable at
// the call site — both are valid signatures chaining to the same root. Binding
// it here means the catalog path can only ever authorize a catalog leaf.
type catalogVerifier struct{ trustRoot string }

// NewVerifier returns a Verifier that accepts only signatures made by a leaf
// carrying OIDCodeSigningCatalog and chaining to the root CA at trustRoot.
//
// There is deliberately no permissive mode. api/internal/updater.Verifier
// degrades to skipping signature checks when no root CA is present, which is
// defensible for a locally-built dev bundle and indefensible for a catalog
// fetched off the internet — so a missing trust root here fails the fetch and
// the cluster keeps its last good catalog.
func NewVerifier(trustRoot string) Verifier { return catalogVerifier{trustRoot: trustRoot} }

func (c catalogVerifier) VerifyForPurpose(artifactPath, sigPath string) error {
	_, err := artifactsig.VerifyForPurpose(artifactPath, sigPath, c.trustRoot, artifactsig.OIDCodeSigningCatalog)
	return err
}
