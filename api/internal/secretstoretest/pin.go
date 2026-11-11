package secretstoretest

// The pinned secret store: the one OpenBao release the harness runs, and the
// one tarball CI accepts for it. scripts/install-openbao.sh reads both
// constants out of this file with an anchored sed, so keep each on its own
// line in the `Name = "value"` form, and keep them in this file.
//
// OpenBaoRelease is the GitHub owner/repo:tag. It is also the pin that
// .github/third-party-capabilities.tsv rows T20-T57 and T60-T64 point at
// (go-const:api/internal/secretstoretest/pin.go#OpenBaoRelease), so changing
// the tag fails gatereg until those rows are re-verified at the new release.
//
// OpenBaoLinuxAMD64SHA256 is the sha256 of
// openbao_<version>_linux_amd64.tar.gz. Its provenance is the point of it:
//
//   - It is copied ONLY from an upstream checksums.txt whose signature has
//     been verified with both GPG (the OpenBao release key) and cosign (the
//     release workflow's identity), as geekdojo-brain#678's
//     verify-signatures.sh does. For v2.7.2 that is
//     projects/rasputin/research/openbao-evidence/rasputin-os-197/raw/signature-verification-v2.7.2.txt
//     (the #678 script run with V=2.7.2, for geekdojo/rasputin-os#197), which
//     records checksums.txt sha256=d839d376…b77e passing both and this
//     tarball's line matching it.
//   - A hash copied from an unverified checksums.txt proves only that the
//     bytes match what the download host served. gatereg fires when the TAG
//     changes, not when this hash does, so nothing but this rule stops a
//     bump from taking an unverified hash.
//   - A bump changes both constants together, re-runs that verification for
//     the new release, and re-verifies T20-T57 and T60-T64 at it. The
//     rasputin-os OPENBAO_VERSION pin is kept in step by hand until
//     geekdojo-brain#769 automates it (docs/testing-secret-store.md).
const (
	OpenBaoRelease          = "openbao/openbao:v2.7.2"
	OpenBaoLinuxAMD64SHA256 = "582b1f3c2fdc5afd443b2d57a225ef654de75adea609fdb66731fd582a9cbc96"
)
