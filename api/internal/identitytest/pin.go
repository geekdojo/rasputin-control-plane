package identitytest

// The pinned identity service, its runtime, its database and the browser: the
// one release of each the harness runs, and the one download CI accepts for
// it. scripts/install-identity.sh reads these constants out of this file with
// an anchored sed, so keep each on its own line in the `Name = "value"` form,
// and keep them in this file.
//
// The release constants use the `owner/repo:version` form, so a later
// capability row can pin one as go-const: (gatereg reads the text after the
// last ':').
//
// Provenance of each hash, which is the point of it:
//
//   - KCDistSHA256 is the sha256 of Maven Central's
//     keycloak-quarkus-dist-26.8.2.tar.gz, copied only after its .asc
//     signature verified under the key keycloak.org/keys lists for Maven
//     artifacts: geekdojo-brain
//     projects/rasputin/research/identity-evidence/958/raw/signature-verification-keycloak-26.8.2.txt
//     (958's verify-signatures.sh run with KC_V=26.8.2 for
//     geekdojo/geekdojo-brain#966). It equals the hash
//     geekdojo/geekdojo-brain#959's probe ran.
//   - JRELinuxX64SHA256 is the sha256 of Adoptium's
//     OpenJDK25U-jre_x64_linux_hotspot_25.0.5_8.tar.gz, signature-verified in
//     the same evidence directory: raw/signature-verification-jre-25.0.5+8.txt.
//   - PostgresImage is addressed by digest, so docker itself verifies the
//     content it pulls; the digest is #959's.
//   - ChromeLinux64SHA256 is the sha256 of Chrome for Testing's
//     chrome-linux64.zip for this version, taken at pin time
//     (2026-11-12). Chrome for Testing publishes no checksum and no signature,
//     so the hash proves only that every later download is the bytes first
//     pinned; Google's stored MD5 for the object matched that download.
//
// A bump changes a release and its hash together and re-runs the same
// verification for the new release (docs/testing-identity.md).
const (
	KeycloakRelease = "keycloak/keycloak:26.8.2"
	KCDistSHA256    = "dd124787283918bc597628887168333465ee2a811a389e0003569e52be7e487f"

	JRERelease        = "adoptium/temurin25-binaries:25.0.5+8"
	JRELinuxX64SHA256 = "6fac98f0c8202efc3135a9e9e42aa61963ec42d1c5cbb40caf231e7b14a24ef6"

	PostgresMajor = "18"
	PostgresImage = "postgres:18.6@sha256:e3d24f6906d0760bf4da0dae872415391ededefad23fd471c47dc53b0ddf3c42"

	ChromeForTestingRelease = "googlechromelabs/chrome-for-testing:157.0.8103.78"
	ChromeLinux64SHA256     = "9223832977a13db3646201b1341c1f9cf08afa3ceae92540116d7b0c062364fb"
)
