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
//     content it pulls; the digest is Docker Hub's index for tag 18.7
//     (2026-11-12), the release rasputin-os carries
//     (geekdojo/geekdojo-brain#972). Capability rows T69 and T70 pin it.
//   - ChromeLinux64SHA256 is the sha256 of Chrome for Testing's
//     chrome-linux64.zip for this version, taken at pin time
//     (2026-11-12). Chrome for Testing publishes no checksum and no signature,
//     so the hash proves only that every later download is the bytes first
//     pinned; Google's stored MD5 for the object matched that download.
//   - ChromeMacArm64SHA256 is the same for chrome-mac-arm64.zip at the same
//     version, taken at pin time (2026-11-23) for the console recipe's
//     screenshots on a Mac (cmd/consoleshots, geekdojo/geekdojo-brain#989):
//     the linux64 build aborts under Apple silicon's amd64 emulation. Google's
//     stored MD5 for the object matched that download.
//   - The password deny list (geekdojo/geekdojo-brain#1145) is SecLists'
//     Pwdb_top-10000000.txt at DenylistRelease's commit, whose data is
//     ignis-sec/Pwdb-Public's breach compilation (DenylistOriginRelease, the
//     repository's last commit). Neither publishes a signature or a
//     checksum, so DenylistSourceSHA256 and the two LICENSE hashes are the
//     sha256 of the files raw.githubusercontent.com served for those
//     commits on 2026-11-23, and prove only that every later download is
//     those bytes. scripts/fetch-denylist.sh downloads them, cuts the list
//     to the realm's minimum length, and the release ships the cut and both
//     MIT notices.
//
// A bump changes a release and its hash together and re-runs the same
// verification for the new release (docs/testing-identity.md).
const (
	KeycloakRelease = "keycloak/keycloak:26.8.2"
	KCDistSHA256    = "dd124787283918bc597628887168333465ee2a811a389e0003569e52be7e487f"

	JRERelease        = "adoptium/temurin25-binaries:25.0.5+8"
	JRELinuxX64SHA256 = "6fac98f0c8202efc3135a9e9e42aa61963ec42d1c5cbb40caf231e7b14a24ef6"

	PostgresMajor = "18"
	PostgresImage = "postgres:18.7@sha256:9f4fd4aa918f52ae3d6f3b687f1de90d8f867cd4d520021545a9a50c120eae3b"

	ChromeForTestingRelease = "googlechromelabs/chrome-for-testing:157.0.8103.78"
	ChromeLinux64SHA256     = "9223832977a13db3646201b1341c1f9cf08afa3ceae92540116d7b0c062364fb"
	ChromeMacArm64SHA256    = "bf3b49d0fe62a62397e98641aa736ef813c46014f03ec13d4913442e6966c7fc"

	DenylistRelease             = "danielmiessler/SecLists:12274c98fdebe98c7a7284914436a472ed469aed"
	DenylistSourcePath          = "Passwords/Common-Credentials/Pwdb_top-10000000.txt"
	DenylistSourceSHA256        = "18dc49ca32b62455a61e3398f4ab9f93eb700ff142fa0d4b9fd11a727f3b80e4"
	DenylistLicenceSHA256       = "3dbdc93d5f8829de0941744841730a09c106d0732e5ae0e98ca1d77be7ded66c"
	DenylistOriginRelease       = "ignis-sec/Pwdb-Public:9b53917431ed5cd57cd6cbec8c3a19cf9a5cd8dd"
	DenylistOriginLicenceSHA256 = "4088d581cba171b1aa6f880ad3fb5327e2d6de415621cf8b80685ac506c0cae1"
)
