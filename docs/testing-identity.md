# Testing against the real identity service

`api/internal/identitytest` runs the real, pinned identity service for a test package:

- **Keycloak 26.8.2**, from the pinned Maven Central tarball, on the pinned **Temurin JRE
  25.0.5+8**, built with the production build options (`identity/keycloak-build.conf`) and
  started the way the product's unit starts it (`kc.sh --config-file=… start --optimized
  --import-realm`, with the unit's `JAVA_OPTS_APPEND`, `JAVA_OPTS_KC_HEAP` and
  `MALLOC_ARENA_MAX`).
- **PostgreSQL 18.6**, in a container pinned by digest, with its data on a tmpfs.
- On demand, **Headscale** at the image `api/internal/mesh/mesh-images.json` pins, run by the
  product's own supervisor (`mesh.DockerSupervisor`).
- On demand, **Chrome for Testing 157.0.8103.78**, pinned by hash and driven by chromedp.

A test package gets one of each through `identitytest.Package`; the first test that asks starts
it, and the package's `TestMain` tears it down with proof. `api/internal/identitytest/signin` is
the Go headless sign-in client, which signs in through Keycloak's own pages
([geekdojo-brain#966](https://github.com/geekdojo/geekdojo-brain/issues/966)).

It is an **enforced gate**. The required `backend (vet + test + build)` CI job installs
everything with `scripts/install-identity.sh` and sets `RASPUTIN_IDENTITY_HOME` and
`RASPUTIN_IDENTITY_FUNCTIONAL=required` on its `test (api with coverage)` step, so on every PR
into `main` the self-test must run and pass. It cannot pass by skipping.

## The switch

`RASPUTIN_IDENTITY_HOME` names the install directory: `keycloak/`, `jre/` and
`chrome-linux64/chrome`, the layout `install-identity.sh` writes. `RASPUTIN_IDENTITY_FUNCTIONAL`
decides what happens when a dependency is missing. With everything present the tests always
run.

| `RASPUTIN_IDENTITY_FUNCTIONAL` | A dependency is missing | A dependency is present but broken |
|---|---|---|
| `required` (exactly) | Fails, naming the dependency, the path or command looked for, and the variable | Fails |
| unset, or any other value | Skips, giving the same reason | Fails |

The dependencies are: `RASPUTIN_IDENTITY_HOME` itself, Keycloak (`keycloak/bin/kc.sh`), the JRE
(`jre/bin/java`), docker (the CLI and a daemon that answers `docker info`) for PostgreSQL and
Headscale, and the browser (`chrome-linux64/chrome`). "Broken" is a Keycloak or JRE that is not
the pinned release, a Chrome that is not the pinned release, a `docker run` or `pull` that
fails, a service that exits before it is ready, or a readiness wait that ends with the test's
context. A start that failed fails every later test in the package with the same error; it is
attempted once.

The switch logic is `api/internal/functest` (`SkipOrFail`), shared with the secret store's and
the appsecret's functional tests.

## What it proves

On the CI runner (linux/amd64), by the self-test `selftest_functional_test.go`:

- With the switch required, a missing Keycloak, JRE, docker or browser fails the required
  `backend` job (the unit test `TestPackage_MissingDependencyFails` covers each case; the job's
  env lines make it live).
- Keycloak 26.8.2 on Temurin 25.0.5+8 against PostgreSQL 18.6 becomes ready on `/health/ready`
  over mutual TLS with a test CA, and a client with no certificate is refused at TLS
  (`TestIdentity_ReadyOverMutualTLS`). The start record names both versions.
- A password sign-in with the authorization code flow and PKCE S256 completes through the
  harness, seeing exactly the page sequence `[login-login]` (#959's FL2), and the ID token's
  `iss` is `Env.Issuer()`, its `aud` holds the client and its `nonce` is the one sent
  (`TestIdentity_PasswordCodeFlowPKCE`).
- Headscale at the `mesh-images.json` digest starts through the product's supervisor and
  answers `/health` over a client trusting only its CA (`TestIdentity_Headscale`).
- The pinned Chrome renders Keycloak's sign-in page through the front, and its body carries
  `data-page-id="login-login"` (`TestIdentity_Browser`).
- No record the harness or the client logged, Keycloak's own output lines included, holds the
  user password, the database password, an authorization code or token bytes
  (`TestIdentity_NoSecretInLogs`).
- Teardown leaves nothing: Keycloak is reaped and its process group, like Chrome's, is killed, the containers are
  gone from `docker ps -a`, no live process's command line or working directory names the
  harness's temporary root (java, `kc.sh`, Chrome and its helpers included), and the root is
  gone. A failed proof is written to stderr and turns the package red.
- The shipped api links no chromedp: the `backend` job's `shipped api binary carries no
  chromedp` step fails on any `github.com/chromedp/` package in
  `go list -deps ./api/cmd/rasputin-api`, and in the same step requires the pattern to match
  `go list -deps ./api/internal/identitytest`, so a drifted pattern cannot pass silently.

## What it does not prove

- arm64, the appliance, the OS packages and units, or the identity service's database link over
  TLS (Identity 2.4 and 2.6, proved in rasputin-os CI).
- That the front behaves like the door. The front is an `httptest` TLS server whose reverse
  proxy presents the client leaf to Keycloak; it stands in for the door (Identity 4.3) and
  forwards everything. It exists because `https-client-auth=required` holds for every caller,
  a browser included.
- Any sign-in verb other than password with PKCE. The TOTP, passkey, reset and app-door verbs
  land with the items whose CI cases need them; the vector file already carries their sections.
- The ID token's signature. The client decodes the payload of a token it received over TLS from
  the issuer.
- The real realm baseline (Identity 3.4) or the identity CA (Identity 3.1). The harness imports
  a minimal realm and makes its own test CA.
- Stability beyond the runs CI makes.
- The Python client's conformance to the vector file, which is #967's.

If Keycloak's runtime file (`keycloak.conf`) lives in rasputin-os, the OS guest checks prove it,
not this harness: the harness renders its own runtime file from #959's template.

**Flake surface.** Keycloak binds ports the kernel assigns and reports them in its start line,
so it has no free-port race. Headscale's HTTP port is picked free and released for docker to
bind, which is a race against other processes on the runner; it is never retried. Headscale's
STUN mapping is fixed at 127.0.0.1:3478/udp by the supervisor. A Docker Hub outage or rate limit
fails the two pulls.

## How to run it

On Linux x86_64 with docker, from the repo root. The install downloads about 440 MB once (Keycloak 174 MB, the JRE 62 MB, Chrome 203 MB) into
the download directory; later runs reuse what is there after checking it.

```sh
scripts/install-identity.sh "$HOME/.cache/rasputin-identity" "$HOME/.cache/rasputin-identity-download"
RASPUTIN_IDENTITY_HOME="$HOME/.cache/rasputin-identity" RASPUTIN_IDENTITY_FUNCTIONAL=required \
  go test -v ./api/internal/identitytest/...
```

- `install-identity.sh <dest> [<download-dir>]` checks every download against its pinned sha256
  before extracting it, refuses a kept download that fails the check (and leaves it in place),
  and refuses any host but Linux x86_64 before downloading anything.
- `RASPUTIN_IDENTITY_FUNCTIONAL=required` turns a missing dependency into a failure; leave it
  unset to skip instead.

A test package of your own uses the harness with this `TestMain`; `ConfigFromEnv` is the only
place the environment is read:

```go
var pkg = identitytest.NewPackage(identitytest.ConfigFromEnv)

func TestMain(m *testing.M) { os.Exit(pkg.Run(m)) }

func TestSomething(t *testing.T) {
	env := pkg.Env(t) // Issuer(), FrontURL(), ClientTLS(), User()
	// pkg.Headscale(t) and pkg.Browser(t) start those on demand.
}
```

## The vector file

`api/internal/identitytest/testdata/signin-vectors.json` is plain JSON, so any language can read
it. The Go client passes it today; the Python client (`os:test/lib/signin.py`,
[geekdojo-brain#967](https://github.com/geekdojo/geekdojo-brain/issues/967)) fetches it at the
control-plane tag the OS pins and must pass it too, so two clients of one protocol cannot drift
apart unseen.

| Section | Holds | Go client passes |
|---|---|---|
| `schema` | `1` | — |
| `source` | Keycloak 26.8.2 and #959's CI run 42538987025 | — |
| `pkce_rfc7636` | RFC 7636 appendix B's verifier and challenge | Yes (`TestPKCE`) |
| `totp_rfc6238` | RFC 6238 appendix B's seed as the ASCII digit string, the key length per hash, and the cases. There is no hex key literal: gitleaks flagged one on #959. | Reproduced under stdlib HMAC (`TestVectorFile`); the client has no TOTP verb yet |
| `webauthn.assertion`, `webauthn.registration` | #959's soft-passkey vectors, unchanged | Checked equal to #959's; the client has no passkey verb yet |
| `pages` | Each of #959's 12 fixtures (`testdata/pages/<id>.html`): its id, sha256, and forms with their field names, as #959's Python parser reads them | Yes (`TestParsePage_Fixtures`) |
| `flows` | Each verb of #959's run: step, verb, arguments, door and the page ids it saw | FL2 (`TestIdentity_PasswordCodeFlowPKCE`) |

The fixtures under `testdata/pages/` are Keycloak 26.8.2's own pages, byte for byte, script
included, and the vector file pins each one's sha256. They are only ever parsed as data: no
browser loads them (the self-test's Chrome renders the real Keycloak's pages). CodeQL's
JavaScript scan flags the theme's recovery-code copy script in one of them; the verdict and its
trip-wire are in `.github/codeql-register.tsv`.

## The pins, and bumping them

The pins are the constants in `api/internal/identitytest/pin.go`, each on a line of its own,
which `install-identity.sh` reads with an anchored `sed`. The CI cache key is the file's hash,
so any change to it downloads afresh. A bump changes a release and its hash together:

- **Keycloak.** Run geekdojo-brain's
  `projects/rasputin/research/identity-evidence/958/verify-signatures.sh` with
  `KC_V=<release> PARTS=keycloak`, commit its transcript, and copy the sha256 from it only if its
  verdict is PASS. Keycloak 26.8.2's transcript is
  `958/raw/signature-verification-keycloak-26.8.2.txt`.
- **The JRE.** The same script with `JRE_V=<release> PARTS=jre`; the x64 tarball's sha256 comes
  from its transcript.
- **PostgreSQL.** The image is addressed by digest, so docker verifies the content; take the
  digest of the new tag's index.
- **Chrome for Testing.** It publishes no checksum and no signature. Download the version's
  `chrome-linux64.zip` from the URL in its `known-good-versions-with-downloads.json` entry, check
  the download's MD5 against Google's stored object hash (the `x-goog-hash` header), and pin the
  sha256 of that download. The pin then proves only that every later download is those bytes.
- **Headscale** is not pinned here: the harness runs whatever `mesh-images.json` pins, through
  the product's supervisor.

Then run the self-test as above.

## Test cases

| ID | Proved by |
|---|---|
| TC-966-01 | `TestPackage_MissingDependencyFails` |
| TC-966-02 | `TestIdentity_PasswordCodeFlowPKCE` (CI) |
| TC-966-03 | `Package.Run`'s proof after the self-test (CI) |
| TC-966-04 | The `shipped api binary carries no chromedp` step (CI) |
| TC-966-05 | `TestStart_RefusesAnUnpinnedRelease`, `TestPackage_FailedStartFailsEveryCaller`, `TestCheckChromeVersion` |
| TC-966-06 | `TestNew_RefusesIncompleteConfig` (both packages) |
| TC-966-07 | `TestRenderKeycloakConf`, `TestRenderRealm`, `TestStart_WritesOwnerOnlyFilesAndTearsDownAnEarlyExit` |
| TC-966-08 | `TestPasswordCodeFlow`, `TestPasswordCodeFlow_FreshJarPerCall` |
| TC-966-09 | `TestParsePage_Fixtures`, `TestParsePage_Refusals` |
| TC-966-10 | `TestPKCE` |
| TC-966-11 | `TestVectorFile` |
| TC-966-12 | `TestIdentity_ReadyOverMutualTLS` (CI) |
| TC-966-13 | `TestIdentity_Headscale` (CI) |
| TC-966-14 | `TestIdentity_Browser` (CI) |
| TC-966-15 | `TestClose_TeardownProof`, `TestPackage_RunTurnsAFailedProofRed` |
| TC-966-16 | `api/internal/proctest`'s tests |
| TC-966-17 | The secret store's functional tests under `RASPUTIN_SECRETSTORE_FUNCTIONAL=required` (CI) |
| TC-966-18 | The install step's log (CI) |
| TC-966-19 | The first and a later CI run's cache steps |
| TC-966-20 | `TestIdentity_NoSecretInLogs` (CI) |
| TC-966-21 | The `api-coverage` artifact's counts for the self-test's functions (CI) |
