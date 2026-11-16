# Testing against the real identity service

`api/internal/identitytest` runs the real, pinned identity service for a test package:

- **Keycloak 26.8.2**, from the pinned Maven Central tarball, on the pinned **Temurin JRE
  25.0.5+8**, built with the production build options (`identity/keycloak-build.conf`) and
  started the way the product's unit starts it (`kc.sh --config-file=… start --optimized
  --import-realm`, with the unit's `JAVA_OPTS_APPEND`, `JAVA_OPTS_KC_HEAP` and
  `MALLOC_ARENA_MAX`).
- **PostgreSQL 18.7**, in a container pinned by digest, with its data on a tmpfs.
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
- Keycloak 26.8.2 on Temurin 25.0.5+8 against PostgreSQL 18.7 becomes ready on `/health/ready`
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
- Under the unit's `-Djava.awt.headless=true`, Keycloak on the pinned JRE renders the
  authenticator-code QR: the pinned Chrome signs the harness user in with
  `kc_action=CONFIGURE_TOTP`, the page is `login-login-config-totp`, and the
  `kc-totp-secret-qr-code` image's `data:image/png;base64` URI decodes as a PNG with non-empty
  bounds (`TestIdentity_TOTPQRUnderHeadlessJRE` in `jre_functional_test.go`, capability row
  T72; Keycloak on the pinned JRE is row T71,
  [geekdojo-brain#969](https://github.com/geekdojo/geekdojo-brain/issues/969)). It runs in its
  own browser context and never submits the enrolment form, so the harness user gets no OTP
  credential. It does not prove what the QR encodes.
- The features `identity/keycloak-build.conf` disables serve nothing at the pin: through the
  front, `/admin/`, the account console, pushed authorization requests and CIBA authentication
  answer 404, the token endpoint refuses the device-code and token-exchange grants with
  `unsupported_grant_type`, and discovery has no `device_authorization_endpoint`
  (`TestIdentity_DisabledFeaturesServeNothing` in `features_functional_test.go`, capability row
  T73, [geekdojo-brain#980](https://github.com/geekdojo/geekdojo-brain/issues/980)).
- No record the harness or the client logged, Keycloak's own output lines included, holds the
  user password, the database password, an authorization code or token bytes
  (`TestIdentity_NoSecretInLogs`).
- Teardown leaves nothing: Keycloak is reaped and its process group, like Chrome's, is killed, the containers are
  gone from `docker ps -a`, no live process's command line or working directory names the
  harness's temporary root (java, `kc.sh`, Chrome and its helpers included), and the root is
  gone. A failed proof is written to stderr and turns the package red.
- PostgreSQL at the pin, configured TLS-only with #958's TLS lines and a `pg_hba` whose only
  line is `hostssl … cert`, refuses a connection without TLS and admits the same one over TLS
  with a client certificate (capability row T69), and accepts its key from files owned by its
  own uid at 0400 in its own 0500 directory, the shape `LoadCredential=` gives a service (row
  T70). `TestPostgresTLSOnly` runs this in a container of its own and needs only docker, not
  Keycloak ([geekdojo-brain#972](https://github.com/geekdojo/geekdojo-brain/issues/972)).
- The shipped api links no chromedp: the `backend` job's `shipped api binary carries no
  chromedp` step fails on any `github.com/chromedp/` package in
  `go list -deps ./api/cmd/rasputin-api`, and in the same step requires the pattern to match
  `go list -deps ./api/internal/identitytest`, so a drifted pattern cannot pass silently.
- The api's identity-CA leaves, minted by the production `wireIdentityLeaves` under the harness's
  test CA (made from `tlsca.IdentityConfig`) and presented straight to Keycloak's own port:
  the api leaf (CN `rasputin-api`) gets an administrator token from the realm's `client-x509`
  client `harness-admin`, the door leaf (CN `rasputin-door`) completes TLS and gets 401
  `invalid_client`, and a controlplane-CA leaf and a store-CA leaf with the api leaf's subject
  are refused at TLS, with no HTTP status
  (`api/cmd/rasputin-api/identityca_functional_test.go`, under the same
  `RASPUTIN_IDENTITY_FUNCTIONAL=required` switch,
  [geekdojo-brain#977](https://github.com/geekdojo/geekdojo-brain/issues/977)).
- The shipped realm baseline works as Keycloak builds it: `identity/realm-baseline.json` is
  imported as realm `rasputin` with Keycloak's own `kc.sh import`; `rasputin-admin`, with a
  `client-x509` leaf whose subject is `CN=rasputin-api,O=Rasputin`, gets a token, reads the realm
  and creates and deletes a user through the Admin API; each of the five sign-in clients completes
  a password sign-in; and the console's token carries `auth_time` and `rasputin_roles`
  (`api/internal/identitytest/baseline_import_functional_test.go`, under the same switch,
  [geekdojo-brain#980](https://github.com/geekdojo/geekdojo-brain/issues/980)).
- The api's identity client, as `wireIdentity` builds it, against the imported baseline
  (`api/internal/identitytest/identityclient_functional_test.go`, under the same switch,
  [geekdojo-brain#978](https://github.com/geekdojo/geekdojo-brain/issues/978)): the Admin API
  session logs in once by `client-x509` as `rasputin-admin`, and after its token is revoked it
  logs in exactly once more and the retried call answers 200; a `CN=rasputin-api` leaf from a
  foreign CA is refused at TLS (`ErrDenied`, capability row T74); the door leaf gets
  `ErrDenied` with `invalid_client` while the api leaf is the administrator (rows T75, T76);
  `/health/ready` answers over mutual TLS; and `identity.recover_admin`, with `rasputin-admin`
  deleted, stops Keycloak, runs the real `kc.sh bootstrap-admin service` with the temporary
  secret only in its environment, starts it on the same ports, re-creates `rasputin-admin` from
  the baseline, and leaves no user and no `rasputin-recover-*` client in realm `master`
  (counted with psql), with the secret in no record and not in `kc.sh`'s output. If the Admin
  API still accepts a token revoked at the RFC 7009 endpoint, the test ends it by retiring the
  realm's RS256 signing key instead, and says so in its log.

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
- The baseline's sign-in flows. Its flow skeletons are empty and unbound until Identity 4.5
  converges them, so the sign-ins above run Keycloak's default browser flow.
- Stability beyond the runs CI makes.
- The Python client's conformance to the vector file, which is #967's.

If Keycloak's runtime file (`keycloak.conf`) lives in rasputin-os, the OS guest checks prove it,
not this harness: the harness renders its own runtime file from #959's template.

**Flake surface.** Keycloak binds ports the kernel assigns and reports them in its start line,
so it has no free-port race. Headscale's HTTP port is picked free and released for docker to
bind, which is a race against other processes on the runner; it is never retried. Headscale's
STUN mapping is fixed at 127.0.0.1:3478/udp by the supervisor. A Docker Hub outage or rate limit
fails the two pulls. The identity-state tests (below) also pick ports free and release them: the restartable
database's host port in TC-979-01, and the pair's database, Keycloak https and management ports
in TC-979-02 and TC-979-04, because those must stay the same across a restart. The same race
applies, and they are never retried.

## The identity state: database down, out of memory, a full partition

[geekdojo-brain#979](https://github.com/geekdojo/geekdojo-brain/issues/979) (Identity 3.3) adds
three functional tests of `api/internal/identitystate`, the api's view of the identity service's
state. They run the real pinned Keycloak and PostgreSQL, and two of them run them under the CI
runner's real systemd.

| Test | Runs as | Proves |
|---|---|---|
| `TestIdentityState_DatabaseDown` (TC-979-01, row T80 K-HEALTH) | the runner user, in `test (api with coverage)` | With Keycloak ready, `docker stop` on its database makes `/health/ready` answer 503 naming `Keycloak database connections async health check` DOWN. The state reads `database-down` with its sentence, and `Ready` refuses with `identity_not_ready`. After `docker start` the state is `Ready` with no `identity:` alert. Its own Env keeps the database's data across the stop and serves it on a fixed port. |
| `TestIdentitySystemd_OutOfMemory` (TC-979-02, row T79 K-OOMEXIT) | root, in `test (identity under real systemd, root)` | Keycloak with a 16 MiB heap exits with status 3 on each start, under `Restart=always`, until systemd's start limit (`StartLimitBurst=3`, `StartLimitIntervalSec=infinity`) fails the unit after its third run. The runner's systemd leaves it `failed` with `Result=exit-code`, not `start-limit-hit`. Each invocation's record says `exit_code=exited`, `exit_status=3`, and `last` names the unit's last `InvocationID`. One reading gives `out-of-memory` and exactly one `identity.service_exit` job per record, and leaves only `last` and its record. A second reading adds no job. |
| `TestIdentitySystemd_FullPartition` (TC-979-04) | root, in the same step | With PostgreSQL's data on a 128 MiB tmpfs that is then filled, the database unit crash-loops until systemd's start limit (`StartLimitBurst=5`, `StartLimitIntervalSec=infinity`) leaves it `failed`, and Keycloak stops with it. The state reads `database-down`, and `identity.recover` arms but is not due. Once the fill file is removed it is due exactly once, its job restarts the pair through `sysunit.RestartUnits`, and the state reaches `Ready`. |

[geekdojo-brain#1127](https://github.com/geekdojo/geekdojo-brain/issues/1127) (Identity 2.8) adds
`TestRecoverAdminTrigger_AgainstPinnedKeycloak`
(`api/internal/identitytest/recoveradmin_trigger_functional_test.go`), the trigger that submits
`identity.recover_admin`. It runs as the runner user in `test (api with coverage)`, under the same
`RASPUTIN_IDENTITY_FUNCTIONAL=required` switch, against the imported baseline. Each subtest builds
its own job ledger, a real `jobs.Runner` over in-process NATS and the api's session, as one api
process would.

| Subtest | Proves |
|---|---|
| TC-1127-15 (row T83) | `failureFactor+1` (read from the baseline) of each of: client-credentials logins as `rasputin-admin` with the door leaf, with a foreign-CA leaf, and with the door leaf and a client secret; password grants for `service-account-rasputin-admin`; and login-form sign-ins as that user through `signin.PasswordCodeFlow`. Afterwards the trigger is not due, the api leaf's login and the session's realm read answer 200, the service account's brute-force status reads not disabled, and the ledger holds no job. |
| TC-1127-16 (row T81) | With `rasputin-admin` deleted, the real scheduler's first tick submits exactly one job, which succeeds; the restored hook is called once with its id; the session reads the realm and creates and deletes a user; the trigger is no longer due; the temporary secret is in no record. |
| TC-1127-17 (row T82) | With the service account's realm-management roles removed, the session's realm read answers 403 and the trigger is due; the job succeeds and the read answers 200. |
| TC-1127-18 | With `rasputin-admin` deleted and the baseline unreadable, the job fails with the baseline sentence; after two more scheduler ticks (30 s apart, waited on as ticks) the ledger still holds that one job, and the alerts list carries `job-failed:<id>` and `identity:admin-client-refused`. |

**The units.** The two root tests write the pair as runtime unit files under
`/run/systemd/system`, related as `keycloak-db.service` and `keycloak.service` are (`Requires=`
and `After=`), and start them through a test target that `Wants=` both, as `multi-user.target`
wants the appliance's units. They are not `systemd-run` transient units, because systemd
garbage-collects an inactive transient unit. The target matters for the same reason: an
inactive unit file that nothing references is unloaded, and `systemctl reset-failed` of an
unloaded unit fails, so `identity.recover`'s restart of a Keycloak its failed database had
stopped would fail. Each test's cleanup stops both units, removes their files, unmounts
the tmpfs and removes the container, then shows the units and the target `not-found`, no container
and nothing mounted.

**What the units do not carry, and the contract they stand in for.** The units carry none of
the hooks that rasputin-os builds for `keycloak.service`
([geekdojo-brain#973](https://github.com/geekdojo/geekdojo-brain/issues/973), Identity 2.5).
None of them is run here:

- **The start wait (`ExecStartPost=`).** It waits for `/health/started` and then removes the
  start-hold count file. It exits non-zero as soon as Keycloak's main process (`$MAINPID`) is
  gone, and the unit's `TimeoutStartSec=` is bounded rather than `infinity`, so a crash during
  start never leaves the unit activating. The test unit has no start wait, so it reads `active`
  from the JVM's start, and its start timeout is systemd's default.
- **The start hold (`ExecStartPre=`)** and its record.
- **The real exit-record hook (`ExecStopPost=`)** and its 256-record cap. TC-979-02 uses
  `api/internal/identitytest/testdata/exit-record-standin.sh` instead. It is a **minimal
  stand-in**, not the shipped hook. It writes exactly the contract's record (`outcome`,
  `invocation_id`, `exit_code`, `exit_status`) and then `last`, from the `SERVICE_RESULT`,
  `INVOCATION_ID`, `EXIT_CODE` and `EXIT_STATUS` systemd gives it, each through a rename. It has
  no cap.

So the tests prove the api's reading of the contract's files under real systemd values. They do
not prove that #973's hooks write them.

**How to run them.** `TestIdentityState_DatabaseDown` runs with the rest of the package (see
[How to run it](#how-to-run-it)). The two root tests need Linux with systemd as the init system,
docker, and root. They skip without them, and fail instead under
`RASPUTIN_IDENTITY_SYSTEMD_FUNCTIONAL=required`, which only CI's root step sets. Build the test
binary as yourself and run it under sudo, from the package directory so `testdata/` resolves.
A test binary run directly has no default timeout, so pass go test's own; each wait ends before
it with an error naming the fact it waited for, and the cleanup still runs.

```sh
go test -c -race -o /tmp/identitytest.test ./api/internal/identitytest
cd api/internal/identitytest
sudo env PATH="$PATH" RASPUTIN_IDENTITY_HOME="$HOME/.cache/rasputin-identity" \
  RASPUTIN_IDENTITY_FUNCTIONAL=required RASPUTIN_IDENTITY_SYSTEMD_FUNCTIONAL=required \
  /tmp/identitytest.test -test.v -test.count=1 -test.timeout=10m -test.run '^TestIdentitySystemd_'
```

**Does not prove:** arm64; the `oom-kill` path (systemd's own OOM kill), which has unit tests
only; the producers of `upgrading`, `held`, `blank`, `apps-paused` and `history-behind`; and the
hooks listed above.

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
  Keep the version equal to the one rasputin-os carries (`RASPUTIN_POSTGRESQL_VERSION` in its
  `package/rasputin-postgresql/rasputin-postgresql.mk`), and re-verify capability rows T69 and
  T70 at the new pin: `TestPostgresTLSOnly` passing there, then the rows' `version` column.
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
| TC-969-18 | `TestIdentity_TOTPQRUnderHeadlessJRE` (CI) |
| TC-969-21 | `TestIdentity_TOTPQRUnderHeadlessJRE` running first, then `TestIdentity_PasswordCodeFlowPKCE`, `TestIdentity_Browser`, `TestIdentity_NoSecretInLogs` and `Package.Run`'s proof (CI) |
| TC-977-16 | `TestIdentityCA_APILeafIsAdministrator` (CI) |
| TC-977-17 | `TestIdentityCA_DoorLeafIsNotAdministrator` (CI) |
| TC-977-18 | `TestIdentityCA_ControlplaneLeafRefusedAtTLS` (CI) |
| TC-977-19 | `TestIdentityCA_StoreLeafRefusedAtTLS` (CI) |
| TC-980-21 | `TestIdentity_DisabledFeaturesServeNothing` (CI) |
| TC-980-25 | `TestIdentity_BaselineImportedWorks` (CI) |
| TC-978-26 | `TestIdentityClient_AgainstPinnedKeycloak`, subtest TC-978-26 (CI) |
| TC-978-27 | `TestIdentityClient_AgainstPinnedKeycloak`, subtest TC-978-27 (CI) |
| TC-978-28 | `TestIdentityClient_AgainstPinnedKeycloak`, subtest TC-978-28 (CI) |
| TC-978-29 | `TestIdentityClient_AgainstPinnedKeycloak`, subtest TC-978-29 (CI) |
| TC-979-01 | `TestIdentityState_DatabaseDown` (CI) |
| TC-979-02 | `TestIdentitySystemd_OutOfMemory` (CI, root step) |
| TC-979-04 | `TestIdentitySystemd_FullPartition` (CI, root step) |
| TC-1127-15 | `TestRecoverAdminTrigger_AgainstPinnedKeycloak`, subtest TC-1127-15 (CI) |
| TC-1127-16 | `TestRecoverAdminTrigger_AgainstPinnedKeycloak`, subtest TC-1127-16 (CI) |
| TC-1127-17 | `TestRecoverAdminTrigger_AgainstPinnedKeycloak`, subtest TC-1127-17 (CI) |
| TC-1127-18 | `TestRecoverAdminTrigger_AgainstPinnedKeycloak`, subtest TC-1127-18 (CI) |
