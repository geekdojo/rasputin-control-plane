# Testing against the real secret store

`TestSecretStore_SmokeWriteReadKV`, in `api/internal/secretstoretest/smoke_functional_test.go`,
runs the real, pinned secret store (OpenBao) through the `secretstoretest` harness. The unit
tests in that package pin the config the harness renders and its start and teardown paths; only
this test shows what OpenBao does with that config.

It is an **enforced gate**. The required `backend (vet + test + build)` CI job installs the
pinned binary with `scripts/install-openbao.sh` and sets `RASPUTIN_SECRETSTORE_BIN` and
`RASPUTIN_SECRETSTORE_FUNCTIONAL=required` on its `test (api with coverage)` step, so on every
PR into `main` the test must run and pass. It cannot pass by skipping
([geekdojo-brain#753](https://github.com/geekdojo/geekdojo-brain/issues/753)).

## The switch

`RASPUTIN_SECRETSTORE_BIN` names the `bao` binary. `RASPUTIN_SECRETSTORE_FUNCTIONAL` decides
what happens when it is unset or names no file. The test is never opt-in: with the binary
present it always runs.

| `RASPUTIN_SECRETSTORE_FUNCTIONAL` | Binary unset or missing | Binary present |
|---|---|---|
| `required` (exactly) | Fails, naming the variable and the missing binary | Runs; its assertions decide |
| unset, or any other value | Skips, giving the reason | Runs; its assertions decide |

The logic lives in `api/internal/functest` (`SkipOrFail`), which the appsecret and Grafana
functional tests share under their own variables.

## What it proves

On the CI runner (linux/amd64), against OpenBao v2.7.1 as pinned in
`api/internal/secretstoretest/pin.go`:

- The store starts with S8's transport: one TCP listener on 127.0.0.1, TLS, a required and
  verified client certificate trusted only from the store CA, and the unauthenticated rekey and
  generate-root endpoints disabled. Four runtime checks show the config took effect: a client
  with no certificate fails at the TLS handshake; a client whose leaf comes from a second,
  foreign store CA fails at the TLS handshake (T20); a token-less
  `GET /v1/sys/generate-root/attempt` answers 405; and a token-less `PUT /v1/sys/rekey/init`
  answers 405 (T21).
- It runs with S6's PebbleDB with clustering disabled, a static test seal, temporary storage,
  and self-init (`-config main.hcl -config init.json`), which leaves no root token.
- The store CA, the server leaf (serverAuth only, IP SAN 127.0.0.1) and the client leaf
  (clientAuth only, CN `harness-client`) come from the production store CA code
  (`api/internal/tlsca`).
- The client leaf logs in through cert auth, gets the `harness-kv` policy, and writes and reads
  back one random KV v2 value at version 1.
- Teardown leaves no process and no temporary directory, and the store stops on SIGTERM.
- No token, seal key, private key or KV value appears in the test's log.

Around it:

- `scripts/install-openbao.sh` reads the release and the sha256 out of `pin.go`, so CI
  downloads exactly what the const names, and a stale hash fails the install.
- Rows T20 to T46 of `.github/third-party-capabilities.tsv` point at the const, so changing the
  tag fails `go test ./api/internal/gatereg` until each row is re-verified at the new release.

## What it does not prove

- **arm64, or the appliance.** Nothing here covers the rasputin-os package, its unit,
  `MemoryMax=`, `LoadCredential=`, or the seal-key oneshot.
- **mlock.** OpenBao v2 removed mlock ([GH-363](https://github.com/openbao/openbao/pull/363),
  noted in the v2.7.0 changelog), so nothing here exercises it, and the config carries no
  `disable_mlock` key.
- **The rest of the listener matrix.** A wrong-EKU leaf is not run here. It rests on #679's
  evidence (row T20).
- **Production use of the store.** It does not cover the api's login
  ([geekdojo-brain#759](https://github.com/geekdojo/geekdojo-brain/issues/759)), restore
  ([geekdojo-brain#765](https://github.com/geekdojo/geekdojo-brain/issues/765)), or an audit
  device. The api's store client has its own test, and so do the production policies
  ([geekdojo-brain#804](https://github.com/geekdojo/geekdojo-brain/issues/804)), both below.
- **A clean stop when `go test` times out.** Start waits for the store's health for as long as
  its ctx allows. The test passes `t.Context()`, so a store that never becomes healthy and never
  exits (a wrong seal key, for one) is bounded only by `go test -timeout`. That timeout panics
  the test binary, and a panic runs no `Cleanup`: the `bao` process outlives the test, and its
  temporary directory stays behind. CI runners are thrown away after each run; a workstation is
  not. After a timed-out run, find a stray store and remove it:

  ```sh
  pgrep -fl 'bao server -config .*/secretstore-'
  ```

  `pgrep -f` matches the whole command line; `-l` prints it beside the PID. Each match is a
  store this harness started. Stop it with `kill <PID>`, then delete the directory its
  `-config` path names (`.../secretstore-<random>/`), which sits under the test's temporary
  directory.

## The store client's functional test

`TestClient_AgainstTheRealStore`, in `api/internal/secretstore/functional_test.go`, runs the
api's store client (`secretstore.Client`) against the same harness and binary, under the same
switch, in the same CI step. Its unit tests run the client against an `httptest` TLS 1.3 server
that requires a client certificate; this test shows the real store answers the way those fakes
do ([geekdojo-brain#758](https://github.com/geekdojo/geekdojo-brain/issues/758)). One store
serves every step, in this order, because sealing and stopping it cannot be undone:

- **Contract (T28 to T30).** The same table the unit tests run against `secretstore.Mock`:
  check-and-set 0 creates and then refuses, a stale check-and-set is `ErrCASMismatch`, a read of
  the latest and of version 1, the version metadata, and `ErrNotFound` for a path never written.
  A token the store does not know is `ErrDenied`.
- **Refused client certificate.** A client presenting no certificate, and one presenting a leaf
  from a foreign store CA with the same CommonName, both get `ErrDenied`, not `ErrUnreachable`,
  from `Health` and from `Read`.
- **Sealed (T31).** `RestartSealed` restarts the store with a fresh, wrong seal key and returns
  once `sys/health` answers 503 with `initialized=true sealed=true`. `Health` and `Read` then
  both give `ErrSealed`.
- **Stopped.** After `Close`, every method gives `ErrUnreachable`.
- **Redaction.** No sentinel value, sentinel token or the real token appears in any log record,
  error rendering, `StoreMessages` or `LogAttrs()` from the steps above.

It does not prove an uninitialised store (row T32 stays `unverified`; the client's 501 handling
is unit-tested only), login, the policy, or what systemd does with the store's unit.

Run it the same way as the smoke test, with `-run TestClient_ ./api/internal/secretstore`:

```sh
RASPUTIN_SECRETSTORE_BIN="$HOME/.cache/openbao/bao" RASPUTIN_SECRETSTORE_FUNCTIONAL=required go test -count=1 -v -run TestClient_ ./api/internal/secretstore
```

Expect `--- PASS: TestClient_AgainstTheRealStore` with one `PASS` line per step, and exit
status 0. With the binary absent and the switch set it fails, naming the variable, exactly as
the smoke test does.

## The audit rotation's functional test

`TestStoreAudit_RotateUnderLoad`, in `api/internal/storeaudit/functional_test.go`, runs the
audit rotation ([geekdojo-brain#799](https://github.com/geekdojo/geekdojo-brain/issues/799))
against the same harness and binary, under the same switch, in the same CI step. The harness
starts the store with `Config.Audit` set, which adds a declarative file audit device writing
`<root>/audit/audit.log` (`Store.AuditPath`). The rotation runs as real jobs on a real
`jobs.Runner` over a temporary ledger with in-process NATS, and the reopen is the harness's
`Store.Reload`, which sends the store SIGHUP. The threshold is 64 KiB so a few hundred writes
rotate the file. A writer makes KV writes continuously through the api's store client, and the
test waits on the writer's progress and on the rotator's own `Due` gate, never on a duration.
The steps run in order on one store:

- **Rotation under load (T38 to T41).** Three rotations, each a job that succeeded with an
  `audit file rotated` step line and INFO record. Then the audit `response` entries for the
  writer's paths, counted across the live file and every copy, equal the writes the store
  accepted, one per path: no audited response is lost across a rotation.
- **Prune on real copies.** A rotator whose cap holds only the two newest copies removes the
  older ones, oldest first.
- **Forced failure.** A rotator whose reopen does nothing waits 2 s, then rolls back: the job
  fails with the rolled-back sentence, the live path holds the original inode again, no copy
  from the attempt is left, an `alerts.Service` over the same ledger lists the `job-failed`
  alert with that sentence and no path, the ERROR record carries the job's id, and the
  response entries still equal the writes.
- **Redaction.** Neither the client token nor any KV value written appears in the log records
  or in the jobs' events.

It does not prove the production route to the store: `systemctl kill` to the sandboxed
`openbao.service`, and the store re-creating the file under the unit's filesystem protections.
That is the secrets-store bench skill's case SST-16. It also does not prove the free-space
alert against a real full disk (SST-12 there), or the image's `audit` stanza (#804).

Run it the same way as the smoke test, with `-run TestStoreAudit_ ./api/internal/storeaudit`:

```sh
RASPUTIN_SECRETSTORE_BIN="$HOME/.cache/openbao/bao" RASPUTIN_SECRETSTORE_FUNCTIONAL=required go test -count=1 -v -run TestStoreAudit_ ./api/internal/storeaudit
```

Expect `--- PASS: TestStoreAudit_RotateUnderLoad` with one `PASS` line per step, the
`audit: writes A to B, N response entries across the live file and the copies` lines
(A and B are the first and last write numbers checked; N is how many response entries
those writes left), and exit status 0.

## The readiness gate's functional test

`TestStoreGate_AgainstTheRealStore`, in `api/internal/apps/storegate_functional_test.go`, runs
the api's handling of a store that cannot serve secrets
([geekdojo-brain#760](https://github.com/geekdojo/geekdojo-brain/issues/760)) against the same
harness and binary, under the same switch, in the same CI step. It wires the real
`secretstore.Client`, a real `storestate.Monitor` and `storestate.Gate` around the HKDF secret
source, a real `jobs.Runner` with in-process NATS and a fake deploy agent, and an
`alerts.Service` with `SetStoreAlerts` set to the monitor. Nothing in it waits on a duration:
each step reads the state the store is in when it asks. The steps run in order on one store,
because each changes it:

- **Up.** No `secret-store:*` alert, and a deploy whose compose has a `${secret:}` token
  succeeds with the derived value in the deploy command.
- **Stopped.** After the harness's `Stop`, the list holds `secret-store:unreachable` (crit). The
  secret-bearing deploy fails with an error carrying `secret_store_not_ready`, no deploy command
  reaches the agent, and no DEPLOYING is announced. A deploy with no token still succeeds.
- **Restarted.** After `Restart`, which returns once `sys/health` answers 200 unsealed, the next
  list has no `secret-store:*` alert and the same deploy succeeds with the same value.
- **Sealed.** After `RestartSealed`, the list holds only `secret-store:sealed` (crit), and the
  deploy is refused with the code.
- **Copy and redaction.** No alert or job error names the vendor, and the derived value appears
  in no log record, job step or job event.

`TestSecretStore_StopAndRestartKeepData`, in
`api/internal/secretstoretest/restart_functional_test.go`, proves the two harness calls the
test above uses: `Stop` leaves the process exited and the data in place, `Restart` brings the
store back unsealed with a KV value written before the stop, `RestartSealed` still ends sealed,
and `Close` leaves no process and no temporary directory.

They do not prove the api process booting while the store is down under systemd, an
uninitialised store against the real binary (row T32 stays `unverified`), audit-blocked against
the real store (row T42 is `unverified` until
[geekdojo-brain#762](https://github.com/geekdojo/geekdojo-brain/issues/762) gives the store
audited callers), or the backup quiesce end to end
([geekdojo-brain#765](https://github.com/geekdojo/geekdojo-brain/issues/765)).

Run them the same way as the smoke test:

```sh
RASPUTIN_SECRETSTORE_BIN="$HOME/.cache/openbao/bao" RASPUTIN_SECRETSTORE_FUNCTIONAL=required go test -count=1 -v -run TestStoreGate_ ./api/internal/apps
RASPUTIN_SECRETSTORE_BIN="$HOME/.cache/openbao/bao" RASPUTIN_SECRETSTORE_FUNCTIONAL=required go test -count=1 -v -run TestSecretStore_StopAndRestart ./api/internal/secretstoretest
```

Expect `--- PASS: TestStoreGate_AgainstTheRealStore` with one `PASS` line per step, then
`--- PASS: TestSecretStore_StopAndRestartKeepData`, and exit status 0. With the binary absent and
the switch set, each fails naming the variable, exactly as the smoke test does.

## The store policy's functional test

`TestStorePolicy_AgainstTheRealStore`, in
`api/internal/secretstore/storepolicy/policy_functional_test.go`, runs the secrets store's
shipped policy text in the same harness and binary, under the same switch, in the same CI step
([geekdojo-brain#804](https://github.com/geekdojo/geekdojo-brain/issues/804)).

The text has one source, `api/internal/secretstore/storepolicy/*.hcl`. `scripts/build-release.sh`
packs those files into every api tarball as `openbao-policy/`, through
`scripts/pack-store-policy.sh`, and the release workflow refuses to publish a tarball whose copy
is missing or differs. rasputin-os installs them, and the image's self-init reads them through a
`file` source. This test starts the store with `secretstoretest.StartWith`, which creates the
`rasputin-secrets` kv-v2 mount and one cert role per policy the same way: each policy read from a
file, each role admitting only its own CommonName, carrying only its own policy, with
`token_no_default_policy` set. Two test-only roles hold half of the rotation policy each.

What it proves, against OpenBao v2.7.1:

- **Self-init leaves no recovery material.** `sys/seal-status` shows t=0 and n=0 (T35,
  TC-804-08).
- **The api's token has its own paths and nothing else.** It creates, reads, updates and deletes
  under `rasputin-secrets/data/apps/` and `data/devices/`, reads and deletes their metadata, and
  its lookup-self shows exactly `["rasputin-api"]`, with no `default` and no `root` (T37,
  TC-804-05). It gets 403 on every other path the test tries: other data, `sys/mounts`, the
  policy endpoints (list, read and write), `sys/audit`, `sys/auth`, `sys/capabilities-self`,
  `sys/tools/hash`, `sys/rotate/root`, the recovery-key and raft snapshot paths, `identity/`,
  `auth/token/create` (also asking for the rotation policy), `create-orphan`,
  `auth/token/accessors`, and writes to both cert roles. `sys/generate-root/attempt` answers
  405 instead: the listener refuses it before any policy applies (T21). Its leaf cannot log in
  against the rotation role (TC-804-06).
- **The rotation policy is the minimum.** The rotation token gets 204 on `sys/rotate/root` and
  403 on every other path above, the api's data paths included (405 on
  `sys/generate-root/attempt`, at the listener, as for the api). A sudo-only and an update-only
  policy on `sys/rotate/root` each get 403, so `update` plus `sudo` is what rotation needs
  (TC-804-07).
- **Policy text through a file source** works on the pinned release (T34).
- No token appears in the test's log.

It does not prove the image: that the tarball's files reach `/usr/share/rasputin/openbao-policy/`,
the image's `init.json`, the audit stanza, or the store under systemd. Those are rasputin-os's
tests. It does not cover the provisioner's role and policy
([geekdojo-brain#805](https://github.com/geekdojo/geekdojo-brain/issues/805)). What the rotation
token can do beyond `sys/rotate/root` is the seal rotation's functional test, below
([geekdojo-brain#830](https://github.com/geekdojo/geekdojo-brain/issues/830)).

Run it the same way as the smoke test, with `-run TestStorePolicy_`:

```sh
RASPUTIN_SECRETSTORE_BIN="$HOME/.cache/openbao/bao" RASPUTIN_SECRETSTORE_FUNCTIONAL=required go test -count=1 -v -run TestStorePolicy_ ./api/internal/secretstore/storepolicy
```

Expect `--- PASS: TestStorePolicy_AgainstTheRealStore` with one `PASS` line per test case, each
probe's status in the log, and exit status 0. The static checks on the same text
(`go test ./api/internal/secretstore/storepolicy` with no binary) and the packing script's tests
(`./scripts/test-pack-store-policy.sh`) need no store.

## The seal rotation's functional test

`TestSealRotate_AgainstTheRealStore`, in
`api/internal/secretstore/sealrotate/functional_test.go`, runs the seal-key rotation job against
the real store, under the same switch, in the same CI step
([geekdojo-brain#830](https://github.com/geekdojo/geekdojo-brain/issues/830)).

The harness starts the store with `Config.ExternalSeal`, so the seal is not in the main config: it
is a third `-config`, the fragment `seal.hcl` in the store's seal directory (`Store.SealDir`),
beside `seal-key` and an empty `rotation/`, in the shape `rasputin-seal-key.sh` writes on the
image. Self-init creates the `rasputin-secrets` mount, the api's role and the
`rasputin-seal-rotate` role from `storepolicy`'s files. The job runs on a real runner with the
real `Files`, `Gate` and `Rotator`, and the production rotation client, which mints a new store-CA
leaf for the rotation role on every handshake through the api's own mint,
`sealrotate.MintRotationLeaf`. The harness stands in for systemd: a restart is
`Stop` and then `StartNoWait`, and the rotator waits on `sys/health` itself.

What it proves, against OpenBao v2.7.1:

- **Rotation and re-wrap (TC-830-17).** Two rotations in a row each succeed as `rotated`, change
  the key id, leave `rotation/` empty and the fragment naming `seal-key` alone, and survive a cold
  stop and start, after which a canary written before the first rotation reads back (T44, T45,
  T46).
- **A second rotation with no re-wrap fails closed (TC-830-18).** With a key staged and opened
  but never re-wrapped, staging a third key with the second as previous leaves the store at 503,
  initialised and sealed, and its output names the unknown key id (T45).
- **Cold copies on either side of a rotation each open (TC-830-19).** A copy of the data
  directory, `seal-key` and the fragment, taken with the store stopped before a rotation and
  another after it, each start, unseal under their own key id and return the canary. The copy is
  put back in place of the store's own files; the identity archive's round trip is
  [geekdojo-brain#765](https://github.com/geekdojo/geekdojo-brain/issues/765)'s.
- **A run stopped part way is finished by the next (TC-830-20).** With the tree left as a run
  stopped after the Staged write (the store still running on the old key), after the Verify write,
  and after the Clean write, the next job ends `resumed`, mints no key, leaves a Clean tree under
  the newest key, and the store opens on it alone after a cold restart. The resume restarts the
  store on the Staged fragment before it re-wraps, so verify opens first time and never takes its
  retry.
- **The rotation token re-wraps and nothing else (TC-830-21).** `sys/rotate/root` answers 204
  with an empty body; its siblings under `sys/rotate` (`root/init`, `update`, `verify`, `backup`,
  `keyring`, `keyring/config`, `config`), `sys/seal`, `sys/raw/core/keyring`, `sys/key-status`,
  `sys/generate-recovery-token/attempt` and `sys/capabilities-self` answer 403; the token-less
  `sys/rekey/init` and `sys/generate-root/attempt` answer 405 at the listener (T43).
- **No key or token in the logs (TC-830-22).** Every seal key the test saw, raw, hex and base64,
  every rotation leaf key the mint made (PKCS#8, raw, hex, base64 and a PEM line), every token it
  holds, and anything shaped like a store token are absent from the captured api
  log and the store's own output.

What it does not prove:

- **systemd.** The image delivers the staged key through a `LoadCredential=` directory and the
  oneshot reads the new fragment shapes at boot. Those are rasputin-os's tests
  (`test/store-unit-functional.sh` scenario 9, `test/seal-key-test.sh`).
- **The api as a non-root user**
  ([geekdojo-brain#670](https://github.com/geekdojo/geekdojo-brain/issues/670)), which will need
  a root helper for `openbao-seal/`.

Run it the same way as the smoke test, with `-run TestSealRotate_`:

```sh
RASPUTIN_SECRETSTORE_BIN="$HOME/.cache/openbao/bao" RASPUTIN_SECRETSTORE_FUNCTIONAL=required go test -count=1 -v -run TestSealRotate_ ./api/internal/secretstore/sealrotate
```

Expect `--- PASS: TestSealRotate_AgainstTheRealStore` with one `PASS` line per test case and exit
status 0. It takes about 40 seconds: the run stopped after the Staged write, whose store was still
on the old key, first fails to open on the new key alone, waits out one `UnsealWait`, then puts
the Staged fragment back, re-wraps and opens. The unit tests in the same package need no store.

## The pin, and bumping it

`pin.go` holds `OpenBaoRelease` (`openbao/openbao:v2.7.1`) and `OpenBaoLinuxAMD64SHA256`, the
sha256 of `openbao_2.7.1_linux_amd64.tar.gz`.

- **Provenance.** The hash is copied only from an upstream `checksums.txt` whose signature has
  been verified with both GPG and cosign, as geekdojo-brain#678's `verify-signatures.sh` does.
  For v2.7.1 that record is geekdojo-brain
  `projects/rasputin/research/openbao-evidence/798/raw/signature-verification-v2.7.1.txt`, the
  #678 script run with `V=2.7.1`
  ([geekdojo-brain#798](https://github.com/geekdojo/geekdojo-brain/issues/798)). A hash taken
  from an unverified `checksums.txt` proves only that the bytes match what the download host
  served, and gatereg fires on the tag, not on the hash, so nothing else catches it.
- **A bump** changes both constants together, re-runs that signature verification for the new
  release, and re-verifies T20 to T46 at it before editing their `version` column.
- **rasputin-os.** Its `OPENBAO_VERSION` pin is kept in step by hand. Automating that sync is
  E22-breakdown F4.6 ([geekdojo-brain#769](https://github.com/geekdojo/geekdojo-brain/issues/769));
  the package itself is E22-breakdown F2.1
  ([geekdojo-brain#798](https://github.com/geekdojo/geekdojo-brain/issues/798)).

## How to run it

Run these from the repo root. Each command uses `-v` so the `PASS`, `SKIP` or `FAIL` line for
the test is printed; without it, a skipped test shows only `ok`.

You need Go. For the positive run you also need the pinned `bao` binary. On Linux x86_64,
install it with the script CI uses; it refuses any other platform:

```sh
./scripts/install-openbao.sh "$HOME/.cache/openbao"
```

It prints the download URL, `openbao_2.7.1_linux_amd64.tar.gz: OK` from `sha256sum -c`, and
`OpenBao v2.7.1 (...)`. On another platform, fetch that release's binary for your platform
yourself; the harness refuses any binary whose `bao version` is not exactly `OpenBao v2.7.1`.

**Positive: binary present, switch set.** This is what CI runs.

```sh
RASPUTIN_SECRETSTORE_BIN="$HOME/.cache/openbao/bao" RASPUTIN_SECRETSTORE_FUNCTIONAL=required go test -count=1 -v -run TestSecretStore_ ./api/internal/secretstoretest
```

Expect `--- PASS: TestSecretStore_SmokeWriteReadKV` and exit status 0.

- `-count=1` turns off Go's test cache, so the test really runs.
- `-run TestSecretStore_` runs only this test.

**Negative: binary absent, switch set.** This proves the switch makes a missing binary a
failure. `env -u` removes the variable for this one command.

```sh
env -u RASPUTIN_SECRETSTORE_BIN RASPUTIN_SECRETSTORE_FUNCTIONAL=required go test -count=1 -v -run TestSecretStore_ ./api/internal/secretstoretest
```

Expect exit status 1, `--- FAIL: TestSecretStore_SmokeWriteReadKV`, and the line
`RASPUTIN_SECRETSTORE_FUNCTIONAL=required but RASPUTIN_SECRETSTORE_BIN is not set, ...`.
Pointing `RASPUTIN_SECRETSTORE_BIN` at a path that does not exist fails the same way, naming
the path.

**Negative: binary absent, switch unset.**

```sh
env -u RASPUTIN_SECRETSTORE_BIN -u RASPUTIN_SECRETSTORE_FUNCTIONAL go test -count=1 -v -run TestSecretStore_ ./api/internal/secretstoretest
```

Expect exit status 0, `--- SKIP: TestSecretStore_SmokeWriteReadKV`, and a skip reason naming
`RASPUTIN_SECRETSTORE_BIN`.

## Test cases

The cases for geekdojo-brain#753, and where each is checked:

| ID | What | Where |
|---|---|---|
| TC-753-01 | `New` refuses an incomplete Config and does no I/O | `TestNew_RefusesIncompleteConfig` |
| TC-753-02 | The main config: S8 transport (unauthenticated-endpoint options inside the listener), PebbleDB, static seal | `TestRenderServerHCL` |
| TC-753-03 | The self-init config: policy, kv-v2 mount, cert auth, role; no root token | `TestRenderInitJSON` |
| TC-753-04 | `Start` refuses a binary that is not the pinned release | `TestStart_RefusesAnUnpinnedRelease` |
| TC-753-05 | A store that exits early: the error carries its exit status and stderr; nothing left behind | `TestStart_StoreExitsEarly` |
| TC-753-06 | ctx ends before the store is healthy; teardown still waits on SIGTERM | `TestStart_CtxEndsBeforeHealthy` |
| TC-753-07 | `Close` SIGKILLs a store that ignores SIGTERM only when its ctx has ended, with a WARN | `TestClose_KillsAStoreThatIgnoresSIGTERM` |
| TC-753-08 | `Close` is idempotent | `TestClose_Idempotent` |
| TC-753-09 | `Close` reports what it could not remove | `TestClose_ReportsResidue` |
| TC-753-10 | The package passes under `-race` with no binary; the smoke test skips | The third command above, without `-run` |
| TC-753-11 | Binary absent with the switch set fails | The second command above |
| TC-753-12 | The smoke case: real store, cert login, KV write and read, asserted teardown | `TestSecretStore_SmokeWriteReadKV`, in the `backend` job |
| TC-753-13 | No client certificate fails at the handshake; token-less generate-root answers 405 | `TestSecretStore_SmokeWriteReadKV` |
| TC-753-14 | In CI, removing the install step fails the `backend` job | A recorded run on the PR |
| TC-753-15 | Changing the const without re-verifying T20 to T41 fails gatereg | `go test ./api/internal/gatereg` with the tag edited |
| TC-753-16 | The capability rows resolve and timer-audit row K22 matches | `go test ./api/internal/gatereg` |
| TC-753-17 | The install follows the const, and a stale hash fails | The CI install step's log, and a local run with the hash edited |
| TC-753-18 | The install fails before any download when a const cannot be read | A local run with the const renamed |
| TC-753-19 | The install refuses any platform but Linux x86_64 | A local run on macOS |
| TC-753-20 | No workflow file and no CI job is added | `git diff` of `.github/workflows` on the PR |
| TC-753-21 | This document | Review |
| TC-753-22 | Coverage of the harness is at least 70%, under `-race` | The `backend` job's `api.coverage.out` |
| TC-753-23 | The PR answers SC-CP line by line | Review |
| TC-753-24 | Every gosec finding in the harness has a reviewed row | `scripts/sast-register.sh --gate` in the `sast` workflow |

The cases for geekdojo-brain#758 that this document's tests check:

| ID | What | Where |
|---|---|---|
| TC-758-26 | The harness: `RestartSealed` ends on the sealed answer or names the last one; `Token`; the smoke test rebuilt for a per-handshake leaf | `TestRestartSealed_CtxEndsBeforeSealed`, `TestCheckHealth`, `TestSecretStore_SmokeWriteReadKV`, `TestClient_AgainstTheRealStore` |
| TC-758-27 | The contract table against the real store (T28 to T30) | `TestClient_AgainstTheRealStore` |
| TC-758-28 | Sealed (T31) | `TestClient_AgainstTheRealStore` |
| TC-758-29 | Stopped | `TestClient_AgainstTheRealStore` |
| TC-758-30 | No client certificate, and a foreign-CA leaf, are `ErrDenied` | `TestClient_AgainstTheRealStore` |
| TC-758-31 | Redaction against the real store | `TestClient_AgainstTheRealStore` |
| TC-758-32 | Binary absent with the switch set fails | The `env -u` command above, with `-run TestClient_ ./api/internal/secretstore` |

The cases for geekdojo-brain#799 that this document's tests check:

| ID | What | Where |
|---|---|---|
| TC-799-27 | The harness's audit stanza is opt-in, under the harness root | `TestRenderServerHCL_AuditOptIn`, `TestStart_AuditPathUnderRoot`, `TestRenderServerHCL` |
| TC-799-29 | Rotation under load, no audited response lost | `TestStoreAudit_RotateUnderLoad` |
| TC-799-30 | Prune on real copies | `TestStoreAudit_RotateUnderLoad` |
| TC-799-31 | Forced failure: rolled back, alert, no line lost | `TestStoreAudit_RotateUnderLoad` |
| TC-799-32 | No token or KV value in the logs or job events | `TestStoreAudit_RotateUnderLoad` |

The cases for geekdojo-brain#760 that this document's tests check:

| ID | What | Where |
|---|---|---|
| TC-760-24 | The harness's `Stop` and `Restart`, with KV data surviving | `TestSecretStore_StopAndRestartKeepData`, `TestStopRestart_Refusals` |
| TC-760-25 | Store up: no alert, the deploy succeeds | `TestStoreGate_AgainstTheRealStore` |
| TC-760-26 | Store stopped: unreachable alert, the deploy refused with the code, a token-free deploy succeeds | `TestStoreGate_AgainstTheRealStore` |
| TC-760-27 | Store restarted: the alert clears, the deploy succeeds | `TestStoreGate_AgainstTheRealStore` |
| TC-760-28 | Store sealed: sealed alert, the deploy refused | `TestStoreGate_AgainstTheRealStore` |
| TC-760-29 | No vendor name in the copy, no secret in the logs or job events; required mode | `TestStoreGate_AgainstTheRealStore`, and the `env -u` command above with `-run TestStoreGate_ ./api/internal/apps` |

The cases for geekdojo-brain#804 that this document's tests check:

| ID | What | Where |
|---|---|---|
| TC-804-01 | `Names` and `Text`: exactly the two policies, the embedded bytes, an unknown name refused | `TestNamesAndText` |
| TC-804-02 | The api policy's allow-list, and six injected stanzas refused | `TestAPIPolicy_AllowList` |
| TC-804-03 | The rotation policy is one stanza; no never-grant path in either file | `TestSealRotatePolicy_AndNeverGrantPaths` |
| TC-804-04 | `StartWith` renders the roles and file sources, and refuses each bad `Bootstrap` | `TestStartWith_RendersTwoRoles`, `TestStartWith_RefusesBadBootstrap`, `TestLogin` |
| TC-804-05 | The api token's own paths and lookup-self | `TestStorePolicy_AgainstTheRealStore` |
| TC-804-06 | The api token is refused everywhere else, and cannot log in as the rotation role | `TestStorePolicy_AgainstTheRealStore` |
| TC-804-07 | The rotation token rotates and nothing else; neither half of its policy rotates | `TestStorePolicy_AgainstTheRealStore` |
| TC-804-08 | t=0 n=0 after self-init | `TestStorePolicy_AgainstTheRealStore` |
| TC-804-09 | The policy files are packed byte-equal, an empty source is refused, and the release checks each api tarball | `./scripts/test-pack-store-policy.sh`; the release workflow's `api tarballs carry the store policy` step |
