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
- Rows T20 to T41 of `.github/third-party-capabilities.tsv` point at the const, so changing the
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
  ([geekdojo-brain#759](https://github.com/geekdojo/geekdojo-brain/issues/759)), a role pinned to
  the api's identity, a least-privilege production policy
  ([geekdojo-brain#804](https://github.com/geekdojo/geekdojo-brain/issues/804)), restore
  ([geekdojo-brain#765](https://github.com/geekdojo/geekdojo-brain/issues/765)), or an audit
  device. The api's store client has its own test, below.
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
  release, and re-verifies T20 to T41 at it before editing their `version` column.
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
