# Testing the app relay

A first-party app granted a runtime identity reaches its own secrets through a TLS Unix
socket its node's agent opens for it, never the secret store itself
([geekdojo-brain#1081](https://github.com/geekdojo/geekdojo-brain/issues/1081)). The agent
mounts the socket's directory into that app's containers, stamps the app's id on every call
that arrives on it, and carries the call over the bus to the api. The api authorizes the call
and calls the store with its own login. Three functional tests cover the parts that unit tests
cannot show.

| Test | File | Real dependencies |
|---|---|---|
| `TestAppRelay_ScopeRuleAgainstTheRealStore` | `api/internal/apprelay/functional_test.go` | OpenBao, NATS with the auth callout enforcing, the delete saga |
| `TestRelaySocket_Functional` | `agent/internal/apprelay/functional_test.go` | Unix socket, TLS 1.3, NATS |
| `TestRelayOverrideFunctional_MountStatusAndRemoval` | `agent/internal/docker/relayoverride_functional_test.go` | Docker Compose and the Docker daemon |

All three run in the required `backend (vet + test + build)` CI job on every PR into `main`.
The api test runs in the `test (api with coverage)` step, which sets
`RASPUTIN_SECRETSTORE_BIN` and `RASPUTIN_SECRETSTORE_FUNCTIONAL=required`. The two agent tests
run in the `test (remaining modules)` step, which sets `RASPUTIN_APPSECRET_FUNCTIONAL=required`.
None of them can pass by skipping.

## The switches

- The api test uses the secret store's switch, described in
  [testing-secret-store.md](testing-secret-store.md): `RASPUTIN_SECRETSTORE_BIN` names the
  pinned `bao` binary. With `RASPUTIN_SECRETSTORE_FUNCTIONAL=required` a missing binary fails
  the test. Without that setting, a missing binary skips it.
- The Compose test uses the Compose switch, described in
  [testing-appsecret-compose.md](testing-appsecret-compose.md). With
  `RASPUTIN_APPSECRET_FUNCTIONAL=required`, a missing `docker`, Compose plugin or daemon fails
  the test. Without that setting, it skips.
- The socket test has no switch. Everything it needs is in-process, so it always runs.

## What each proves

**`TestAppRelay_ScopeRuleAgainstTheRealStore`** runs the api's relay endpoint and service, as
`main` wires them, over the real secrets service and the real store chain (client, readiness
monitor, login session and repository). The store is the pinned OpenBao under the shipped
`rasputin-api` policy. The bus is the embedded NATS server with the auth callout enforcing, and
nodes N and M connect with join tokens bound to them. App A is granted and runs on N. App B is
granted and runs on M.

- A, calling from N, creates, reads, replaces and deletes its own entries under
  `apps/<A>/_runtime/`. A second create answers `exists`, and a read after the delete answers
  `not_found`.
- A runtime read of the name of a value pushed at deploy (`db-password`) answers `not_found`,
  and the pushed value is untouched. A name that tries to climb into B's tree answers
  `invalid`.
- N acting as B, which runs on M, answers `forbidden`. M acting as A, which runs on N, also
  answers `forbidden`.
- The broker refuses M a publish on N's relay subject, and a subscribe to N's reply lane.
- After A's real `app.delete` saga runs (stop, leaf teardown, relay teardown, remove,
  `destroy_secrets`), a call naming A answers `forbidden`, and each of A's runtime entries
  reads 404 at the store's metadata endpoint.
- Every reply carries a code, a message and a correlation id. No written value appears in any
  api log record, job log event or step result.

**`TestRelaySocket_Functional`** opens a real socket under the agent's `Manager`, with a
certificate from a test CA over the key the Manager generated. A real NATS server and a stub
api answer on the relay subject.

- A client that trusts only the `ca.pem` in the socket's mount directory, with server name
  `relay.rasputin.internal`, creates a secret and reads it back through the agent and the bus.
- The handshake fails for another server name, for a client that offers only TLS 1.2, and for
  a client that trusts the system roots instead of `ca.pem`.
- After a re-install with a new certificate, the next handshake presents the new certificate,
  with no restart.
- A new `Manager` that runs `Restore` serves the same app again.

**`TestRelayOverrideFunctional_MountStatusAndRemoval`** drives the real `ComposeBackend`. It
deploys a two-service compose, once with no secrets and once with a secret reference, each with
a relay directory that holds `ca.pem` and a listening socket.

- Every container mounts the directory read-only at `/run/rasputin/relay`, and `ls -l` inside
  each container shows `ca.pem` and `relay.sock`.
- `Status` reads the app running, and no service is outdated. This shows that
  `config --hash`, run with the override, equals the label `up` stamped.
- A `stop` and `start` keep the mount.
- Deploying again without the relay removes the mount and the override file, and `Status` is
  still not outdated.

## What they do not prove

- **Hardware, and the image's dockerd.** None of the three proves that a non-root container
  user can reach the socket under the OS image's daemon, or that a real first-party app
  completes a round trip. That is the bench case,
  [geekdojo-brain#1082](https://github.com/geekdojo/geekdojo-brain/issues/1082).
- **arm64.** CI runs linux/amd64. No code here is specific to one architecture.
- **The socket inside a container on macOS.** Docker Desktop shares files with its VM, but not
  Unix sockets. On macOS the Compose test checks `ca.pem` and the read-only mount, logs that it
  skipped the `relay.sock` listing, and still checks everything else. CI and every node run
  dockerd on Linux, where the socket is checked.
- **The agent and the api together.** The api test stands in for the agent with a NATS client
  bound to N. The socket test stands in for the api with a stub. Each side's half of the wire
  contract is in `proto/apprelay.go`.

## How to run them

Run these from the repo root. `-count=1` turns off Go's test cache, so each test really runs.
`-v` prints each test's `PASS`, `SKIP` or `FAIL` line; without it, a skipped test shows only
`ok`.

You need Go. The api test also needs the pinned OpenBao binary. To install it, follow step 1
of "Local secret store" in [AGENTS.md](../AGENTS.md), or run `scripts/install-openbao.sh`. The
Compose test needs `docker` on your `PATH`, with the Compose plugin and a running daemon. To
check, run `docker compose version` and `docker info`.

**The api test**, with the binary installed at `$HOME/.cache/openbao/bao`:

```sh
RASPUTIN_SECRETSTORE_BIN="$HOME/.cache/openbao/bao" RASPUTIN_SECRETSTORE_FUNCTIONAL=required \
  go test -count=1 -v -run TestAppRelay_ScopeRuleAgainstTheRealStore ./api/internal/apprelay
```

Expect `--- PASS: TestAppRelay_ScopeRuleAgainstTheRealStore` with three passing subtests, and
exit status 0.

**The socket test:**

```sh
go test -count=1 -v -run TestRelaySocket_Functional ./agent/internal/apprelay
```

Expect `--- PASS: TestRelaySocket_Functional` with four passing subtests. The test creates a
short-lived directory under `/tmp`, because a Unix socket path must fit in 104 bytes on macOS,
and removes it when it ends.

**The Compose test:**

```sh
RASPUTIN_APPSECRET_FUNCTIONAL=required \
  go test -count=1 -v -run TestRelayOverrideFunctional_ ./agent/internal/docker
```

Expect `--- PASS: TestRelayOverrideFunctional_MountStatusAndRemoval` with two passing subtests,
`plain` and `secret-bearing`. The test pulls `busybox:1.36.1` once. It starts containers in
compose projects named `rasp_<random id>` and deletes them, with their volumes, when it ends.
