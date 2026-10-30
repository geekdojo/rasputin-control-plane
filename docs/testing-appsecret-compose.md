# Testing app secrets against real Docker Compose

Two tests run the real `docker compose` binary:

- `TestCompose_AcceptsEscapedRefusesRawResolvesDerived`, in
  `api/internal/appsecret/compose_functional_test.go`, over what the `appsecret` package
  emits. The unit tests in that package pin the strings; only this test shows what Compose
  does with them.
- `TestSecretEnvFunctional_*`, in `agent/internal/docker/secretenv_functional_test.go`, drive
  the agent's real `ComposeBackend` through a secret-bearing deploy, where the values travel
  beside the compose and reach Compose as the process environment of `config --hash` and `up`
  only ([geekdojo-brain#776](https://github.com/geekdojo/geekdojo-brain/issues/776)).

Both are an **enforced gate**. The required `backend (vet + test + build)` CI job sets
`RASPUTIN_APPSECRET_FUNCTIONAL=required` on its `test (api with coverage)` step and its
`test (remaining modules)` step, so on every PR into `main` both must run and pass. Neither
can pass by skipping
([geekdojo-brain#695](https://github.com/geekdojo/geekdojo-brain/issues/695)).

## The switch

`RASPUTIN_APPSECRET_FUNCTIONAL` decides what happens when `docker` or the Compose plugin is
missing. The test is never opt-in: with Docker and Compose present it always runs.

| `RASPUTIN_APPSECRET_FUNCTIONAL` | Docker or Compose missing | Docker and Compose present |
|---|---|---|
| `required` (exactly) | Fails, naming the variable and the reason | Runs; its assertions decide |
| unset, or any other value | Skips, giving the reason | Runs; its assertions decide |

The api test's logic lives in `api/internal/functest` (`SkipOrFail`), which the api's Grafana
functional tests share under their own variable, `RASPUTIN_GRAFANA_FUNCTIONAL`. The agent test
inlines the same switch, because `api/internal/functest` is internal to the api module; it also
treats an unreachable Docker daemon as missing.

## What it proves

Against the Compose on the machine running it:

- Compose refuses the whole file when it holds an unescaped `${secret:x}`, with
  `invalid interpolation format`. That includes `config --volumes`, which is the volume
  gate's own call. So a token shipped to a node unescaped breaks the deploy.
- `Escape` output parses, keeps the `${secret:x}` placeholder literal, and never carries the
  derived value.
- `Resolve` output holds `${RASPUTIN_SECRET_<NAME>}` references and no value. With its value
  map as Compose's process environment it parses, and the base64url-nopad value arrives
  intact and unquoted in the service's environment; without the map the value is nowhere in
  Compose's output (TC-776-31).
- A compose the store source resolved (`StoreSource`, over a fake secrets service holding a
  value of the derived shape) parses with its map, and the stored value arrives intact
  ([geekdojo-brain#762](https://github.com/geekdojo/geekdojo-brain/issues/762), TC-762-26).
- A stored value that would change compose text if it were ever written into it (`$`,
  `${HOME}`, `$$`, another secret's reference, a newline followed by `privileged: true` and
  `volumes:`, quotes, YAML indicators) leaves the parsed model with the same key paths as a
  benign value, and reaches `SESSION_KEY` byte-exact once Compose's `$` to `$$` output escape is
  undone: Compose interpolates it once and never re-reads it
  ([geekdojo-brain#779](https://github.com/geekdojo/geekdojo-brain/issues/779), TC-779-07).

The agent test, against the Compose and daemon on the machine running it, with a fresh random
value per run and `busybox:1.36.1`:

- A deploy with the value in the map comes up running; no file under the agent's state
  directory holds the value; the container's `env` and `docker inspect` `Config.Env` do; and
  `Status` reads it running and not outdated, so the hash the deploy recorded equals the label
  `up` stamped (TC-776-26).
- A `stop` then `start` without the values leaves it running, with the value, not outdated
  (TC-776-27).
- A reference in `user:` is refused before any container exists, on a service named `web` and on
  one named `x-web` (an `x-` name is a service, not an extension field), and a deploy that fails
  at the daemon with the value in its environment does not quote the value in its detail (TC-776-28).
- Deleting the app removes its state directory, the record included (TC-776-29).
- An app deployed with its value inline, as an older api or agent leaves it, reads current, and
  moving it to the reference shape keeps its container and its value (TC-776-30).

## What it does not prove

- For the api test: that containers start or receive the variable. It runs `docker compose
  config` and `docker compose version` only, never `up`, so it pulls no image. The agent test
  does run `up`, and pulls `busybox:1.36.1` once.
- Anything about the Compose version on an appliance. CI checks the runner's Compose, which
  is not pinned and may differ from the one rasputin-os ships.
- The real secret store: that is `TestStoreSource_AgainstTheRealStore`
  (docs/testing-secret-store.md).
- That the value stays out of dockerd's container store, containerd's `meta.db` or `/proc`. It
  does not: `docker inspect` shows it, and the agent test asserts that it does.
- That dockerd's journal stays clean on a node. The guard keeps references out of the fields
  dockerd quotes back, which is what makes that so; the journal itself is measured on the
  bench.
- arm64. CI runs amd64; no code here is architecture-specific.

## How to run it

Run these from the repo root. Each command uses `-v` so the `PASS`, `SKIP` or `FAIL` line for
the test is printed; without it, a skipped test shows only `ok`.

You need Go. For the positive run you also need `docker` on your `PATH` with the Compose
plugin; check with `docker compose version`.

**Positive: real Docker and Compose, switch set.** This is what CI runs.

```sh
RASPUTIN_APPSECRET_FUNCTIONAL=required go test -count=1 -v -run TestCompose_ ./api/internal/appsecret
RASPUTIN_APPSECRET_FUNCTIONAL=required go test -count=1 -v -run TestSecretEnvFunctional_ ./agent/internal/docker
```

Expect `--- PASS: TestCompose_AcceptsEscapedRefusesRawResolvesDerived`, three
`--- PASS: TestSecretEnvFunctional_...` lines, and exit status 0 from each. The agent test
starts containers in compose projects named `rasp_<random id>` and deletes them, with their
volumes, when it ends.

- `-count=1` turns off Go's test cache, so the test really runs.
- `-run TestCompose_` runs only this test.

**Negative: Docker hidden, switch set.** This proves the switch makes a missing Docker a
failure. It narrows `PATH` to the directory holding `go` plus `/usr/bin:/bin`, so `docker` is
not found. If `docker` sits in the same directory as `go` (check with `command -v docker` and
`command -v go`), this does not hide it.

```sh
env PATH="$(dirname "$(command -v go)"):/usr/bin:/bin" RASPUTIN_APPSECRET_FUNCTIONAL=required go test -count=1 -v -run TestCompose_ ./api/internal/appsecret
```

Expect exit status 1, `--- FAIL: TestCompose_AcceptsEscapedRefusesRawResolvesDerived`, and
the line `RASPUTIN_APPSECRET_FUNCTIONAL=required but docker not on PATH: ...`.

**Negative: Docker hidden, switch unset.** The same `PATH`, without the switch.

```sh
env PATH="$(dirname "$(command -v go)"):/usr/bin:/bin" go test -count=1 -v -run TestCompose_ ./api/internal/appsecret
```

Expect exit status 0, `--- SKIP: TestCompose_AcceptsEscapedRefusesRawResolvesDerived`, and a
skip reason containing `docker not on PATH`.
