# Testing app secrets against real Docker Compose

`TestCompose_AcceptsEscapedRefusesRawResolvesDerived`, in
`api/internal/appsecret/compose_functional_test.go`, runs the real `docker compose` binary over
what the `appsecret` package emits. The unit tests in that package pin the strings; only this
test shows what Compose does with them.

It is an **enforced gate**. The required `backend (vet + test + build)` CI job sets
`RASPUTIN_APPSECRET_FUNCTIONAL=required` on its `test (api with coverage)` step, so on every
PR into `main` the test must run and pass. It cannot pass by skipping
([geekdojo-brain#695](https://github.com/geekdojo/geekdojo-brain/issues/695)).

## The switch

`RASPUTIN_APPSECRET_FUNCTIONAL` decides what happens when `docker` or the Compose plugin is
missing. The test is never opt-in: with Docker and Compose present it always runs.

| `RASPUTIN_APPSECRET_FUNCTIONAL` | Docker or Compose missing | Docker and Compose present |
|---|---|---|
| `required` (exactly) | Fails, naming the variable and the reason | Runs; its assertions decide |
| unset, or any other value | Skips, giving the reason | Runs; its assertions decide |

The logic lives in `api/internal/functest` (`SkipOrFail`), which the api's Grafana functional
tests share under their own variable, `RASPUTIN_GRAFANA_FUNCTIONAL`.

## What it proves

Against the Compose on the machine running it:

- Compose refuses the whole file when it holds an unescaped `${secret:x}`, with
  `invalid interpolation format`. That includes `config --volumes`, which is the volume
  gate's own call. So a token shipped to a node unescaped breaks the deploy.
- `Escape` output parses, keeps the `${secret:x}` placeholder literal, and never carries the
  derived value.
- `Resolve` output parses, and the base64url-nopad value arrives intact and unquoted.

## What it does not prove

- That containers start or receive the variable. It runs `docker compose config` and
  `docker compose version` only, never `up`, so it pulls no image and needs no network.
- Anything about the Compose version on an appliance. CI checks the runner's Compose, which
  is not pinned and may differ from the one rasputin-os ships.
- Store-backed resolution
  ([geekdojo-brain#762](https://github.com/geekdojo/geekdojo-brain/issues/762)), or carrying
  values beside the deploy command
  ([geekdojo-brain#776](https://github.com/geekdojo/geekdojo-brain/issues/776)).
- That the value stays out of `docker inspect` or `/proc`.

## How to run it

Run these from the repo root. Each command uses `-v` so the `PASS`, `SKIP` or `FAIL` line for
the test is printed; without it, a skipped test shows only `ok`.

You need Go. For the positive run you also need `docker` on your `PATH` with the Compose
plugin; check with `docker compose version`.

**Positive: real Docker and Compose, switch set.** This is what CI runs.

```sh
RASPUTIN_APPSECRET_FUNCTIONAL=required go test -count=1 -v -run TestCompose_ ./api/internal/appsecret
```

Expect `--- PASS: TestCompose_AcceptsEscapedRefusesRawResolvesDerived` and exit status 0.

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
