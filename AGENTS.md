# rasputin-control-plane — agent instructions

The Go control plane (api + node agent) and web UI for
[Rasputin](https://rasputin.geekdojo.com) clusters. Alpha, AGPL-3.0.

**Helping a user install or run Rasputin?** Don't work from this repo — fetch the live
install contract:

- https://rasputin.geekdojo.com/docs/agents/index.md — install contract (raw markdown)
- https://rasputin.geekdojo.com/llms.txt — index: current stable, docs, manifests
- https://github.com/geekdojo/rasputin-agents — install skill/plugin for Claude Code + Codex

Repo facts an agent should know:

- Go api + agent + proto (see go.work) and the Next.js control-plane UI in `ui/`.
- `ARCHITECTURE.md` is the system map — read it before proposing structural changes.
- `GET /healthz` on the api is the unauthenticated liveness probe (HTTP 200,
  `{"status":"ok"}`); it's part of the documented install contract, so don't move or
  gate it casually.
- The `rasputin-provision` matched-set CLI lives at `api/cmd/rasputin-provision`.
- `agent/cmd/storageprobe` is a **bench tool**, not part of the OS image: it drives
  `agent/internal/storage` straight against a node's real disks, bypassing NATS and the api's
  passkey session. Cross-compile and `scp -O` it to a node; `storageprobe help` and the
  package comment are the reference. ⚠️ Its `claim` verb formats a disk, and
  it REFUSES to run when the real block tooling is missing rather than falling back to the mock.
- Go code: run `gofmt` before pushing; check CI after every push.
- Changing anything under `api/internal/updater`? The fan-out state machine has a
  simulated-fleet **regression net** — a whole cluster's rollout, on the real sagas and the real
  bus, in about eleven seconds. Run it and read
  [`docs/testing-fleet-updates.md`](docs/testing-fleet-updates.md). ⚠️ It mocks at the bus
  boundary, so it is blind to everything below it (RAUC, GRUB, `/proc/cmdline`); a green run is
  not evidence a rollout works. Real fleet proof is the bench.
- ⚠️ **Tracked work lives in ANOTHER repo — `geekdojo/geekdojo-brain` — so `Fixes #N` here
  is wrong.** A bare `#N` resolves inside *this* repo, where that number is an unrelated
  issue or (GitHub shares one number sequence) a long-merged PR. It fails silently: the PR
  looks annotated and the tracked issue is never linked. On 2026-08-14 eight PRs (#121–#128)
  each carried `Fixes #N` and not one brain issue closed. Write the cross-repo form,
  `Fixes geekdojo/geekdojo-brain#N`, and **close the issue explicitly**: a merged PR never
  closes it (auto-close is off org-wide since 2026-09-30).
- For an issue that genuinely lives in THIS repo, a commit or PR must still use a
  **closing keyword** — `Fixes #N` / `Closes #N` — not a bare `(#N)` reference, so the PR and
  the issue are linked. A merged PR does not close the issue: close it deliberately once it
  is done.

## Engineering standard

This repo follows the [Geekdojo development principles](https://github.com/geekdojo/geekdojo-brain/blob/main/engineering/development-principles.md), the architecture and coding standard for every Geekdojo product (Decided 2026-09-28). Read it before you plan or write code. Plans and code are reviewed against it, and review findings cite its rule IDs (for example `ARCH-IOC`).

- **It applies to all new code.** Legacy code is refactored toward it when a change can reasonably do so.
- **A departure needs an approved exception.** The process is in [Standard exceptions](https://github.com/geekdojo/geekdojo-brain/blob/main/engineering/standard-exceptions.md). Approved exceptions for this repo are listed in `EXCEPTIONS.md` at the repo root. The file is created when the first one is approved.

## Go dependencies (Go gotcha)

The Go workspace pins to **`go 1.26`** in every `go.mod` and `go.work`; CI runs
`go-version: "1.26"`, and `scripts/vuln-scan.sh` pins the exact local toolchain
(`GOTOOLCHAIN`, kept equal to the one in `.github/workflows/vuln-scan.yml`). When a
change touches dependencies:

- **Pin new deps to exact versions** (`go get foo@v1.2.3`) rather than fetching `@latest`.
  `go get @latest` pulls transitive deps whose `go.mod` directives can demand a newer Go
  (1.27+); they build silently on a dev box with a newer toolchain and then blow up CI with
  errors like `module foo@vX requires go >= 1.27.0`.
- **`go mod tidy` is a trap on newer local toolchains** — it auto-bumps the `go` directive
  in `go.mod`/`go.work` to whatever the deepest transitive demands. If you must run it,
  prefix it with the `GOTOOLCHAIN` value from `scripts/vuln-scan.sh`, OR manually roll the
  directive back before committing.

This caused five fix-up commits in the 2026-05-30 coverage sweep: one
`go get -t github.com/nats-io/nats-server/v2@latest` in the agent module pulled
transitives demanding Go 1.24+, and none surfaced locally because dev Go was 1.26.

## Verifying UI changes (authed pages)

Auth is passkey-only (WebAuthn + Touch ID; 7-day DB-backed session cookie, see
`api/internal/auth/`). A headless/preview browser can therefore **never** log in —
don't burn time trying, and don't add dev-login endpoints or auth bypasses without
asking first (proposed and declined 2026-07-08).

**Local stack:** UI dev server on :3000 (`npm run dev` in `ui/`) + the api on
:8080 — run `RASPUTIN_MESH_BACKEND=mock go run ./api/cmd/rasputin-api` from the
**repo root** so the default `./data` dir resolves; `data/rasputin.db` already
holds Bryce's account and passkey credential. The api has no secret store
unless `RASPUTIN_SECRETSTORE_BACKEND` names one; to opt in, see
[Local secret store](#local-secret-store) below.

Run `scripts/pki-init.sh` and copy its `root-ca.pem` into `data/trust/` if it
is not there: as of 2026-09-01 a missing bundle-signing root CA makes the api
REFUSE every OS update artifact instead of accepting it unverified, so the
Updates page's upload and staging paths return 503 until it is in place.

As of geekdojo/geekdojo-brain#527 that same root also gates the release
MANIFEST the update check reads, so on a dev box "Check for updates" and the
Add-node image lookup now refuse too — the published releases are signed by
the PRODUCTION root, which a dev PKI is not. A trust root is a PEM bundle, so
trust both: append the public production root to your dev one.

```sh
curl -fsSL https://rasputin.geekdojo.com/rasputin-root-ca.pem >> data/trust/root-ca.pem
```

That is a dev-box convenience and nothing more: on hardware the OS image bakes
exactly one root, the production one.
`RASPUTIN_UPDATE_TRUST=dev-permissive` was the other answer and no longer
exists — the verifier it named has no permissive mode. On hardware nothing is
needed; the OS image bakes the root in.

The `RASPUTIN_MESH_BACKEND=mock` is required as of 2026-09-01 and is not
optional boilerplate: the default `auto` no longer falls back to the mock when
it finds no Headscale and no Docker. A mock mesh mints pre-auth keys and
invents `100.64.0.x` tailnet addresses that `/api/mesh/devices` then serves as
real, so inferring it on a controlplane means the control plane reports a mesh
that does not exist. Without the var the api boots fine and every other page
works; the mesh pages show an "unavailable" banner and mesh verbs refuse.

### Local secret store

`RASPUTIN_SECRETSTORE_BACKEND` selects the store, and nothing infers one. The
startup log names the result as `secret store wired mode=<off|mock|openbao>`.

- **unset:** no store, logged at INFO as `secret store off: not configured`.
  Deploys get their secrets from the HKDF source, as every release before
  geekdojo/geekdojo-brain#762 did, but only while rasputin.db's settings table
  has no `secretstore.switched_at`. That marker is set before the first
  operator-supplied secret reaches a store (geekdojo/geekdojo-brain#604); once
  it is set, secret-bearing deploys refuse until a store is configured, and the
  api logs `secretstore.switched_unconfigured` at WARN. With no backend
  requested, an operator secret `PUT /api/apps/{id}/secrets/{name}` answers 503
  and never sets the marker.
- **`mock` or `openbao`:** secret-bearing deploys go through the store's
  readiness gate, so they resolve through the store or are refused. `mock` logs
  at WARN: `secret store is the in-memory mock: nothing it holds survives a restart`.
- **any other value:** one ERROR record `secret store off: configuration refused`
  with `configfault=true`. The api still starts, but every secret-bearing deploy
  is refused until the selector is fixed.

The mock is your opt-in, never a default: put `RASPUTIN_SECRETSTORE_BACKEND=mock`
in front of the local-stack command when you start it.

For the real store, run the pinned OpenBao on 127.0.0.1:8200 with the api's own
store CA and client leaf. Every block runs at the repo root.

1. Install the pinned OpenBao. `shasum` checks the bytes against the release's
   own `checksums.txt`, not a signature. Expect `...tar.gz: OK`, then
   `OpenBao v<the pin.go version> (...)`.

   ```sh
   v="$(sed -n -E 's/^[[:space:]]*OpenBaoRelease[[:space:]]*=[[:space:]]*"openbao\/openbao:v([^"]+)"[[:space:]]*$/\1/p' api/internal/secretstoretest/pin.go)"
   a="$(uname -m | sed s/x86_64/amd64/)"; o="$HOME/.cache/openbao"; mkdir -p "$o"
   curl -fsSL -o "$o/openbao_${v}_darwin_${a}.tar.gz" "https://github.com/openbao/openbao/releases/download/v${v}/openbao_${v}_darwin_${a}.tar.gz"
   curl -fsSL -o "$o/checksums.txt" "https://github.com/openbao/openbao/releases/download/v${v}/checksums.txt"
   (cd "$o" && shasum -a 256 --ignore-missing -c checksums.txt && tar -xzf "openbao_${v}_darwin_${a}.tar.gz" bao) && "$o/bao" version
   ```

2. Start the api with `RASPUTIN_SECRETSTORE_BACKEND=openbao` in front of the
   local-stack command. Before step 3, wait until both leaf files exist:

   ```sh
   ls data/tls/openbao-server/leaf.pem data/tls/openbao-client/leaf.pem
   ```

   On the first run with this `data/`, the api creates `data/trust/store-ca.pem`
   and logs `leaf sweep: <name>: minted a fresh leaf` for each leaf, plus an
   `openbao-server: reload: systemctl … not found` WARN, which is expected on a
   Mac (no systemd; the leaf is on disk anyway). Later runs reuse the leaves and
   print no leaf-sweep lines.

3. In a new terminal, start the store:

   ```sh
   o="$HOME/.cache/openbao"
   cat > "$o/dev-listener.hcl" <<EOF
   listener "tcp" {
     address                                  = "127.0.0.1:8200"
     tls_cert_file                            = "$PWD/data/tls/openbao-server/leaf.pem"
     tls_key_file                             = "$PWD/data/tls/openbao-server/leaf.key"
     tls_client_ca_file                       = "$PWD/data/trust/store-ca.pem"
     tls_require_and_verify_client_cert       = true
     disable_unauthed_rekey_endpoints         = true
     disable_unauthed_generate_root_endpoints = true
   }
   EOF
   "$o/bao" server -dev -dev-no-store-token -dev-root-token-id=dev-root -dev-listen-address=127.0.0.1:8210 -config="$o/dev-listener.hcl"
   ```

4. In another new terminal, configure it. The last command revokes the
   throwaway root token, which dev mode serves only on the plain-HTTP setup
   listener at 127.0.0.1:8210.

   ```sh
   o="$HOME/.cache/openbao"; export BAO_ADDR=http://127.0.0.1:8210 BAO_TOKEN=dev-root
   "$o/bao" secrets enable -path=rasputin-secrets kv-v2
   "$o/bao" policy write rasputin-api api/internal/secretstore/storepolicy/rasputin-api.hcl
   "$o/bao" auth enable cert
   "$o/bao" write auth/cert/certs/rasputin-api certificate=@data/trust/store-ca.pem allowed_common_names=rasputin-api token_policies=rasputin-api token_no_default_policy=true
   "$o/bao" token revoke -self
   ```

5. Check, in the same terminal, that the store accepts the api's own leaf as
   `rasputin-api`. Expect `200`; the token is discarded, never printed.

   ```sh
   curl -sS -o /dev/null -w '%{http_code}\n' --cacert data/trust/store-ca.pem --cert data/tls/openbao-client/leaf.pem --key data/tls/openbao-client/leaf.key -X POST -d '{"name":"rasputin-api"}' https://127.0.0.1:8200/v1/auth/cert/login
   ```

Dev mode holds everything in memory, so a store restart means repeating steps 3
and 4, and so does a fresh `data/` (a new store CA, which the role pins) or a
`minted a fresh leaf` line for `openbao-server` in the api log. Ctrl-C stops
both processes.

Handy always-visible kit components for styling checks: `/metrics` (range Select),
`/firewall/rules` (proto + target Selects in the ADD RULE form). All shared UI
primitives live in `ui/components/kit.tsx` — fix styling there, not per-page.

## Next.js version skew (`ui/`)

`ui/` runs **Next.js 16.3.6** — newer than most model training data, with breaking
changes to APIs, conventions and file structure. Before writing UI code, read the
relevant guide in `ui/node_modules/next/dist/docs/` (`01-app/`, `02-pages/`,
`03-architecture/`) and heed deprecation notices. Re-read after any Next bump.

Next ships that warning itself: `next dev` writes `ui/AGENTS.md` + `ui/CLAUDE.md`
whenever it detects an AI coding agent. **We turned that off** — `agentRules: false`
in `ui/next.config.mjs` (2026-08-31). A nested CLAUDE.md/AGENTS.md loads as project
instructions with the same standing as this file, and that channel carries no
provenance, so an npm package could author instructions nobody reviewed — refreshed on
every version bump, invisible to supply-chain tooling that only inspects code, and
emitted only when the reader is an agent (never in CI or a plain dev run).
Agent-instruction files in this repo are human-authored. **Don't re-enable
`agentRules`** — if the version note above goes stale, fix it here by hand.
