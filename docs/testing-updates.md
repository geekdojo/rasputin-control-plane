# Testing the OS update workflow

> This page covers ONE node updating, against a real `rasputin-agent` process with the mock
> backend. For a whole FLEET — the canary gate, bounded fan-out, the failure budget and the
> results grid — see [`testing-fleet-updates.md`](testing-fleet-updates.md), which needs no
> running processes at all.
>
> The mock backend below downloads over plain http from a laptop api. The real backends'
> download client, which trusts only the node's trust bundle, is not exercised here.

Three failure scenarios exercise the Phase 2 exit-gate criterion "atomic A/B OS update demonstrably rolls back on simulated failure." All three run against the **mock backend** on a dev laptop — no real hardware required.

When the LattePanda Mu N100 + Pi 5 hardware lands, the same three scenarios run against the real **RAUC backend** with no changes to the saga or test harness.

## Setup

1. **Bootstrap PKI** (once) — not optional. With no `root-ca.pem` the api refuses
   every bundle (`503`), because a missing trust root is a refusal rather than a
   downgrade to unverified. See [`pki.md`](pki.md#the-trust-root-is-required).

   ```sh
   ./scripts/pki-init.sh --out-dir ./pki-out
   cp ./pki-out/root-ca.pem ./data/trust/root-ca.pem
   export RASPUTIN_TRUST_ROOT="$PWD/data/trust/root-ca.pem"   # in the api's shell
   ```

   This step is not optional: there is no mode that accepts an artifact
   unchecked. `pki-init.sh` mints a release leaf carrying the same purpose OID
   the release pipeline's leaf carries, so a bundle built against it verifies
   under exactly the rule the fleet enforces.

2. **Start the api** through the signed-in console recipe
   ([geekdojo-brain#989](https://github.com/geekdojo/geekdojo-brain/issues/989)): it runs the
   api built from this tree in a container with the real sign-in, and signs a synthetic
   fixture account in, so step 4 has a session. Docker (Rancher Desktop or Docker Desktop)
   must be running. From the repo root:

   ```sh
   scripts/identity-on-mac.sh up \
     --api-env RASPUTIN_HTTP_ADDR=127.0.0.1:8080 \
     --api-env RASPUTIN_NATS_PORT=4222 \
     --api-env RASPUTIN_PUBLIC_BASE_URL=http://localhost:8080 \
     --api-env RASPUTIN_BUS_AUTH=off \
     --api-env RASPUTIN_TRUST_ROOT="$PWD/data/trust/root-ca.pem"
   ```

   - Each `--api-env` is one setting for the api. The first two put its HTTP listener and
     bus on fixed loopback ports, which the agent and the test script on the Mac reach at
     `127.0.0.1` (the container shares the docker host's network, and Docker forwards its
     loopback ports to the Mac).
   - `RASPUTIN_TRUST_ROOT` is step 1's root; the repo is mounted at the same path in the
     container, so the same path works there.
   - The api's data directory is `work/api-data` in the recipe's docker volume, which the Mac
     does not see directly. Its bus pin, which step 3 reads, is read through the container:
     `docker exec rasputin-identity-on-mac sh -c 'cat "$RASPUTIN_ON_MAC_STATE/work/api-data/bus/agent.pin"'`
     (`RASPUTIN_ON_MAC_STATE` is the volume's path, set in the container by `up`; the single
     quotes make the container's shell expand it, not the Mac's).
   - The api's plain HTTP listener on `127.0.0.1:8080` serves only the bootstrap surface: it
     answers every `/api/...` request with a redirect to https. The api itself is its https
     listener, `https://ci.local` on `127.0.0.1:9443`, with a leaf the api minted from its own
     CA. Step 4 sets curl up to reach it and trust that leaf.
   - `scripts/identity-on-mac.sh down` stops and removes everything `up` started.

   - `RASPUTIN_BUS_AUTH=off` lets the agent in step 3 join the bus without a join token.
     The bus normally refuses every connection that has no token bound to the node id it
     claims, including one from `127.0.0.1`
     ([geekdojo-brain#140](https://github.com/geekdojo/geekdojo-brain/issues/140)). A laptop
     api has no node of its own to mint a token for, so without this line the agent is
     refused with `Authorization Violation`. It is safe here because the dev api's bus
     listens on `127.0.0.1` only (`RASPUTIN_NATS_HOST` is unset), and that is now a
     requirement rather than an assumption: the api **refuses to start** with
     `RASPUTIN_BUS_AUTH=off` unless the bus binds loopback, because an open bus on
     `0.0.0.0` or a LAN address lets any device that can reach the host claim any node's
     id. The api logs that bus auth is off and raises its bus-auth-off alert; both are
     expected.
   - To keep bus auth on instead, sign in (step 4) and mint a token bound to `node-dev`.
     The token is the `token` field of the response, which is shown only once:

     ```sh
     curl -s -b cookies.txt -H 'Content-Type: application/json' \
       -d '{"label":"laptop agent","nodeId":"node-dev","role":"compute"}' \
       https://ci.local/api/bus/tokens
     ```

     `-b cookies.txt` sends the session cookie from step 4 (run it in the shell where step 4
     set `CURL_HOME`), `-H` says the body is JSON and
     `-d` is the body: `nodeId` must be exactly the agent's `RASPUTIN_NODE_ID`, and `role`
     is the role the token is bound to — one of `compute`, `firewall` or `storage`. A mint
     that names no role is refused with 400, because the bus refuses a token with no role.
     `label` is free text you choose, shown in the token list.

     Save the token to a file only you can read, replacing `<token>` with the value from
     the response. `umask 077` makes the new file mode 0600:

     ```sh
     (umask 077 && printf '%s\n' '<token>' > data/node-dev.token)
     ```

     Then add `RASPUTIN_CP_JOIN_TOKEN_FILE=data/node-dev.token \` to the agent's command
     in step 3. The agent reads the file again on every connect. It reads a token from a
     file only: `RASPUTIN_CP_JOIN_TOKEN` is not read.

3. **Start an agent** in mock-update mode, from the repository root:

   ```sh
   RASPUTIN_NODE_ID=node-dev \
   RASPUTIN_BUS_PIN="$(docker exec rasputin-identity-on-mac sh -c 'cat "$RASPUTIN_ON_MAC_STATE/work/api-data/bus/agent.pin"')" \
   RASPUTIN_UPDATE_BACKEND=mock \
   RASPUTIN_BOOT_ID=laptop-boot-1 \
   ./agent/rasputin-agent
   ```

   - `RASPUTIN_NODE_ID` is the name the node registers under. The test script expects
     `node-dev`.
   - `RASPUTIN_BUS_PIN` is the pin of the api's bus key. The bus accepts only TLS, and an
     agent with no pin refuses to start: it exits with a `FATAL` line naming the variable.
     The api writes its pin to `bus/agent.pin` in its data directory on every start, so
     that file is where to read it (step 2 says why it is read through the container).
   - `RASPUTIN_UPDATE_BACKEND=mock` replaces RAUC with a file-backed slot model. Its state
     lives in `./agent-state/node-dev/state.json`, relative to the directory you start the
     agent from, so always start it from the same directory.
   - `RASPUTIN_BOOT_ID` is the boot identity the agent reports. Any non-empty string works;
     `laptop-boot-1` is just a label. Without it the agent reads
     `/proc/sys/kernel/random/boot_id`, which does not change while the laptop stays up and
     does not exist at all on macOS. See the next section for why this value matters.

4. **Authenticate** so the test script has a session cookie. Step 2 already signed the
   synthetic fixture in through the real sign-in and wrote its console session cookie to
   `data/identity-on-mac/session.cookie`. Write it as the test script's cookie jar, from the
   repo root:

   ```sh
   (umask 077 && printf 'ci.local\tFALSE\t/\tTRUE\t0\t__Host-rasputin-session\t%s\n' \
     "$(cat data/identity-on-mac/session.cookie)" > cookies.txt)
   ```

   Then point curl at the api's https listener, in the shell you run every later `curl` and
   the test script from:

   ```sh
   mkdir -p data/identity-on-mac/curl
   printf 'connect-to = "ci.local:443:127.0.0.1:9443"\ninsecure\npinnedpubkey = "sha256//%s"\n' \
     "$(cat data/identity-on-mac/api-spki)" > data/identity-on-mac/curl/.curlrc
   export CURL_HOME="$PWD/data/identity-on-mac/curl" API=https://ci.local
   curl -sS -b cookies.txt https://ci.local/api/auth/me
   ```

   - curl reads `$CURL_HOME/.curlrc` before every command. `connect-to` sends
     `https://ci.local` to the listener on `127.0.0.1:9443`, so the request still names
     `ci.local`, the name the api's leaf is for.
   - `pinnedpubkey` is how curl trusts the leaf: `data/identity-on-mac/api-spki` is the
     SHA-256 of the leaf's public key, which `up` wrote, and curl refuses any other key.
     The leaf is signed by a CA the api minted, which no trust store on the Mac holds, so
     `insecure` turns off the CA check and the pin is the whole check (curl applies a pin
     with `insecure` set).
   - `API` is the address `scripts/test-update-rollback.sh` calls; its default is the plain
     listener, which only redirects.
   - The last line answers with the fixture's `sub`, `name` and `roles`: the jar and the
     trust work.

   - The line is curl's cookie-jar format: the host, whether subdomains match, the path,
     whether it is HTTPS-only, the expiry (0 is a session cookie), the name and the value.
     `umask 077` makes the file mode 0600: it is a sign-in.
   - `__Host-rasputin-session` is the console's session cookie. A `__Host-` cookie must be
     HTTPS-only, so the fourth field is `TRUE`, and the host is `ci.local`, the api's https
     name.
   - The session lasts until `down`, a sign-out, or 7 days. Nothing is written into the api's
     database by hand: the session row is the one the real sign-in made.

## The mock does not reboot: restart the agent with a new boot id

A mock update does not complete on its own. Every staged update stops at step 6
(`wait_online_and_verify_slot`) until you restart the agent with a different
`RASPUTIN_BOOT_ID`.

**Why.** Step 6 accepts a node as updated only if the agent answering is on a *different
boot* from the one that was told to reboot (ADR-0005, conjunct (a) of the verify contract).
Step 2 (`precheck`) records the agent's boot id before the reboot command; step 6 then asks
the agent every 2 seconds and waits for a different one
(`waitForNewBoot` in `api/internal/updater/verify.go`). On real hardware the kernel issues a
new boot id on every boot. The mock backend's "reboot" only flips the slot in its state file
inside the same running process, so the agent keeps reporting the old id and keeps
answering. Setting a new `RASPUTIN_BOOT_ID` on restart is what stands in for the reboot.

**What to do**, for every update job you submit (including each scenario the script runs):

1. Submit the job (or start the script) and note the job id it prints.
2. Wait until step 6 is running. Either watch for it with:

   ```sh
   curl -sS -b ./cookies.txt https://ci.local/api/jobs/<job-id>/steps \
     | jq '.[] | {name, status}'
   ```

   where `<job-id>` is the id from step 1, and look for `wait_online_and_verify_slot` with
   status `running`. Then wait a further 5 seconds: the mock applies its simulated reboot 3
   seconds after the reboot command, and restarting before that discards it.
3. Stop the agent process (`Ctrl-C` in its terminal).
4. Start it again from the same directory with a new boot id, keeping every other variable
   the same (including `RASPUTIN_UPDATE_FAIL_MODE` if the scenario uses one):

   ```sh
   RASPUTIN_NODE_ID=node-dev \
   RASPUTIN_BUS_PIN="$(docker exec rasputin-identity-on-mac sh -c 'cat "$RASPUTIN_ON_MAC_STATE/work/api-data/bus/agent.pin"')" \
   RASPUTIN_UPDATE_BACKEND=mock \
   RASPUTIN_BOOT_ID=laptop-boot-2 \
   ./agent/rasputin-agent
   ```

   Use a value you have not used before on this run; for the next job, `laptop-boot-3`,
   and so on. The value is compared only for equality, so its content does not matter.

Step 6 then sees the new boot id within a few seconds and the saga continues to slot and
version checks and the health step.

**If you skip it.** Step 6 has a 5-minute timeout (`Timeout: 5 * time.Minute` in
`UpdateWorkflow`, `api/internal/updater/jobs.go`), counted from when that step starts, which
with the mock is a few seconds after the job starts. About 5 minutes in, the
`wait_online_and_verify_slot` step and the job end `failed`, the per-node update row
(`GET /api/updates?nodeId=node-dev`) ends `failed` rather than `committed` or `rolled_back`,
and the step error reads:

- `node never rebooted: still answering on boot <id> after context deadline exceeded` when
  the agent reported a boot id (Linux, or `RASPUTIN_BOOT_ID` set); `<id>` is the first 12
  characters of the boot id it kept reporting, or
- `node never rebooted: it answered prechecks throughout and never went quiet: context deadline exceeded`
  when it reported none (macOS without `RASPUTIN_BOOT_ID`).

This is the verify contract refusing to accept a node that has not proved it rebooted. It is
the expected result when no restart happens, not a product fault. Scenarios A and B also
depend on the restart, because both reach step 6 before their failure is detected; without
it they end `failed` instead of `rolled_back`. Scenario C fails at download and is
unaffected.

**Automated path.** `go test ./api/internal/updater -run TestFleetFunctional -count=1` runs
the real `node.update` saga, including step 6's boot-identity check, against simulated nodes
that present a new boot id when they reboot. It needs no running processes and no manual
restart. It does not exercise the agent binary or the mock backend. See
[`testing-fleet-updates.md`](testing-fleet-updates.md).

## The same applies to the REBOOT action

`RASPUTIN_UPDATE_BACKEND=mock` also makes the agent **simulate** every reboot, because a
laptop must not restart itself. It is the only setting that does, and it works only on a dev
build: an agent whose image version is a released one (no `-dev.` in it) ignores it and
reboots for real. An agent started without the mock always reboots for real, through the
one function every reboot goes through (`Reboot` in `agent/internal/system/reboot.go`). If
the node has no `reboot` command, or the command fails, the reboot fails and says so; it is
never simulated instead.

The `node.reboot` job (the REBOOT button) uses the same boot-identity check as step 6 above
(`VerifyRestart` in `api/internal/bootverify`). Against a mock agent it therefore stops at
its `wait_new_boot` step until you restart the agent with a new `RASPUTIN_BOOT_ID`, exactly
as described above, and fails after 5 minutes with
`node never rebooted: still answering on boot <id> after context deadline exceeded` if you
do not. Unlike an update, a reboot has nothing else to check, so a node that reports no boot
identity at all (macOS without `RASPUTIN_BOOT_ID`) can never pass it: set
`RASPUTIN_BOOT_ID`.

## Running

In the shell where step 4 set `CURL_HOME` and `API`:

```sh
./scripts/test-update-rollback.sh
```

The script:

1. Builds a unique mock artifact and its detached `.sig` per scenario via `build-bundle.sh`
2. Uploads the pair to `/api/bundles` as multipart, signature part first
3. Submits a `node.update` job
4. Polls the job to completion
5. Asserts the `node_updates` row's final status

**Important about `RASPUTIN_UPDATE_FAIL_MODE`**: the mock backend reads this env var at runtime (during download and reboot). To test scenarios A and B, restart the agent with the corresponding env var before running the script. Scenario C (network loss) also uses an env var but doesn't require an agent restart on its own — the mock fails the download synchronously.

| Scenario | Agent env var | What it simulates | Expected outcome |
|---|---|---|---|
| A — Kernel panic | `RASPUTIN_UPDATE_FAIL_MODE=panic` | Bootloader watchdog reverts to old slot after reboot | `rolled_back` (step 6 detects slot mismatch) |
| B — Userspace fail | `RASPUTIN_UPDATE_FAIL_MODE=health` | New slot boots, but the health check fails | `rolled_back` (step 7 sends mark-bad, agent reboots back) |
| C — Network loss | `RASPUTIN_UPDATE_FAIL_MODE=download` | `Download()` returns an error immediately | `rolled_back` / job `failed` (step 3 fails; no slot mutation) |

## When hardware arrives

Two Raspberry Pi 5 / 8GB units + custom Buildroot 2026.02 LTS image with rauc 1.15. Same partition layout described in `wiki/projects/rasputin/design/control-plane/updates.md`. The bundle producer needs a `--rauc` mode added to `scripts/build-bundle.sh` that calls `rauc bundle` instead of signing a plain blob. The saga and test harness are unchanged.

Scenario A on hardware: build a bundle whose kernel cmdline includes `panic=1 panic_on_oops=1` + an OOPS-triggering test module. Boot will fail, Pi tryboot will revert.

Scenario B on hardware: build a bundle whose `rasputin-agent.service` includes `Environment=RASPUTIN_DEV_FORCE_HEALTH_FAIL=1`. The agent's first health probe returns red.

Scenario C on hardware: `tc qdisc add dev eth0 root netem loss 100%` on the api host after step 3 starts.

## Future: CI

When we have a Pi 5 / QEMU CI environment, this harness becomes a GitHub Actions matrix job that runs all three scenarios on every PR that touches `api/internal/updater`, `agent/internal/updater`, or `proto/updates.go`.
