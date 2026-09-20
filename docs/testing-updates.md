# Testing the OS update workflow

> This page covers ONE node updating, against a real `rasputin-agent` process with the mock
> backend. For a whole FLEET — the canary gate, bounded fan-out, the failure budget and the
> results grid — see [`testing-fleet-updates.md`](testing-fleet-updates.md), which needs no
> running processes at all.

Three failure scenarios exercise the Phase 2 exit-gate criterion "atomic A/B OS update demonstrably rolls back on simulated failure." All three run against the **mock backend** on a dev laptop — no real hardware required.

When the LattePanda Mu N100 + Pi 5 hardware lands, the same three scenarios run against the real **RAUC backend** with no changes to the saga or test harness.

## Setup

1. **Bootstrap PKI** (once) — not optional. With no `root-ca.pem` the api refuses
   every bundle (`503`), because a missing trust root is a refusal rather than a
   downgrade to unverified. See [`pki.md`](pki.md#the-trust-root-is-required).

   ```sh
   ./scripts/pki-init.sh --out-dir ./pki-out
   cp ./pki-out/root-ca.pem ./data/trust/root-ca.pem
   ```

   This step is not optional: there is no mode that accepts an artifact
   unchecked. `pki-init.sh` mints a release leaf carrying the same purpose OID
   the release pipeline's leaf carries, so a bundle built against it verifies
   under exactly the rule the fleet enforces.

2. **Start the api**:

   ```sh
   RASPUTIN_PUBLIC_BASE_URL=http://localhost:8080 \
   RASPUTIN_BUS_AUTH=off \
   ./api/rasputin-api
   ```

   - `RASPUTIN_BUS_AUTH=off` lets the agent in step 3 join the bus without a join token.
     The bus normally refuses every connection that has no token bound to the node id it
     claims, including one from `127.0.0.1`
     ([geekdojo-brain#140](https://github.com/geekdojo/geekdojo-brain/issues/140)). A laptop
     api has no node of its own to mint a token for, so without this line the agent is
     refused with `Authorization Violation`. It is safe here because the dev api's bus
     listens on `127.0.0.1` only (`RASPUTIN_NATS_HOST` is unset). The api logs that bus auth
     is off and raises its bus-auth-off alert; both are expected.
   - To keep bus auth on instead, sign in (step 4), mint a token bound to `node-dev`, and
     give it to the agent as `RASPUTIN_CP_JOIN_TOKEN=<token>` in step 3. `<token>` is the
     `token` field of the response, which is shown only once:

     ```sh
     curl -s -b cookies.txt -H 'Content-Type: application/json' \
       -d '{"label":"laptop agent","nodeId":"node-dev","role":"compute"}' \
       http://localhost:8080/api/bus/tokens
     ```

     `-b cookies.txt` sends the session cookie from step 4, `-H` says the body is JSON and
     `-d` is the body: `nodeId` must be exactly the agent's `RASPUTIN_NODE_ID`, and `role`
     is the role the token is bound to — one of `compute`, `firewall` or `storage`. A mint
     that names no role is refused with 400, because the bus refuses a token with no role.
     `label` is free text you choose, shown in the token list.

3. **Start an agent** in mock-update mode, from the repository root:

   ```sh
   RASPUTIN_NODE_ID=node-dev \
   RASPUTIN_UPDATE_BACKEND=mock \
   RASPUTIN_BOOT_ID=laptop-boot-1 \
   ./agent/rasputin-agent
   ```

   - `RASPUTIN_NODE_ID` is the name the node registers under. The test script expects
     `node-dev`.
   - `RASPUTIN_UPDATE_BACKEND=mock` replaces RAUC with a file-backed slot model. Its state
     lives in `./agent-state/node-dev/state.json`, relative to the directory you start the
     agent from, so always start it from the same directory.
   - `RASPUTIN_BOOT_ID` is the boot identity the agent reports. Any non-empty string works;
     `laptop-boot-1` is just a label. Without it the agent reads
     `/proc/sys/kernel/random/boot_id`, which does not change while the laptop stays up and
     does not exist at all on macOS. See the next section for why this value matters.

4. **Authenticate** so the test script has a session cookie. A passkey sign-in cannot run
   headless, so the test harness inserts a session row straight into `./data/rasputin.db`.
   Run this from the repo root; the api does not need a restart:

   ```sh
   TOKEN=$(openssl rand -hex 32)
   HASH=$(printf '%s' "$TOKEN" | shasum -a 256 | cut -d ' ' -f 1)
   NOW=$(( $(date +%s) * 1000 ))
   sqlite3 ./data/rasputin.db "INSERT INTO sessions (token, token_hash, user_id, created_at, expires_at, last_active_at) SELECT '$TOKEN', '$HASH', id, $NOW, $NOW + 86400000, $NOW FROM users ORDER BY created_at LIMIT 1"
   printf 'rasputin-session=%s\n' "$TOKEN"
   ```

   - `TOKEN` is the session cookie value: 32 random bytes, hex-encoded, the same shape the
     api mints. `openssl` and `shasum` ship with macOS; on Linux use `sha256sum` in place of
     `shasum -a 256`.
   - `HASH` is the token's sha256 in hex. The api stores sessions hashed (the `token_hash`
     column) and looks them up by hash first. It still writes and accepts the plaintext
     `token` column while an A/B rollback could return to an api that only reads that
     column, so the row carries both.
   - The `SELECT ... FROM users` picks the first registered user, so the database must
     already hold an account (sign in once with a passkey through the UI).
   - `86400000` is one day in milliseconds; the row expires after that.
   - The last line prints the `Cookie` header value for `curl -H "Cookie: ..."` or the test
     script's `./cookies.txt`.

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
   curl -sS -b ./cookies.txt http://localhost:8080/api/jobs/<job-id>/steps \
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

## Running

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
