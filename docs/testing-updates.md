# Testing the OS update workflow

Three failure scenarios exercise the Phase 2 exit-gate criterion "atomic A/B OS update demonstrably rolls back on simulated failure." All three run against the **mock backend** on a dev laptop — no real hardware required.

When the LattePanda Mu N100 + Pi 5 hardware lands, the same three scenarios run against the real **RAUC backend** with no changes to the saga or test harness.

## Setup

1. **Bootstrap PKI** (once):

   ```sh
   ./scripts/pki-init.sh --out-dir ./pki-out
   cp ./pki-out/root-ca.pem ./data/trust/root-ca.pem
   ```

2. **Start the api**:

   ```sh
   RASPUTIN_PUBLIC_BASE_URL=http://localhost:8080 \
   ./api/rasputin-api
   ```

3. **Start an agent** in mock-update mode:

   ```sh
   RASPUTIN_NODE_ID=node-dev \
   RASPUTIN_UPDATE_BACKEND=mock \
   ./agent/rasputin-agent
   ```

4. **Authenticate** so the test script has a session cookie. The simplest path for the test harness is to manually insert a session row via sqlite3 against `./data/rasputin.db`, then write the token to `./cookies.txt`. A small `scripts/dev-login.sh` may exist depending on session state.

## Running

```sh
./scripts/test-update-rollback.sh
```

The script:

1. Builds a unique mock bundle per scenario via `build-bundle.sh`
2. Uploads it to `/api/bundles`
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

Two Raspberry Pi 5 / 8GB units + custom Buildroot 2026.02 LTS image with rauc 1.15. Same partition layout described in `wiki/projects/rasputin/design/control-plane/updates.md`. The bundle producer needs a `--rauc` mode added to `scripts/build-bundle.sh` that calls `rauc bundle` instead of producing the mock JSON envelope. The saga and test harness are unchanged.

Scenario A on hardware: build a bundle whose kernel cmdline includes `panic=1 panic_on_oops=1` + an OOPS-triggering test module. Boot will fail, Pi tryboot will revert.

Scenario B on hardware: build a bundle whose `rasputin-agent.service` includes `Environment=RASPUTIN_DEV_FORCE_HEALTH_FAIL=1`. The agent's first health probe returns red.

Scenario C on hardware: `tc qdisc add dev eth0 root netem loss 100%` on the api host after step 3 starts.

## Future: CI

When we have a Pi 5 / QEMU CI environment, this harness becomes a GitHub Actions matrix job that runs all three scenarios on every PR that touches `api/internal/updater`, `agent/internal/updater`, or `proto/updates.go`.
