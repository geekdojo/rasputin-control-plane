# Testing collector trust: the Alloy probe and the bench

Every observability collector trusts the api the standard way every Rasputin HTTPS client
does: **by chain to the Mesh CA, under the cluster name, with no certificate pinned**
([geekdojo-brain#672](https://github.com/geekdojo/geekdojo-brain/issues/672)). The api's
node listener (`RASPUTIN_OBS_INGEST_ADDR`, default `:8443`) serves the api's Mesh-CA-signed
HTTPS leaf for every name. A collector presents its node's own self-signed key (or, on a
legacy node, a mesh client leaf), and the api admits it by that key.

The trust line is one constant, `collectorTrustLine` in `api/internal/obs/collector.go`, and
the auth register's C17 row anchors to it, so changing what a collector trusts fails
`scripts/auth-register.sh --gate` until the row is re-read.

The unit tests prove the rendering and the decisions. They cannot prove what Alloy does with
the config. Two functional tests cover that:

- **The Alloy probe** — local, repeatable, about a minute. Run it on any change to the
  collector's TLS config, and on every bump of the pinned Alloy image (`defaultAlloyImage`;
  the `T05` row of `.github/third-party-capabilities.tsv` records it).
- **The bench procedure** — real collectors on real nodes, run after merge on a signed dev
  build in the next bench batch.

## The Alloy probe

`TestAlloyProbe` in `api/internal/obs/collector_alloy_probe_test.go`, behind the
`alloyprobe` build tag, so a plain `go test` never runs it.

### What it proves

On the digest-pinned Alloy image, with the exact `tls_config` a collector is rendered with
(`collectorTLSConfig`), against an in-process TLS 1.3 server that requires a client
certificate:

- **Positive (TC-672-17).** Alloy presents a self-signed client pair made with the agent's
  parameters (ECDSA P-256, PKCS#8 `PRIVATE KEY` PEM, clientAuth EKU, dated 1970 to 9999),
  verifies the server's leaf by chain to a throwaway Mesh CA through `ca_file`, sends SNI equal
  to `server_name`, and delivers a `remote_write` POST to `/api/obs/ingest`. The server sees
  the generated key's SPKI.
- **No certificate pinned (TC-672-20).** The server swaps in a re-minted leaf (a fresh key,
  the same CA, the same name) and drops its connections. Alloy delivers again under the new
  serial, with no config change and no container restart.
- **Chain enforced (TC-672-18).** A leaf from a different CA gets an `x509:` error in Alloy's
  log and no delivery.
- **Name enforced (TC-672-19).** A Mesh-CA leaf for `other.rasputin.test` gets an `x509:`
  name-mismatch error and no delivery.

### What it does not prove

- The real fleet: real nodes, the real api leaf, both architectures. The bench does.
- `loki.write`. It renders the same block as `remote_write` (a unit test, TC-672-05, checks
  that byte for byte), but the probe drives only `remote_write`.
- The Linux docker route. On Linux the probe adds
  `--add-host=host.docker.internal:host-gateway`; that branch has not been run.

### How to run it

Docker must be on `PATH`. On this studio's Mac, Docker is Rancher Desktop, whose CLI lives in
`~/.rd/bin`, which is not on `PATH` by default:

```sh
# From the repo root.
# -tags=alloyprobe  compiles the probe in (it is excluded otherwise).
# -run TestAlloyProbe  runs only the probe.
# -count=1  disables the test cache, so the probe really runs.
# -v  prints each case's evidence (serials, SNI, Alloy's error line).
PATH="$HOME/.rd/bin:$PATH" go test -tags=alloyprobe -run TestAlloyProbe -count=1 -v ./api/internal/obs/
```

- The first run pulls the pinned image (tens of MB).
- With no `docker` on `PATH`, or no reachable daemon, the probe **fails**. It never skips.
- Each wait is on a fact (a delivery, a log line, or the container exiting), bounded by a
  90-second deadline that names what never happened.
- It writes its files under `$HOME/.cache/rasputin-alloy-probe`, because Docker on macOS
  bind-mounts only paths shared with its VM (`$HOME` is; the system temp dir is not).
- **Cleanup is part of the run.** It removes every container it started
  (`rasputin-alloy-probe-*`) and that directory. Confirm afterwards:

  ```sh
  PATH="$HOME/.rd/bin:$PATH" docker ps -a --filter name=rasputin-alloy-probe   # header only
  ls "$HOME/.cache/rasputin-alloy-probe"                                       # No such file or directory
  ```

## The bench procedure

### What it proves

- Real keyed collectors on the bench verify the api's real Mesh leaf by chain, under the
  cluster name, and ship metrics and logs, on **amd64 and arm64** (TC-672-26, TC-672-27).
- The upgrade migrates every keyed collector by trust drift, with no manual step, and does not
  churn legacy collectors (TC-672-25).
- A collector follows the api's leaf across an api restart without a redeploy (TC-672-28).

### What it does not prove

- Behaviour, or how much data is lost, on a node with a wrong clock. Alloy checks the leaf's
  dates against the node's clock; that is the same dependency the agent's HTTPS clients
  already carry (register row C16).
- A leaf renewal in the field (the probe's re-minted-leaf case and the unit test TC-672-14
  stand in for it).
- The firewall, which runs no collector.
- Anything on the BitScope rack.

### Scope guard

- **`bench.local` only.** Refuse to run against any other cluster. The BitScope rack is never
  used unless Bryce names it, in so many words, for this run. A general "validate on hardware"
  does not name it.
- **Resolve every node fresh, every time,** from `GET /api/nodes` (or `<node>.local`) at the
  start of each step and again after any restart. The bench has no DHCP reservations; never
  reuse an address from an earlier run.
- **Announce every disruptive action in the same message that takes it:** the update and the
  api restart.

### Prerequisites

- A signed dev build of the controlplane holding this change.
- **The operator's passkey session in real Chrome.** The agent drives the api from the page
  context of its own tab in the operator's Chrome, signed in to `https://bench.local`, using
  the mechanics in
  [`rasputin-fleet-test` §1](https://github.com/geekdojo/geekdojo-brain/blob/main/plugins/geekdojo/skills/rasputin-fleet-test/SKILL.md)
  (its own tab, never one of the operator's; `fetch(..., {credentials: 'same-origin'})` from
  the page).
- **SSH** to the controlplane and to the compute nodes. Node images ship no `openssl`, so
  nothing below runs one on a node.
- At least one **keyed** amd64 compute node and one **keyed** arm64 compute node: their agent
  has registered a collector key.

### Step 1: facts before the update

1. Obs is on: `GET /api/obs/status`.
2. Which compute nodes are keyed. For each node in `GET /api/nodes`, a keyed node is one whose
   newest successful `obs.collectors.deploy_node` job (below) has a non-empty `collectorKey`
   in its spec. Record the keyed set and the legacy set.
3. **Every node's last successful deploy time.** This is what scopes steps 3 and 5:

   ```js
   // In the agent's tab: the newest 300 collector deploy jobs, newest first.
   const jobs = await (await fetch('/api/jobs?kind=obs.collectors.deploy_node&limit=300',
     {credentials: 'same-origin'})).json();
   ```

   For each node id, the `createdAt` of its newest job with status `succeeded`.
4. The Mesh CA's trust fingerprint, computed the way `proto.MeshCAFingerprint` computes it
   (surrounding whitespace trimmed, then SHA-256). On the controlplane:

   ```sh
   # /var/lib/rasputin/trust/mesh-ca.pem is the api's Mesh CA (RASPUTIN_TRUST_DIR moves it).
   printf '%s' "$(cat /var/lib/rasputin/trust/mesh-ca.pem)" | sha256sum
   ```

   This is `fp(Mesh CA)` below.

### Step 2: update the controlplane

Announce it, then update the controlplane to the dev build through the normal update path.
Record the api's start time: the first `rasputin-api:` line of this start in
`journalctl -u rasputin-api`. Every "after the api start" below means after that time.

### Step 3: migration by trust drift (TC-672-25)

Wait for the reconcile (its first run is two minutes after start, then every five), with a
deadline of 20 minutes from the api start that names the node whose job never came. Then,
from the same jobs list:

- **Every keyed node** has exactly one successful `obs.collectors.deploy_node` job created
  after the api start, and its spec's `trustFingerprint` equals `fp(Mesh CA)`.
- **No legacy node whose last successful deploy (Step 1, item 3) was under 6 hours old at the
  api start gets a deploy job** after the api start. A legacy collector already records
  `fp(Mesh CA)`, so it is current.
- **The 6-hour safety net is expected, not a failure.** `collectorRedeployInterval` (6 h,
  `api/internal/obs/collector_jobs.go`) redeploys any collector whose last success is 6 h or
  more old. So a legacy node whose previous success was 6 h or more old at the api start may
  get a deploy job after it. Record each such job with the node's previous success time, and
  check that it, too, records `trustFingerprint = fp(Mesh CA)`.
- No manual step is taken.

### Step 4: the rendered compose, on both platforms (TC-672-26)

On one keyed amd64 node and one keyed arm64 node, over SSH:

```sh
# The compose the agent wrote for the collector (app id obs-collector).
C=/var/lib/rasputin/agent-state/apps/obs-collector/docker-compose.yml
grep -n 'ca_file' "$C"                      # two lines: ca_file = "/etc/alloy/certs/mesh-ca.pem"
grep -n 'server_name = "bench.local"' "$C"  # two lines
grep -c -E 'ca_pem|PRIVATE KEY' "$C"        # 0
docker ps --filter name=rasputin-obs-collector --format '{{.Names}} {{.Status}}'   # Up ...
```

### Step 5: the handshake works (TC-672-27)

For each node from Step 4, with `<deploy time>` its Step 3 job's `createdAt`:

1. **No certificate error since the deploy.** On the node:

   ```sh
   # <deploy time>: RFC 3339, e.g. 2026-10-02T14:05:00Z.
   docker logs --since <deploy time> rasputin-obs-collector 2>&1 | grep -c 'x509:'   # 0
   ```

2. **Fresh metrics.** VictoriaMetrics listens on the controlplane's loopback only
   (`127.0.0.1:8428`). From the Mac, forward it over SSH and query it:

   ```sh
   # -N: no remote command; -L: forward local 18428 to the controlplane's loopback 8428.
   ssh -N -L 18428:127.0.0.1:8428 root@bench.local &
   # The newest cAdvisor sample's timestamp for the node, in Unix seconds.
   curl -s http://127.0.0.1:18428/api/v1/query \
     --data-urlencode 'query=max(timestamp(container_last_seen{node_id="<node>"}))'
   kill %1
   ```

   The value is later than `<deploy time>`.
3. **Fresh log streams.** In the agent's tab:

   ```js
   // node: the node id; start: <deploy time>.
   await (await fetch('/api/obs/logs?node=<node>&start=<deploy time>&limit=5',
     {credentials: 'same-origin'})).json();
   ```

   At least one stream with `node_id=<node>` and an entry newer than `<deploy time>`.

Both amd64 and arm64 must be shown.

### Step 6: the collector follows the leaf across an api restart (TC-672-28)

1. Announce it, then restart the api on the controlplane (`systemctl restart rasputin-api`).
   Record the new start time.
2. Repeat Step 5, items 2 and 3, with the restart time in place of `<deploy time>`. Series and
   log streams for each keyed node resume after the restart.
3. **No deploy job is created after the restart for any node whose last successful deploy is
   under 6 hours old** at the restart. A deploy job for a node whose last success was 6 hours
   or more old is the safety net (Step 3); record it with the node's previous success time and
   check it records `trustFingerprint = fp(Mesh CA)`.

### Step 7: cleanup

Nothing is copied off a node, and nothing is left running: kill any SSH forward that is still
open.

### Recording

Record, in the story record and as a comment on
[geekdojo-brain#672](https://github.com/geekdojo/geekdojo-brain/issues/672):

- Step 1's facts: the keyed and legacy sets, each node's last success time, and `fp(Mesh CA)`;
- the jobs list before and after (Step 3 and Step 6), with each node's previous success time;
- the `grep` and `docker ps` output from both nodes (Step 4);
- the log count, the metric timestamp and the log query result per node (Steps 5 and 6).

A step that could not run is recorded as **not run**, with the reason; it is never recorded as
passed. State coverage by platform, for example "proven on amd64, not arm64".
