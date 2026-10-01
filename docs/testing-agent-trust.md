# Testing the agent's HTTPS trust on the bench

The node agent has three HTTPS clients that talk to the control plane's api:

- the **OS update download**: the bundle, and on the firewall its detached `.sig`
  (`agent/internal/updater`, `RAUCBackend` and `OpenWrtABBackend`);
- the **backup transfer**: a sealed volume uploaded to the api's ingest endpoint
  (`agent/internal/quiesce` over `backupxfer`);
- the **restore fetch**: a volume streamed back from the api's egress endpoint (same path).

All three trust exactly one thing: the node's mesh CA bundle, the file `mesh.enroll` installs.
There are no system roots and no pin. The bundle is read again on every request, and a missing
or unusable bundle is refused before anything is sent
([geekdojo-brain#590](https://github.com/geekdojo/geekdojo-brain/issues/590)). The unit tests
prove that logic against throwaway CAs. This page is the functional test: it proves the same
clients against the real api leaf, on real nodes, on every image.

It is run by an agent, on the bench, with the operator signed in. It is batched with a bench
cycle (see [Batching](#batching)), not run per merge.

## What it proves

- The new agent's three clients work against the api's real Mesh-CA leaf at
  `https://bench.local`, on each image's bundle path:
  - **Rasputin OS, amd64 and arm64:** the compiled default,
    `/var/lib/rasputin/mesh/tailscaled-ca.pem`.
  - **The firewall (OpenWrt):** `/etc/rasputin/mesh/tailscaled-ca.pem`, which the firewall's
    procd service passes as `RASPUTIN_MESH_CA_BUNDLE`.
- A node with no bundle refuses, and the refusal reaches the operator by name: a failed
  download step that names the bundle path, and a backup transfer refused as `backend-error`
  with the path in its detail.
- Putting the bundle back recovers without restarting the agent.

## What it does not prove

- **An update that delivers a build proves nothing about that build's download client.** The
  download is run by the agent already on the node, before the install and the reboot. So an
  update *to* the first build that holds this change exercises the *old* client. Only an update
  taken *from* a build that holds the change counts. That is why the prerequisites need two
  such builds, N and N+1.
- Anything on the BitScope rack. This procedure never runs there.
- That no fielded cluster points `RASPUTIN_PUBLIC_BASE_URL` at a host with a public-web
  certificate. Such a cluster's nodes would now refuse its api; the bench does not set it.

## Scope guard

- **`bench.local` only.** Refuse to run against any other cluster. The BitScope rack is never
  used unless Bryce names it, in so many words, for this run. A general "validate on hardware"
  does not name it.
- **Resolve every node fresh, every time.** The bench has no DHCP reservations. Take node names
  and addresses from `GET /api/nodes` or `<node>.local` at the start of each case, and again
  after any reboot. Never reuse an address from an earlier run or an earlier case.
- **Announce every disruptive action in the same message that takes it:** moving a bundle
  aside, starting an update, starting a restore.

## Prerequisites

- **Two consecutive signed builds, N and N+1, that both hold this change**, for each of:
  Rasputin OS amd64, Rasputin OS arm64, and the firewall image (which carries its own agent).
- **N is already installed on every bench node**, through the normal update path. Confirm the
  running version of each node in `GET /api/nodes` before Step 0.
- **For Case A, a build newer than the amd64 node's running build.** If that node is still on N,
  N+1 is that build. If it has already taken N+1 (in Case B, or in an earlier fleet update), you
  need a third build, N+2, that also holds the change.
- **The operator's passkey session in real Chrome.** Auth is passkey-only, so the agent drives
  the api from the page context of its own tab in the operator's Chrome, signed in to
  `https://bench.local`. Use the same mechanics as the fleet test, and don't re-derive them:
  [`rasputin-fleet-test` §1](https://github.com/geekdojo/geekdojo-brain/blob/main/plugins/geekdojo/skills/rasputin-fleet-test/SKILL.md)
  (own tab, never one of the operator's; `fetch(..., {credentials: 'same-origin'})` from the
  page).
- **SSH to the nodes**, to read a bundle path and move a file.
- **At least one app with a captured volume on one amd64 compute node and on one arm64 compute
  node** (for Case C and Case A).

## Run order

Step 0 on every node you will use, then Case C, then Case A, then Case B. Case A needs Case C's
amd64 node and Case C's record that the node's volume transfers, so Case C runs first.

## Step 0: facts for each node

For every node used below (one amd64 compute, one arm64 compute, the firewall), record:

1. **The bundle path the running agent uses.** On the node:

   ```sh
   # <agent pid>: the pid of the running rasputin-agent process (pidof rasputin-agent).
   tr '\0' '\n' < /proc/<agent pid>/environ | grep '^RASPUTIN_MESH_CA_BUNDLE='
   ```

   If the variable is absent, the path is the compiled default,
   `/var/lib/rasputin/mesh/tailscaled-ca.pem`. On the firewall it must be
   `/etc/rasputin/mesh/tailscaled-ca.pem`.
2. **The file's fingerprint**, computed the way `proto.MeshCAFingerprint` computes it
   (surrounding whitespace trimmed, then SHA-256):

   ```sh
   # <path>: the bundle path from item 1.
   printf '%s' "$(cat <path>)" | sha256sum
   ```

3. **The fingerprints agree.** The node's value must equal the node's
   `metadata.meshCaFingerprint` in `GET /api/nodes`. The field sits inside each node object's
   `metadata`, not at the node object's top level. It must also equal the same computation on
   the controlplane's own CA, `/var/lib/rasputin/trust/mesh-ca.pem` (the api's `RASPUTIN_TRUST_DIR`, if set, moves it).
   If any of the three differs, stop: the node's trust has not converged, and every case below
   would fail for that reason rather than for the one under test.

Once for the cluster, record the api's start log line
`rasputin-api: cluster identity: ... public-base-url="..."` (`journalctl -u rasputin-api` on
the controlplane). It must read `https://bench.local`. Every URL the agent is sent is built on
it.

## Case C: backup and restore through the new transport

1. Start a backup run (`POST /api/backup/runs`, or the Backups page) that covers the captured
   volumes on the amd64 node and the arm64 node.
2. The run completes with every member transferred. Record the run's result and the listing of
   the target's generation directory, and name at least one member from each of the two nodes.
   The amd64 member is Case A's precondition.
3. Announce the restore, then restore one captured volume through the app's restore
   (`POST /api/apps/{id}/restore`, or the app's page). The restore job completes, and the
   restored volume's contents match the source. Compare the bytes, not only the job status.

## Case A: fail closed, then recover

The node is **Case C's amd64 node**: it runs a build that holds the change, holds a captured
volume, and Case C recorded at least one member transferred from it. Without that record, stop:
a backup that had nothing to send from this node would "refuse" vacuously.

Below, `<newer build>` is a build that holds the change and is newer than the node's running
build (see [Prerequisites](#prerequisites)). It must be staged for the node: `GET /api/bundles`
lists it.

1. Announce the action, then move the bundle aside on the node (`<path>` from Step 0):

   ```sh
   mv <path> <path>.aside
   ```

2. Start a node update to `<newer build>` for that node only. The download step fails, and its error
   starts `rauc download: mesh CA bundle <path>:` and names the path. Record the job's step
   results (`GET /api/jobs/{id}/steps`).
3. Start a backup run covering the node's captured volume. That node's transfer is refused
   with refusal `backend-error` (`StorageRefusalBackendError`), and the bundle path is in the
   detail. The target's generation for this run holds no member from this node. Record the
   run result and the target listing.
4. Put the file back (`mv <path>.aside <path>`), and re-run both:
   - **The backup re-run** transfers the node's member. Record the run result and the target
     listing.
   - **The update re-run** to `<newer build>` reaches `committed`, with its download step
     fetched from `https://bench.local/api/bundles/<sha>` (`<sha>`: the sha256 of
     `<newer build>`'s bundle, as `GET /api/bundles` lists it).
5. **The file is present at the end, whatever happened.** If any step above fails or the run is
   abandoned, restore the file before doing anything else, and list it
   (`ls -l <path>`) as the last record of the case.

If the file reappears by itself partway through the case, that is `mesh.reconcile`
re-delivering the CA after the node re-registered, which is working as designed. Record it as
that, then run the case again from step 1.

## Case B: updates taken from a build that holds the change

Each update below stands on its own. Any update to a newer build, taken by a node already
running a build that holds the change, proves the new download client on that node's image.
It may run as a single-node update or as that node's part of a fleet Update All
(`POST /api/updates/system`, or the Update page); either path counts. Case A's update does not
stand in for any of them.

1. **amd64.** Update one amd64 (n100) compute node from N to N+1. The job reaches `committed`,
   and its download step fetched from `https://bench.local/api/bundles/<sha>`. The job's
   `precheck` step reports N's image version, which shows the update started from N and not
   from a reflash. Record the node's id and architecture from `GET /api/nodes`.
2. **arm64.** Update one arm64 compute node from N to N+1, with the same checks and the same
   record as the amd64 update.
3. **The firewall.** An OS update (`component: os`) neither stages nor updates the firewall,
   so a fleet Update All of the OS leaves it on N. Stage its bundle and update it on its own:
   1. Stage the firewall bundle. Either use the Update page's equivalent action for the
      firewall, or send:

      ```http
      POST /api/updates/pull
      {"component":"fw","channel":"dev"}
      ```

      `component` `fw` is the firewall image. `channel` `dev` is the release channel the
      bench's builds come from.
   2. Check that `GET /api/bundles` lists the firewall bundle: an entry in `bundles` whose
      `version` is the firewall's N+1. Record its `sha256`. Below it is `<fw sha>`.
   3. Start the firewall update with `component` `fw`, either from the Update page or with:

      ```http
      POST /api/updates/system
      {"version":"<fw version>","component":"fw"}
      ```

      `<fw version>` is the `version` from the previous step. The job reaches `committed`.
      The firewall refuses to install without the `.sig`, so a commit already implies it
      arrived, but record the direct evidence too (next step).
   4. Show that the `.sig` was downloaded. The job record logs only the artifact URL, not the
      `.sig` URL, so the evidence is the file the agent wrote. Do this before any later
      firewall update, which prunes the file. On the firewall:

      ```sh
      ls -l /etc/rasputin/agent-state/updater/bundles/
      sha256sum /etc/rasputin/agent-state/updater/bundles/*.rootfs.sig
      ```

      The listing shows a file ending `.rootfs.sig` next to the `.rootfs` artifact. Then hash
      the api's copy of the same signature. From the agent's own tab in the operator's Chrome
      (see [Prerequisites](#prerequisites)), in the page's console:

      ```js
      // Replace <fw sha> with the sha256 recorded in step 2.
      fetch('/api/bundles/<fw sha>/sig', {credentials: 'same-origin'})
        .then(r => r.arrayBuffer())
        .then(b => crypto.subtle.digest('SHA-256', b))
        .then(d => [...new Uint8Array(d)].map(x => x.toString(16).padStart(2, '0')).join(''))
      ```

      The two hashes must be equal. Record both, and the listing.

## Recording

For each case, record:

- the job-ledger step results (`GET /api/jobs/{id}/steps`) for every update, backup and restore;
- the Step 0 record for each node: path, the three fingerprints, and the `public-base-url` line;
- the target listings for the backup runs, and the content comparison for the restore;
- for Case A, the file listing at the end;
- for Case B, each update's `precheck` version and download URL, the node's id and
  architecture, and for the firewall the bundle listing and the two `.sig` hashes.

A case that could not run is recorded as **not run**, with the reason. It is never recorded as
passed. State coverage by platform, for example "proven on amd64 and the firewall, not arm64".

## Batching

Run this with the next bench cycle that has builds N and N+1 available, under the standing
rule that merged work is benched. It is owed on amd64, on arm64 and on the firewall, and it is
not complete until all three are recorded.
