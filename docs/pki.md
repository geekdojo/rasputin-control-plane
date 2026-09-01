# Update-signing PKI

Rasputin signs every OS update bundle with a PKI we own. The keys, in increasing operational risk:

| Key | Lives | Used | Risk if lost |
|---|---|---|---|
| **Root CA** | Offline (YubiKey / vault / encrypted USB) | Once a year, to issue intermediates | Full re-image of all nodes |
| **Intermediate CA** | Release machine or sealed CI secret | Quarterly, to issue leafs | Revoke + reissue leaf set |
| **Leaf** | Build pipeline (release machine or sealed CI) | Every bundle build | Issue new leaf, ship in next OS update |

Trust on the device side: `/etc/rasputin/trust/root-ca.pem`. The api reads the same file from `$RASPUTIN_TRUST_DIR/root-ca.pem` (default `./data/trust/root-ca.pem`).

## The trust root is required

Without it the api **refuses every OS update bundle** — upload and staging return `503` naming the missing file, and nothing installs. It does not degrade to accepting bundles unverified, which is what it used to do: a missing `root-ca.pem` selected a "dev-permissive" verifier that skipped every signature check and marked the bundle `SignedBy "<unverified>"`, on the one artifact that decides what code a node boots.

The api still **starts** with no trust root — it serves `/healthz`, the UI and every other subsystem, because a control plane that won't start can't be used to fix anything (#89). Only the update path refuses.

On Rasputin hardware nothing is needed: the OS image bakes the public root at `/etc/rasputin/trust/root-ca.pem` (CI injects `vars.RASPUTIN_ROOT_CA_PEM`) and `rasputin-os`'s `tmpfiles.d` symlinks it into `/var/lib/rasputin/trust/root-ca.pem` before the api starts.

On a dev box with no PKI at all, ask for the old behaviour by name:

```sh
RASPUTIN_UPDATE_TRUST=dev-permissive go run ./api/cmd/rasputin-api
```

`require` (the default) and `dev-permissive` are the only accepted values; anything else falls back to `require`, never to permissive. Setting `dev-permissive` on a box that *does* have a `root-ca.pem` changes nothing — the root is loaded and enforced.

## One-time bootstrap

```sh
./scripts/pki-init.sh --out-dir ./pki-out
```

This produces five files in `./pki-out/`:

- `root-ca.{key,pem}` — root CA
- `intermediate-ca.{key,pem}` — issued from root
- `leaf-001.{key,pem}` — first release signing leaf, valid 90 days

Then, immediately:

1. `cp ./pki-out/root-ca.pem ./data/trust/root-ca.pem` so the api trusts it.
2. Bake `root-ca.pem` into your OS image build at `/etc/rasputin/trust/root-ca.pem`. Every node ships with this same file.
3. **Move `root-ca.key` offline.** Air-gapped USB, YubiKey, 1Password — anything that's not the same machine as the build pipeline. The api never needs the root key.
4. `intermediate-ca.key` can stay on the release machine (or a sealed CI secret). It's used by `pki-init.sh --rotate-leaf` to issue new leafs.
5. `leaf-001.{key,pem}` is what `build-bundle.sh` consumes.

## Rotation

Quarterly (or after a suspected leaf compromise):

```sh
./scripts/pki-init.sh --out-dir ./pki-out --rotate-leaf
```

This issues `leaf-002.{key,pem}` (then `-003`, etc.) under the existing intermediate. No root-CA access required. Use the new leaf in `build-bundle.sh` for the next release.

The old leaf cert remains technically valid until its 90-day expiry. To force an immediate cutover, ship an OS update that swaps the trusted keyring. RAUC supports this via its standard bundle-update mechanism; in the mock dev environment it's a no-op.

## Threat model (v0)

- **Stolen leaf key**: attacker can sign one rogue bundle. Containment: nodes only install signed bundles, so signed-by-leaf-001 is required. We rotate to leaf-002, retire leaf-001 in the next OS update's keyring.
- **Stolen intermediate key**: attacker can sign leaf-NNN themselves. Containment: requires ripping out the intermediate from the keyring → next OS update bakes in a new intermediate signed by root.
- **Stolen root key**: full breakdown. Requires manual re-image of every node from scratch with a freshly-generated trust hierarchy. This is the scenario the offline storage exists to prevent.

## v1 enhancements

- Per-installation device certs at factory provisioning time (each node has its own keypair signed by an intermediate)
- mTLS for the agent → api channel (currently the bundle download is over a content-addressed URL with no agent authentication; works because the tailnet is the network boundary)
- Hardware-backed root key (YubiHSM2, AWS CloudHSM)
