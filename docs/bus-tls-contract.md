# Bus TLS: the seed and file contract

The cluster bus is the controlplane's embedded NATS server on `:4222`. It accepts **only TLS**. Nodes decide whether to trust it by checking a **pin**: the hash of one dedicated, long-lived **bus key**. The decision is recorded in [geekdojo/geekdojo-brain#448](https://github.com/geekdojo/geekdojo-brain/issues/448); the plaintext migration ladder that once let an older fleet climb to TLS was deleted in [geekdojo/geekdojo-brain#517](https://github.com/geekdojo/geekdojo-brain/issues/517).

This page is the contract between this repo (the api, the agent and `rasputin-provision`) and the repos that consume seeds:

- `rasputin-os`: `rasputin-firstboot.sh`
- `rasputin-openwrt-firewall`: `apply-seed`, UCI and `init.d/rasputin-agent`

If you change anything on this page, change the consumers in the same release.

The current consumers are [rasputin-os#74](https://github.com/geekdojo/rasputin-os/pull/74) (firstboot) and [rasputin-openwrt-firewall#49](https://github.com/geekdojo/rasputin-openwrt-firewall/pull/49) (`apply-seed`, `bus-pin.sh`, `init.d/rasputin-agent`, `keep.d`). Both were merged on 2026-09-16 and implement this page as written.

## The two values

| Seed variable | In which seeds | What it is | Secret? |
|---|---|---|---|
| `RASPUTIN_BUS_PIN` | **Every** seed, the controlplane's included | `sha256/` followed by the standard, padded base64 of the SHA-256 of the bus key's DER `SubjectPublicKeyInfo`. Always 51 characters. | No |
| `RASPUTIN_BUS_KEY` | **Only** the controlplane seed | The bus private key as one line: the standard base64 of its PKCS#8 DER encoding. The key is ECDSA P-256 when we generate it. | **Yes** |

Here is an example seed line. The pin value below is a placeholder, not a real key:

```sh
RASPUTIN_BUS_PIN=sha256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
```

Both values are single lines. They use only `A-Z a-z 0-9 + / =`, so they are written **unquoted**, like `RASPUTIN_CP_JOIN_TOKEN`. Nothing in that alphabet means anything to `sh` or to UCI.

### Why this pin encoding

It is the `pin-sha256` format from HPKP ([RFC 7469 §2.4](https://www.rfc-editor.org/rfc/rfc7469#section-2.4)), and it is the value `curl --pinnedpubkey` takes (curl writes the prefix as `sha256//`). Three reasons:

- **It hashes the key, not the certificate.** The certificate around the key can be re-minted with any dates, and the pin does not change.
- **An operator can recompute it with stock openssl.** No Rasputin tooling is needed (see [Checking a pin by hand](#checking-a-pin-by-hand)).
- **The prefix names the algorithm.** If the hash ever changes, that is a new prefix, not a new meaning for an existing value.

Hex would work too, but it is 71 characters instead of 51 and matches no existing tool.

The agent accepts **only** the exact form above. It trims surrounding whitespace and nothing else. Hex, URL-safe base64, a missing `=`, `SHA256/` or curl's `sha256//` are all refused, as described in [Bad values](#bad-values).

## What a seed consumer must do

### Every node: `RASPUTIN_BUS_PIN`

Hand the value to the agent as the environment variable `RASPUTIN_BUS_PIN`, exactly as you already hand over `RASPUTIN_CP_JOIN_TOKEN`:

- **Rasputin OS:** firstboot copies the line into `/var/lib/rasputin/node.env`. The pin is public, so it needs no scrubbing and may stay in the seed.
- **Firewall:** `apply-seed` stores the value in UCI as `rasputin.main.bus_pin`, and `init.d/rasputin-agent` passes it on with `procd_append_param env RASPUTIN_BUS_PIN="$bus_pin"`. It is trust material, so it lives in `/etc/rasputin` / UCI, which survives sysupgrade. It must **not** go in the system CA bundle, because it is not a CA.
- **If the seed has no pin line** (an older seed, or a hand-written one), write nothing. The agent then uses the pin file an earlier agent saved, if the node has one (see [below](#what-the-agent-does-with-the-pin)). A node with no pin anywhere cannot join: the bus accepts only TLS, and the agent refuses to dial without a pin.

### Controlplane only: `RASPUTIN_BUS_KEY`

1. Write the value **verbatim**, followed by one newline, to `/var/lib/rasputin/bus/bus.key` with mode `0600`. Create `/var/lib/rasputin/bus/` if it is missing; firstboot already does this for the token preseed. **Do not decode it**: the api reads this exact one-line form.
2. **Do not overwrite an existing `bus.key`.** Every node pins that key, so replacing it strands the fleet. Firstboot only runs on a fresh persistent partition, so in practice the file is not there yet.
3. **Do not put `RASPUTIN_BUS_KEY` into `node.env`.** The api never reads it from the environment.
4. **Scrub it from the seed** after the write succeeds. Use the same sed-and-rewrite step that already scrubs `RASPUTIN_CP_JOIN_TOKEN`, leaving `RASPUTIN_BUS_KEY=` with an empty value. As with the token, a failed scrub must never fail provisioning.
5. Also copy `RASPUTIN_BUS_PIN` into `node.env`, as for any other node. The controlplane's own agent dials `127.0.0.1` and pins the key too.

Also note:

- The api sets the file to `0600` if it finds it readable by anyone else.
- The api also accepts a PEM `PRIVATE KEY` or `EC PRIVATE KEY` block in that file, for an operator who made a key with openssl. It only ever writes the one-line form.

### If the controlplane seed has no key

The api generates a key on first start, writes it to `/var/lib/rasputin/bus/bus.key` and logs the pin. After that:

- Add-node puts the live pin into every seed it mints.
- The controlplane's own agent reads it from `bus/agent.pin` (below).

## What the api does with the key

- **Serves TLS on `:4222`** using the key, wrapped in the persisted bus certificate (below). TLS 1.3 only, and there are no client certificates (mTLS is out of scope).
- **Includes the key in the identity backup** as `bus/bus.key`. A restore puts it back, so a restored or reflashed-and-restored controlplane keeps the fleet's pin.
- **Exposes the pin to the authenticated UI:**
  - `GET /api/bus/tls` returns `{"pin": "sha256/…"}`, and nothing else.
  - `POST /api/bus/tokens` returns it as `busPin`. Add-node renders it into the seed from that same response.

## The bus certificate

`/var/lib/rasputin/bus/bus.crt` is the certificate the key is served in. One PEM `CERTIFICATE` block, mode `0644` inside the `0700` bus directory: it holds the bus public key and nothing else, and a container user reads it.

- **It is persisted.** The api mints it once, on the first start that finds no file, and serves the same bytes on every start after that. It used to be re-minted, with a fresh random serial, every time the api started.
- **It carries a fixed DNS SAN: `rasputin-bus`.** The same value on every cluster. Nothing resolves it — a node reaches the bus by address and verifies the server by the pin alone, checking no chain, no name and no dates. The SAN is for clients that cannot be told to do that. Go's `crypto/tls` matches the name against SANs only and does not fall back to the Common Name, so a certificate with `CN=rasputin-bus` and no SAN is "not valid for any names" to anything that verifies it at all — measured against Alloy v1.4.2 on a certificate of exactly the old shape ([geekdojo-brain#467](https://github.com/geekdojo/geekdojo-brain/issues/467)).
- **Dates:** 1970-01-01 to 9999-12-31, as before. 9999-12-31 is RFC 5280's "no well-defined expiration".
- **It is re-minted, with the reason logged, when the persisted file is not one the api would have written:** it does not parse, it wraps a different key (the key was replaced or restored), it carries no `rasputin-bus` SAN, or its `NotAfter` is not 9999-12-31. Re-minting costs nothing on the node side, because the pin is the key, and no client pins the certificate's bytes.
- **It is in the identity backup** as `bus/bus.crt`, and a restore puts it back beside the key. It is derivable from the key, so an archive without it still restores — the api mints one at the next start.
- **It is public.** It may be copied anywhere. It is not a CA and must not go in a system CA bundle.

## What the agent does with the pin

- **Choosing the pin.** It uses `RASPUTIN_BUS_PIN` if the variable is set and valid. Otherwise it reads the saved pin file `<RASPUTIN_AGENT_STATE_DIR>/bus/pin`:
  - Rasputin OS: `/var/lib/rasputin/agent-state/bus/pin`
  - Firewall: `/etc/rasputin/agent-state/bus/pin`, kept across sysupgrade by `keep.d`.

  An agent of release 2026.09.5 or older wrote that file when the controlplane delivered the pin over the bus to a node enrolled before pins existed. Nothing writes it any more, and it is still read: a node migrated in place holds its pin only there, so the file must be kept.
- **On the controlplane's own agent only,** there is a third source, read last: `/var/lib/rasputin/bus/agent.pin`, which the api writes beside its bus key on **every** start. Nobody provisions it, exactly as nobody provisions `agent.token` next to it. It exists because a controlplane that self-initialised (the `bootstrap.sh` path) has no seed, so nothing put `RASPUTIN_BUS_PIN` in its agent's environment. `RASPUTIN_BUS_PIN_FILE` overrides the path on a dev box. Other roles never read it.
- **Every connection is TLS.** The agent verifies only that the SHA-256 of the server leaf's `SubjectPublicKeyInfo` equals the pin. It does not check a chain, a hostname or dates. If the server offers no TLS, or the key differs, the agent refuses before its join token is sent and keeps retrying on its normal reconnect schedule; a refused key is logged at WARN once per distinct error.
- **With no usable pin from any source,** the agent does not dial at all. It logs one FATAL entry naming the node, each source it read and the fix, and exits non-zero; see [Bad values](#bad-values).
- **Registration** reports `tokenSource` and the node's keys (`nodeKeys`). Agents of 2026.09.5 and older also sent `busTls`; nothing reads it now.
- **Nothing in this release accepts a pin over the bus.** The `bus.pin` verb is gone from the agent and the api.

## Upgrading from a release with the ladder

- **The floor is 2026.09.5**, the last stable release that carried the plaintext ladder. A cluster below it must update through it before taking a release without the ladder: its unpinned nodes would otherwise be stranded and need reseeding. Nothing in the code enforces the floor (Bryce accepted this on 2026-09-28: Rasputin is in alpha, and early adopters may have to rebuild).
- **A recorded `bus.tls_mode` setting** is left in the settings table and never read.
- **`RASPUTIN_BUS_TLS` in `node.env`** is no longer read. Whatever its value, the bus requires TLS. The api writes one WARN entry at start naming the variable and its value; remove it from `node.env`.
- **Rolling out:** computes update before the controlplane. An api of 2026.09.5 wants `busTls=true` before it records a node's keys, so while it still runs it logs `WARN refusing node keys` for a node on the new agent and keeps whatever keys it had recorded. Once the controlplane updates, every node reconnects and re-registers, and the new api records the keys.

## Restoring onto another key

Restoring the identity backup onto a controlplane that had generated its own bus key (a reflash that self-initialised first) puts the old key back and restarts **only the api**. The api rewrites `agent.pin` with the restored pin at start. The controlplane's own agent is still running and still pinned to the key it read at its own start, so it refuses the restored key: it logs `refused the bus server's key` with the pin it holds and keeps re-dialing, but does not register. A reboot, or `systemctl restart rasputin-agent`, makes it read the rewritten file and join. Re-reading the file on every dial is tracked as [geekdojo/geekdojo-brain#669](https://github.com/geekdojo/geekdojo-brain/issues/669).

## Bad values

- **An invalid pin or key in a seed is refused by the seed consumer.** Both images stop provisioning with an error rather than applying a partial seed; the firewall's `apply-seed` leaves `/etc/config/rasputin` untouched. So the agent-side handling below only applies to a value that got past the seed (for example, a hand-edited `node.env` or UCI value).
- **An invalid `RASPUTIN_BUS_PIN` that reaches the agent** is reported as a configuration fault, and the agent falls through to the saved pin file, which is still the right pin to use while the typo is fixed.
- **No usable pin from any source fails CLOSED.** The agent does not dial the bus at all. It logs one FATAL entry naming the node, the variable, each file it read and what was wrong with it, and the fix, and exits non-zero; the unit restarts it, so the entry repeats in the journal until the pin is fixed (on the firewall, procd's respawn limit stops after ten fast exits, and `apply-seed` or a UCI change restarts it). A present-but-empty or malformed pin file counts as unusable, not absent.
- **An unusable `bus.key`, or a `bus.crt` that cannot be read or written, on the controlplane** does not stop the api from starting. The bus serves **no network listener at all**, so no node — the controlplane's own agent included — can join, and the api logs an ERROR naming the file that failed. A standing crit alert, `bus-tls-unavailable`, names that file. `GET /api/bus/tls` and `POST /api/bus/tokens` answer `503` with the code `bus_unavailable` and a correlation id, and the cause is logged under that id: a seed minted now would carry no `RASPUTIN_BUS_PIN`, and its node could not join. Restoring the identity backup puts the key and certificate back.

## Checking a pin by hand

This recomputes the pin from the key file on the controlplane. It needs only `base64` and `openssl`:

```sh
base64 -d < /var/lib/rasputin/bus/bus.key \
  | openssl pkey -inform der -pubout -outform der \
  | openssl dgst -sha256 -binary | base64
```

Add `sha256/` in front of the output and compare it with the node's `RASPUTIN_BUS_PIN`. Use `base64 -D` on older macOS.
