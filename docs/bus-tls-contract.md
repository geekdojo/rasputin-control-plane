# Bus TLS: the seed and file contract

The cluster bus is the controlplane's embedded NATS server on `:4222`. It now serves TLS. Nodes decide whether to trust it by checking a **pin**: the hash of one dedicated, long-lived **bus key**. The decision is recorded in [geekdojo/geekdojo-brain#448](https://github.com/geekdojo/geekdojo-brain/issues/448).

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

The agent accepts **only** the exact form above. It trims surrounding whitespace and nothing else. Hex, URL-safe base64, a missing `=`, `SHA256/` or curl's `sha256//` are all refused. A refused pin is not an outage: it is reported, and the node falls back as described in [Bad values](#bad-values).

## What a seed consumer must do

### Every node: `RASPUTIN_BUS_PIN`

Hand the value to the agent as the environment variable `RASPUTIN_BUS_PIN`, exactly as you already hand over `RASPUTIN_CP_JOIN_TOKEN`:

- **Rasputin OS:** firstboot copies the line into `/var/lib/rasputin/node.env`. The pin is public, so it needs no scrubbing and may stay in the seed.
- **Firewall:** `apply-seed` stores the value in UCI as `rasputin.main.bus_pin`, and `init.d/rasputin-agent` passes it on with `procd_append_param env RASPUTIN_BUS_PIN="$bus_pin"`. It is trust material, so it lives in `/etc/rasputin` / UCI, which survives sysupgrade. It must **not** go in the system CA bundle, because it is not a CA.
- **If the seed has no pin line** (an older seed, or a hand-written one), write nothing. The agent then dials in plaintext, as it does today, until the controlplane delivers a pin (see [below](#pin-delivery-to-nodes-enrolled-before-the-pin-existed)).

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
- Nodes enrolled earlier get the pin by delivery.

## What the api does with the key

- **Serves TLS on `:4222`** using the key, wrapped in a certificate the api self-signs at each start. The certificate is valid from 1970 to 9999, and the dates mean nothing to a node. TLS 1.3 only, and there are no client certificates (mTLS is out of scope).
- **Includes the key in the identity backup** as `bus/bus.key`. A restore puts it back, so a restored or reflashed-and-restored controlplane keeps the fleet's pin.
- **Exposes the pin to the authenticated UI:**
  - `GET /api/bus/tls` returns it as `pin` (read-only status).
  - `POST /api/bus/tokens` returns it as `busPin`. Add-node renders it into the seed from that same response.

## What the agent does with the pin

- **Choosing the pin.** It uses `RASPUTIN_BUS_PIN` if the variable is set and valid. Otherwise it reads the pin file `<RASPUTIN_AGENT_STATE_DIR>/bus/pin`, which it writes itself when a pin is delivered:
  - Rasputin OS: `/var/lib/rasputin/agent-state/bus/pin`
  - Firewall: `/etc/rasputin/agent-state/bus/pin`, already kept across sysupgrade by `keep.d`.

  **No image change is needed for the file.**
- **With a pin,** every connection is TLS. The agent verifies only that the SHA-256 of the server leaf's `SubjectPublicKeyInfo` equals the pin. It does not check a chain, a hostname or dates. If the server offers no TLS, or the key differs, the agent refuses before its join token is sent and keeps retrying on its normal reconnect schedule.
- **Without a pin,** it dials plaintext, as today.
- **On every registration** it reports `metadata.busTls`: `true` only for a TLS connection with the pin verified, `false` otherwise. An agent that predates this field omits it, and the api treats that as not TLS.

## Pin delivery to nodes enrolled before the pin existed

The api sends `rasputin.node.<id>.cmd.bus.pin` (request/reply, `proto.BusPinCmd{pin}` → `proto.BusPinAck`). The agent handles it as follows:

- **It holds no pin:** it validates the pin, saves it to the pin file (atomically) and replies `ok, reconnecting`. It then drops the current connection and re-dials over TLS. The next registration reports `busTls=true`.
- **It already holds that pin:** it replies `ok` and changes nothing.
- **It holds a different pin:** it **refuses**. Replacing a pin is key rotation, which the bus cannot serve.
- **It cannot save the pin:** it refuses and stays on its current connection.

During migration this command travels over the plaintext bus. Bryce accepted that exposure in #448.

## The migration ladder (api)

The api moves itself through three modes. Nobody calls an API to do it, and nothing moves on a timer: each step waits for facts, and the api re-checks them whenever one might have changed.

| Mode | Plaintext | Pin delivery | The api moves on when |
|---|---|---|---|
| `offer` (start) | accepted | none | the controlplane's running build is **committed** → `migrate` |
| `migrate` | accepted | to every online node not on TLS when the mode is entered, then to each node that registers without `busTls=true` | every enrolled node (online or not) reports `busTls=true`, **and** the server holds no plaintext client connection (the controlplane's own agent included), **and** no job is in flight → `require` |
| `require` | **refused by the server** | none | never; this is the end |

**What "committed" means.** Both of these must hold:

- **The job ledger has no update in flight that could still roll the controlplane back:** no queued or running `node.update` for the controlplane, and no `system.update`.
- **The controlplane's own agent says its slot is committed.** It reports this as `bootCommitted` in its `update.precheck` answer:
  - **RAUC:** the booted slot is the bootloader's primary slot, and its boot status is good.
  - **Raspberry Pi:** additionally, there is no `rauc-trial.pending` marker on the selector partition.
  - **Mock backend:** nothing is pending and the active slot is marked good.
  - **An api with no node of its own** (`RASPUTIN_SELF_NODE_ID` unset, i.e. a dev box) counts as committed. There is no A/B slot that could roll it back.
  - **An agent too old to report `bootCommitted`**, or no answer at all, counts as **not** committed.

Why pin delivery waits for commit: **a delivered pin cannot be taken back over the bus.** If the api were rolled back to a build without TLS, every pinned node would be stranded.

**When the api re-checks.** It re-evaluates when:

- a node registers;
- a client connection closes (the server's disconnect advisory);
- a job ends (which is also how a self-update's commit shows up);
- the api starts.

A time limit applies only to each check's individual calls.

**The switch to `require`** happens inside the running api. The api process, its HTTP server and its own bus connection stay up. nats-server cannot change whether it accepts plaintext on a config reload (`config reload not supported for AllowNonTLS`, checked by a test against the vendored version), so the api replaces its embedded bus server instead. In this order:

1. **Close job intake.** This happens under the same lock as the "no job in flight" check. From this point a job submit is **refused** with an error its caller can retry, and nothing is recorded. Every HTTP endpoint that submits a job answers `503` with `Retry-After`.
2. **Record `require`** in the `bus.tls_mode` setting. If that fails, job intake reopens and the bus is not touched.
3. **Replace the bus server.** The old server shuts down, which closes every client connection. A new one starts on the same port and JetStream store, with the same bus key, the same auth callout and the same disconnect-advisory wiring, and it refuses plaintext. The api's own connection is the same connection object before and after: it is sent to the new server at once, every subscription on it (the auth-callout responder, heartbeats, registrations, job events, the disconnect advisory, request replies) is re-sent, and a round trip confirms the server has them.
4. **Reopen job intake.** While steps 2 to 4 run, the auth callout refuses every node, so no node can register and trigger a job before intake reopens.

Nodes rejoin over TLS on their own reconnect loop, the controlplane's own agent included. The switch runs at most once per process, and a process that starts in `require` starts its server refusing plaintext.

**If the new server does not start** (for example, the port is taken), the api starts a server with the previous options again. The bus accepts plaintext as before, and every node reconnects. The api records `migrate` again, reopens job intake, and raises a standing security warning, `bus-tls-require-failed`. It does not try again until the api next starts: a retry on the next event would drop every node again each time it failed. **If no server starts at all**, or the api's own connection cannot rejoin, the api has no bus. It exits non-zero, as it does when the bus cannot start at boot, and the unit restarts it.

**A fresh cluster whose seeds all carry the pin** (a provisioned matched set, Add-node) never speaks plaintext, because every agent is pinned from its first boot. A freshly flashed controlplane is committed, so the first check after its own agent registers moves `offer` → `migrate` (nothing to deliver) → `require` in one pass, as soon as no job is in flight, and the bus server is replaced once. Until then the server accepts plaintext that no node uses.

**Status and the escape hatch:**

- `GET /api/bus/tls` (authenticated) is read-only. It shows the mode, the pin, the next mode, and exactly which facts hold that next mode back. `plaintextAllowed` is what the running server does, `switching` is true while the server is being replaced, and `switchFailed` names the error when a switch fell back.
- `RASPUTIN_BUS_TLS=offer|migrate|require` in `node.env` pins the mode. This is the escape hatch for a controlplane with a node that cannot speak TLS. A pinned mode never moves, and a pinned mode below `require` raises a standing security warning (`bus-tls-pinned`), like `bus-auth-off`.

## Bad values

- **An invalid pin or key in a seed is refused by the seed consumer.** Both images stop provisioning with an error rather than applying a partial seed; the firewall's `apply-seed` leaves `/etc/config/rasputin` untouched. Dropping a bad pin and carrying on would provision the node straight into plaintext. So the agent-side fallback in the next bullet only applies to a value that got past the seed (for example, a hand-edited `node.env` or UCI value).
- **An invalid `RASPUTIN_BUS_PIN` that reaches the agent** is reported as a configuration fault (it appears in the node's registration and the startup log). The agent then uses the pin file if one exists, and otherwise plaintext.
- **An unreadable pin file** is also reported as a fault, and the agent dials in plaintext.
- **An unusable `bus.key` on the controlplane** does not stop the api from starting. The bus runs **plaintext-only** and the api logs why. `GET /api/bus/tls` answers 503, and a standing `bus-tls-unavailable` warning is raised. Pinned nodes stay off the bus rather than speak plaintext.

## Checking a pin by hand

This recomputes the pin from the key file on the controlplane. It needs only `base64` and `openssl`:

```sh
base64 -d < /var/lib/rasputin/bus/bus.key \
  | openssl pkey -inform der -pubout -outform der \
  | openssl dgst -sha256 -binary | base64
```

Add `sha256/` in front of the output and compare it with the node's `RASPUTIN_BUS_PIN`. Use `base64 -D` on older macOS.
