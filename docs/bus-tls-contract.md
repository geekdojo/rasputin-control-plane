# Bus TLS: the seed and file contract

The cluster bus is the controlplane's embedded NATS server on `:4222`. It now serves TLS. Nodes decide whether to trust it by checking a **pin**: the hash of one dedicated, long-lived **bus key**. The decision is recorded in [geekdojo/geekdojo-brain#448](https://github.com/geekdojo/geekdojo-brain/issues/448).

This page is the contract between this repo (the api, the agent and `rasputin-provision`) and the repos that consume seeds:

- `rasputin-os`: `rasputin-firstboot.sh`
- `rasputin-openwrt-firewall`: `apply-seed`, UCI and `init.d/rasputin-agent`

If you change anything on this page, change the consumers in the same release.

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
- **Firewall:** `apply-seed` stores the value in UCI (proposed: `rasputin.main.bus_pin`), and `init.d/rasputin-agent` passes it on with `procd_append_param env RASPUTIN_BUS_PIN="$bus_pin"`. It is trust material, so it lives in `/etc/rasputin` / UCI, which survives sysupgrade. It must **not** go in the system CA bundle, because it is not a CA.
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
  - `GET /api/bus/tls` returns it as `pin`.
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

The setting `bus.tls_mode` can be changed with `PUT /api/bus/tls {"mode": …}`. Setting `RASPUTIN_BUS_TLS` in `node.env` pins the mode, and the api then refuses changes.

| Mode | Plaintext | Pin delivery | Moves to it when |
|---|---|---|---|
| `offer` (default) | accepted | none | always allowed |
| `migrate` | accepted | to every online node not on TLS when the mode is entered, then to each node that registers without `busTls=true` | always allowed |
| `require` | **refused by the server** | none | **only when** every inventory node, online or not, reports `busTls=true` **and** the server holds no plaintext client connection |

Changing between `require` and any other mode flips a nats-server option that cannot be reloaded, so **the api restarts itself** after saving the new mode. It uses the same exit as a prepared restore, which means any job in flight ends the way any api restart ends it. Leaving `require` is never gated, because it is the recovery path.

`offer` and `migrate` are separate steps for a reason. **A delivered pin cannot be taken back over the bus.** A pinned node refuses plaintext from then on, so rolling the controlplane back to a build without TLS would strand every pinned node. Start delivery (`migrate`) only once the controlplane build is one you are keeping.

## Bad values

- **An invalid `RASPUTIN_BUS_PIN`** is reported as a configuration fault (it appears in the node's registration and the startup log). The agent then uses the pin file if one exists, and otherwise plaintext.
- **An unreadable pin file** is also reported as a fault, and the agent dials in plaintext.
- **An unusable `bus.key` on the controlplane** does not stop the api from starting. The bus runs **plaintext-only** and the api logs why. `GET /api/bus/tls` answers 503. Pinned nodes stay off the bus rather than speak plaintext.

## Checking a pin by hand

This recomputes the pin from the key file on the controlplane. It needs only `base64` and `openssl`:

```sh
base64 -d < /var/lib/rasputin/bus/bus.key \
  | openssl pkey -inform der -pubout -outform der \
  | openssl dgst -sha256 -binary | base64
```

Add `sha256/` in front of the output and compare it with the node's `RASPUTIN_BUS_PIN`. Use `base64 -D` on older macOS.
