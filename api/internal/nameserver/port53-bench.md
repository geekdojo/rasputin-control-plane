# Port-53 coexistence bench — CP nameserver (E3 AA-2)

This is the on-image feasibility bench owed by [ADR-0004 §8](https://github.com/geekdojo/geekdojo-brain/blob/main/projects/rasputin/adr/0004-app-access-model.md).
The Go tests in this package (`go test ./internal/nameserver`) prove the
responder's *behavior*; this runbook proves the one thing they can't, because
they bind `127.0.0.1` on an unprivileged ephemeral port: that on the **real
Buildroot control-plane image**, the api's nameserver can bind the LAN IP on
**port 53** and coexist with `systemd-resolved` without breaking anything.

## What it proves (the pass criteria)

1. The api's nameserver is listening on `<CP-LAN-IP>:53` for **both UDP and TCP**.
2. `systemd-resolved`'s stub is **untouched** — still on `127.0.0.53:53`, so the
   cluster's mDNS `<cluster-id>.local` (ADR-0003) still resolves. Binding the LAN
   IP *by value* (never `0.0.0.0:53`) is what makes this true; the bench verifies
   it actually held.
3. A LAN client resolves `<cluster-id>.internal` and `<cluster-id>.local` to the
   CP's LAN IP, over UDP and TCP.
4. The negative paths are correct on the wire: NXDOMAIN in-zone, REFUSED off-zone.

If any of these fail, do **not** advance E3 past Slice 1 — the coexistence
assumption is the load-bearing one.

## Terms & placeholders (fill these in for your bench)

| Placeholder | What it is | How to find it |
|---|---|---|
| `<CP-LAN-IP>` | the control plane's LAN IPv4 | on the CP: `ip route get 8.8.8.8` → the `src` address; or read it from the api log line below |
| `<cluster-id>` | the bare cluster id, e.g. `home1` | the value of `RASPUTIN_CLUSTER_ID` in `/var/lib/rasputin/node.env` on the CP |
| `<zone>` | `<cluster-id>.internal` | derived from the two above |

Two shells are used: **[CP]** = an SSH session on the control-plane node,
**[client]** = any other host on the same LAN (your Mac is fine — it already
has `dig`).

---

## Phase 0 — optional early de-risk (run on the CURRENT image, before the nameserver ships)

This costs nothing and front-loads the only real coexistence risk — *does
anything already hold the LAN IP's port 53?* — without waiting for a nameserver
build. Run it on any existing CP-image node.

**[CP]** Confirm `systemd-resolved` binds **loopback only**, not the LAN IP:

```bash
resolvectl status | sed -n '1,12p'
# Expect a "DNS Servers" stub on 127.0.0.53 (and possibly 127.0.0.54).
# Nothing here should be <CP-LAN-IP>.

ss -H -lunp 'sport = :53'; ss -H -ltnp 'sport = :53'
# ss flags: -l listening, -u UDP, -t TCP, -n numeric ports, -p owning process,
#           -H no header. The 'sport = :53' filter limits to source port 53.
# Expect: bindings on 127.0.0.53 (systemd-resolved) only. <CP-LAN-IP>:53 MUST be
# absent — that's the address our nameserver will claim.
```

If `<CP-LAN-IP>:53` is already free (it should be — resolved uses loopback), the
coexistence design holds and the real bench below is a confirmation, not a
gamble.

---

## Phase 1 — the real bench (run after flashing an image that CONTAINS the nameserver)

Prerequisite: the CP node is running a `rasputin-os` image built from a
control-plane release that includes the nameserver (PR #80 / the first release
after it merges). `n100` (amd64) or a Pi (arm64) are equally valid — this bench
is arch-independent.

### 1. The nameserver started

**[CP]**
```bash
journalctl -u rasputin-api --no-pager | grep -i nameserver | tail -3
# Expect: "rasputin-api: nameserver authoritative for <zone> on <CP-LAN-IP>:53"
# If instead you see "nameserver not started (...)", the bind failed — read the
# error; on the real image it should NOT fail (the api has the privilege to bind
# 53). A "no LAN IPv4 to bind" here means the box has no default route.
```

### 2. The bind is on the LAN IP, resolved is untouched

**[CP]**
```bash
ss -H -lunp 'sport = :53'; ss -H -ltnp 'sport = :53'
# Expect TWO distinct owners, no clash:
#   127.0.0.53:53          users:(("systemd-resolve",...))   <- resolved stub, still there
#   <CP-LAN-IP>:53         users:(("rasputin-api",...))       <- our nameserver, UDP and TCP

resolvectl status | sed -n '1,12p'
# Expect the resolved stub unchanged from Phase 0 — proves we didn't displace it.
```

### 3. mDNS `.local` still resolves (ADR-0003 discovery intact)

**[CP]**
```bash
resolvectl query <cluster-id>.local
# Expect it to resolve via mDNS as before. Our unicast :53 answer for the same
# name (below) is additive; it must not have broken multicast resolution.
```

### 4. A LAN client resolves the names — UDP then TCP

**[client]** (`dig` flags: `@X` query server X directly; `+short` terse answer;
`+tcp` force TCP; the trailing word is the record type.)
```bash
dig @<CP-LAN-IP> <zone> A +short          # expect: <CP-LAN-IP>
dig @<CP-LAN-IP> <zone> A +short +tcp      # same answer over TCP
dig @<CP-LAN-IP> <cluster-id>.local A +short   # expect: <CP-LAN-IP>
dig @<CP-LAN-IP> <zone> SOA +short         # expect a SOA line (MNAME = <zone>.)
```

### 5. Negative paths are correct

**[client]**
```bash
dig @<CP-LAN-IP> ghost.<zone> A | grep -E 'status:'
# expect: status: NXDOMAIN   (an in-zone name that doesn't exist)

dig @<CP-LAN-IP> example.com A | grep -E 'status:'
# expect: status: REFUSED    (off-zone — we are authoritative, never recursive)
```

---

## Result

Record pass/fail for each numbered check. All green → Slice 1 is closed and the
port-53 coexistence assumption is validated on real hardware. Fold the result
into ADR-0004 §8 (replace "owed" with the bench date) and the E3 epic.

This bench is **read-only** — it starts no services and changes no config, so
there is nothing to clean up (Phase 0 runs no listener). Re-run it on any future
image change that touches the api's listeners or the OS's resolved config.
