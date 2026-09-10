# Testing the disk-claim contract on hardware (`storageprobe`)

`agent/cmd/storageprobe` drives `agent/internal/storage`'s backend **directly against a bench
node's real disks** — enumerate, claim, mount-data, inspect — with no NATS broker, no api and no
browser in the way.

It exists because `design/storage.md` §4.8 and §6 ([geekdojo-brain#302][i302]) are safety-critical
block-device code. What they promise is about what happens to a real partition table on real
hardware — which of two identical NVMes the protected set resolves to, what a fingerprint does
when the disk underneath it changes, whether a claimed filesystem actually carries its marker
after `mkfs` — and none of that can be witnessed by a unit test. The product path to the same
verbs runs through the api, which is **passkey-only**: a WebAuthn session behind a Touch ID
prompt in a browser, which a headless bench run cannot get and must not be given a way around.

> ⚠️ **`claim` formats a disk.** This is the one verb in Rasputin that can destroy the cluster
> it is running on. Everything below assumes you have read the enumerate output first.

## It is not in the OS image

`storageprobe` is deliberately absent from `scripts/build-release.sh`'s component list. It is
cross-compiled on a laptop and copied to a node for one run:

```bash
cd agent
GOOS=linux GOARCH=arm64 go build -o /tmp/storageprobe ./cmd/storageprobe   # Pi 5
GOOS=linux GOARCH=amd64 go build -o /tmp/storageprobe ./cmd/storageprobe   # n100, CWWK
scp -O /tmp/storageprobe root@<node>.local:/tmp/
```

**The `-O` is not optional.** A Rasputin node's busybox ships no `sftp-server`, and every
OpenSSH client since 9.0 speaks SFTP by default, so a plain `scp` fails with
`subsystem request failed on channel 0`. `-O` forces the legacy SCP protocol. Same gotcha the
firewall runbook carries; it costs a round trip every time it is forgotten.

Resolve the node by name every run (`<cluster>.local`, or `/api/nodes`) — the bench has no DHCP
reservations by design, so a rebooted node's address is not the one you last saw.

## The four verbs

```bash
/tmp/storageprobe                       # enumerate — the default, read-only
/tmp/storageprobe enumerate --json
/tmp/storageprobe claim --device /dev/nvme1n1 --purpose data \
                        --fingerprint <from enumerate> --label "media" --cluster-id <id>
/tmp/storageprobe mount-data            # the §6.5 startup sweep
/tmp/storageprobe inspect --part-uuid <uuid>
```

`--json` on any of them emits the same report a script can parse. `storageprobe help` is the
full reference; `agent/cmd/storageprobe`'s package comment is the rationale.

**`enumerate` prints the protected set first, as its own block, with the reason verbatim.** That
is the headline rather than a flag on a list: on a controlplane with two identical NVMes there is
no model, size, transport or bus difference between the boot medium and the spare, so the
protection reason is the only thing in the entire output that tells them apart.

**`claim` requires `--fingerprint`, and that requirement is the guardrail.** The fingerprint
hashes the disk's stable identity together with its *current* partition table, and the agent
recomputes it against live hardware immediately before it writes anything. It does two jobs:
it forces an operator to run `enumerate` and look at the protected set first, and it makes a
stale or replayed invocation fail closed on its own — the format rewrites the partition table
the hash covers, so the same command run twice is refused the second time, with no dedup state
anywhere. An empty fingerprint is a refusal and never a wildcard.

`claim` never reports a success without the ground truth an operator has to go and check:
partition UUID, GPT name, filesystem label, mount path *and options*, and the marker path. If
the ack cannot supply them the run is reported as a failure, whatever the backend said — the
suggested recovery is `enumerate` again, because a claimed disk is self-describing.

## The mock is never inferred

The real backend needs util-linux on `PATH`. When any of it is missing `storageprobe` **refuses
and names the missing tool** (exit 3); it does not fall back to `MockBackend`, and
`RASPUTIN_STORAGE_BACKEND` is deliberately not read here — a bench run inherits the environment
of whatever shell started it.

That is the 2026-09-01 e3bench incident encoded as a rule. An OS image shipped without `wipefs`,
the agent's autodetect answered "mock", and `storage.enumerate` told a real n100 controlplane it
had three disks that do not exist in it — with `ok:true`, one confirmation away from a
destructive format against a device that was not there. The mock models disks, partitions and
live mounts precisely so the safety rules can be tested against it, and that fidelity is exactly
what makes its output indistinguishable from truth.

`--backend mock` reaches it by name, on a laptop, and stamps every line of output as fixture
output. That path is how the command's own test suite drives it.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | the verb did what was asked |
| 1 | the backend refused, or the work failed |
| 2 | the command line was wrong; nothing was attempted |
| 3 | the real backend is unavailable here and no fixture was substituted |
| 4 | the verb ran and the answer is no — `inspect`: not present; `mount-data`: a disk was skipped |

2 is not 1 on purpose: a script that treats every non-zero exit as "the disk refused" must not
be able to reach that conclusion from a typo. 4 is not 1 for the converse reason — a data disk
that did not mount is never fatal to a node (§6.3's first bullet), but a bench script asking
"did the disk come up" still needs an answer it can branch on.

Deadlines default to each verb's `proto` work budget — the same number the agent gets over the
bus, so a bench result transfers. **`claim`'s is fifteen minutes and that is real**: `wipefs` +
`sfdisk` + `mkfs` + a udev settle on a spinning 8 TB archive drive takes that long, so a claim
that looks hung usually is not. Do not interrupt one.

## What it does not prove

- **Nothing about the api, the saga, or the UI.** It bypasses all three by design. The claim
  saga's step ordering, its re-verify, and the adopt-or-wipe prompt are not exercised here.
- **Nothing about the mock's fidelity.** A `--backend mock` run tells you what the command
  prints, not what a disk does.
- **`mount-data` here is not the agent's startup sweep.** It is the same function, called by
  hand, after boot. That the *agent* runs it at startup — and lands the mount early enough — is a
  separate thing to watch in the node's log.

[i302]: https://github.com/geekdojo/geekdojo-brain/issues/302
