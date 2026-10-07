# Testing collector trust: the Alloy probe

Every observability collector trusts the api the standard way every Rasputin HTTPS client
does: **by chain to the controlplane CA, under the cluster name, with no certificate pinned**
([geekdojo-brain#672](https://github.com/geekdojo/geekdojo-brain/issues/672)). The api's
node listener (`RASPUTIN_OBS_INGEST_ADDR`, default `:8443`) serves the api's controlplane-CA-signed
HTTPS leaf for every name. A collector presents its node's own self-signed key, and the api
admits it by that key and nothing else.

The trust line is one constant, `collectorTrustLine` in `api/internal/obs/collector.go`, and
the auth register's C17 row anchors to it, so changing what a collector trusts fails
`scripts/auth-register.sh --gate` until the row is re-read.

The unit tests prove the rendering and the decisions. They cannot prove what Alloy does with
the config. The Alloy probe covers that: local, repeatable, about a minute. Run it on any
change to the collector's TLS config, and on every bump of the pinned Alloy image
(`defaultAlloyImage`; the `T05` row of `.github/third-party-capabilities.tsv` records it).

## The Alloy probe

`TestAlloyProbe` in `api/internal/obs/collector_alloy_probe_test.go`, behind the
`alloyprobe` build tag, so a plain `go test` never runs it.

### What it proves

On the digest-pinned Alloy image, with the exact `tls_config` a collector is rendered with
(`collectorTLSConfig`), against an in-process TLS 1.3 server that requires a client
certificate:

- **Positive (TC-672-17).** Alloy presents a self-signed client pair made with the agent's
  parameters (ECDSA P-256, PKCS#8 `PRIVATE KEY` PEM, clientAuth EKU, dated 1970 to 9999),
  verifies the server's leaf by chain to a throwaway controlplane CA through `ca_file`, sends SNI equal
  to `server_name`, and delivers a `remote_write` POST to `/api/obs/ingest`. The server sees
  the generated key's SPKI.
- **No certificate pinned (TC-672-20).** The server swaps in a re-minted leaf (a fresh key,
  the same CA, the same name) and drops its connections. Alloy delivers again under the new
  serial, with no config change and no container restart.
- **Chain enforced (TC-672-18).** A leaf from a different CA gets an `x509:` error in Alloy's
  log and no delivery.
- **Name enforced (TC-672-19).** A controlplane-CA leaf for `other.rasputin.test` gets an `x509:`
  name-mismatch error and no delivery.

### What it does not prove

- The real fleet: real nodes, the real api leaf, both architectures.
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
