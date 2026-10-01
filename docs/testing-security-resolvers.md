# Testing the security-setting resolvers

Twelve security settings used to be read inline in the agent's and the api's `main`, where
nothing could table-test them
([geekdojo-brain#591](https://github.com/geekdojo/geekdojo-brain/issues/591)). Each is now read
in one named resolver, registered in `.github/security-resolvers.tsv`, with a table test that
asserts the closed outcome for every shape of input:

| Binary | Setting | Resolver |
|---|---|---|
| agent | `RASPUTIN_BMC_BACKEND` | `bmcBackendFromEnv` |
| agent | `RASPUTIN_DOCKER_BACKEND`, `_UCI_`, `_UPDATE_`, `_STORAGE_`, `_TAILSCALE_BACKEND` | `dockerBackendFromEnv` and its four siblings, over `selectBackend` |
| agent | `RASPUTIN_RESOLVED_DROPIN_DIR` | `resolvedDropinDirFromEnv` |
| api | `RASPUTIN_TRUST_DIR` | `trustDirFromEnv` |
| api | `RASPUTIN_CP_AUTHORIZED_KEYS` | `cpAuthorizedKeysFromEnv` |
| api | `RASPUTIN_RP_ID` | `rpIDFromEnv` |
| api | `RASPUTIN_RP_ORIGINS` | `rpOriginsFromEnv` |
| api | `RASPUTIN_SECURE_COOKIES` | `secureCookies` |

The unit tests prove each resolver in isolation. This page is the functional test: it proves
that the lint gate sees every read, and that `main` wires the api's resolvers into the running
process. The local part runs on a laptop in a few minutes and can be run by an agent. The bench
part runs with the normal batched bench pass.

## What it proves

- **Gate 3 (failopenlint) passes with no allowance for #591**, and the gate itself was not
  changed to get there (checks 1 and 2).
- **FO04 can see every one of the twelve reads.** With the resolvers' register rows removed,
  the lint reports exactly twelve findings, each inside its resolver (check 3).
- **The api's RP ID and origins reach the auth config.** A blank or comma-only
  `RASPUTIN_RP_ORIGINS` gives the derived origins, and a malformed RP ID stops the api at
  start (check 5).
- **The Secure decision reaches the cookie, with and without an HTTPS listener** (check 6).
  `RASPUTIN_SECURE_COOKIES` can always force Secure on. A recognised off value
  (`0|false|no|off`) turns it off only when there is no HTTPS listener. With an HTTPS listener,
  an off value is refused: the cookie keeps Secure and the api logs one WARN with the refused
  value. Any unrecognised value forces Secure on, with one WARN.
- **On hardware, on arm64 and amd64**, an upgrade changes nothing on a default appliance, an
  off value is refused on the appliance's HTTPS listener, and an agent survives and reports an
  unknown backend selector (the bench section).

## What it does not prove

- That a well-formed but *wrong* path or RP ID is safe. Those values are honoured, and their
  consumers check them.
- Secure behind a TLS-terminating reverse proxy in front of a plain-HTTP api. There is no HTTPS
  listener there, so an off value is honoured by design; the operator forces Secure on.
- The agent's wiring for the four selectors other than Docker on hardware. The bench case uses
  Docker; the other four go through the same `switch` shape and the same unit table.

## Local checks

### Prerequisites

- **Go**, the version in `go.work`. Check with `go version`.
- **`python3`**, only to ask the OS for a free port. It ships with macOS. Check with
  `python3 --version`.
- **`curl`**, **`lsof`** and **`rsync`**. All ship with macOS.
- **`gosec` and `staticcheck`**, for check 4's SAST gate. `scripts/sast-register.sh --install`
  installs the pinned versions into `$(go env GOPATH)/bin`; put that directory on your `PATH`.
  If your local Go is newer than the CI toolchain, run check 4 with the CI's `GOTOOLCHAIN`
  (the value in `.github/workflows/sast.yml`), or staticcheck cannot read the standard library.

Run everything below **in bash, from the repo root**, in one shell session: later blocks use
the functions and variables that earlier blocks define. macOS's default shell is zsh, so type
`bash` first.

### 1. Gate 3 passes with no allowance for #591 (TC-591-22)

```bash
go run ./api/cmd/failopenlint; echo "exit=$?"
grep -c 'geekdojo-brain#591' .github/failopen-allow.tsv
```

**Pass:** the output is exactly these two lines, then `exit=0`, then `0`:

```text
failopenlint: 9 finding(s) · 9 allowed · 0 to fix
security resolvers: 36 declared · 36 with a fail-closed test · 0 owed
```

There is no `allowed pending a fix` line.

### 2. The gate was not weakened (TC-591-23)

```bash
git fetch origin
git diff --stat origin/main -- api/cmd/failopenlint        # prints nothing
git diff origin/main -- .github/failopen-allow.tsv | grep -c '^-FO04.*blocked.*geekdojo/geekdojo-brain#591'   # 12
git diff origin/main -- .github/failopen-allow.tsv | grep -c '^[-+][^-+]'                                     # 12
go test ./api/cmd/failopenlint/...
```

**Pass:** the first diff prints nothing; the allow-file diff is exactly twelve deleted
`FO04 … blocked geekdojo/geekdojo-brain#591` rows and no other changed line (both counts are
12); the lint's own tests pass, `TestTheRepoItselfPasses` included.

### 3. FO04 sees every read, inside its resolver (TC-591-24)

This runs the lint on a scratch copy of the tree whose register no longer declares the twelve
resolvers (R01 and R28–R38), so every read they hold must surface as a finding.

```bash
SCRATCH=$(mktemp -d)
git ls-files -co --exclude-standard | rsync -a --files-from=- ./ "$SCRATCH/tree/"
awk -F'\t' '!($1 == "R01" || $1 ~ /^R(2[89]|3[0-8])$/)' .github/security-resolvers.tsv \
  > "$SCRATCH/tree/.github/security-resolvers.tsv"
go run ./api/cmd/failopenlint -root "$SCRATCH/tree" > "$SCRATCH/lint.out" 2>&1
grep FO04 "$SCRATCH/lint.out"
grep -c FO04 "$SCRATCH/lint.out"                                          # 12
grep FO04 "$SCRATCH/lint.out" | grep -c 'agent/cmd/rasputin-agent/resolvers.go'  # 7
grep FO04 "$SCRATCH/lint.out" | grep -c 'api/cmd/rasputin-api/resolvers.go'      # 4
grep FO04 "$SCRATCH/lint.out" | grep -c 'main.go:[0-9]*  secureCookies:RASPUTIN_SECURE_COOKIES'  # 1
grep FO04 "$SCRATCH/lint.out" | grep -c '  main:'                         # 0
grep FO04 "$SCRATCH/lint.out" | grep -c 'RASPUTIN_TRUST_DIR'              # 1
rm -rf "$SCRATCH"
```

**Pass:** the counts are as commented. The lint exits 1 on the scratch copy; that is expected,
because the copy's register is incomplete on purpose. The scratch copy is deleted by the last
line.

### 4. The other gates (TC-591-25)

```bash
awk -F'\t' '$1 ~ /^R(0[167]|2[89]|3[0-8])$/ {print $1, $3, $5, $6}' .github/security-resolvers.tsv
gofmt -l agent api                           # prints nothing
go vet ./agent/... ./api/...
go test -race ./agent/... ./api/...
scripts/sast-register.sh --gate
scripts/auth-register.sh --gate
```

**Pass:** rows R28–R38 are present and `covered`; R29–R33 name
`TestExplicitMockIsAlwaysHonoured`, and R30 also names `TestUCIBackendSelectionEnvOverride`;
R01 names `TestSecureCookies TestSecureCookies_FailsClosedOnEveryShapeOfInput`; R06 and R07
do not appear. `gofmt -l` prints nothing, and every other command exits 0.

### The api under test

Checks 5 and 6 start a real api. It must never touch a dev stack that is already running, so
it gets:

- its own temp data dir, deleted when it stops;
- **its own loopback port for each listener it opens**, each chosen by asking the OS for a free
  one: HTTP, the embedded NATS server, and the node listener (obs ingest). Never leave
  `RASPUTIN_OBS_INGEST_ADDR` empty: an empty value binds the default `:8443` on all
  interfaces, because `envOr` treats empty as unset;
- `RASPUTIN_MESH_BACKEND=mock`, which the api needs to boot with no Headscale;
- no inherited identity or cookie settings: `start_api` removes `RASPUTIN_CLUSTER_ID`,
  `RASPUTIN_RP_ID`, `RASPUTIN_RP_ORIGINS`, `RASPUTIN_SECURE_COOKIES` and `RASPUTIN_HTTPS_ADDR`
  from its environment, and each run adds back only what it sets.

It is started from a built binary, not `go run`: `go run` runs the api as a child process, so
`$!` would be the `go` command's pid, and `lsof` and `kill` would miss the api.

Nothing is trusted until **this process's own log** shows its identity line and its listening
line. The wait is on that fact, and it gives up if the process exits first, or after 60
seconds.

```bash
API_BIN_DIR=$(mktemp -d)
go build -o "$API_BIN_DIR/rasputin-api" ./api/cmd/rasputin-api
API_BIN="$API_BIN_DIR/rasputin-api"

# free_port: ask the OS for a free loopback port.
free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

# start_api [VAR=value ...]: start the api under test on its own data dir and
# its own loopback ports, plus the settings given. Sets DATA, LOG, PID,
# HTTP_PORT, NATS_PORT and OBS_PORT.
start_api() {
  DATA=$(mktemp -d)
  LOG="$DATA/api.log"
  HTTP_PORT=$(free_port); NATS_PORT=$(free_port); OBS_PORT=$(free_port)
  env -u RASPUTIN_CLUSTER_ID -u RASPUTIN_RP_ID -u RASPUTIN_RP_ORIGINS \
      -u RASPUTIN_SECURE_COOKIES -u RASPUTIN_HTTPS_ADDR \
    RASPUTIN_DATA_DIR="$DATA" \
    RASPUTIN_MESH_BACKEND=mock \
    RASPUTIN_HTTP_ADDR="127.0.0.1:$HTTP_PORT" \
    RASPUTIN_NATS_PORT="$NATS_PORT" \
    RASPUTIN_OBS_INGEST_ADDR="127.0.0.1:$OBS_PORT" \
    "$@" "$API_BIN" >"$LOG" 2>&1 &
  PID=$!
}

# wait_for_log PATTERN: wait until this process's log holds PATTERN.
wait_for_log() {
  local deadline=$((SECONDS + 60))
  until grep -q -- "$1" "$LOG"; do
    if ! kill -0 "$PID" 2>/dev/null; then echo "FAIL: the api exited before logging: $1"; cat "$LOG"; return 1; fi
    if (( SECONDS > deadline )); then echo "FAIL: no '$1' within 60s"; return 1; fi
    sleep 0.2
  done
}

# wait_for_exit: wait until the api has exited, and print its status.
wait_for_exit() {
  local deadline=$((SECONDS + 60))
  while kill -0 "$PID" 2>/dev/null; do
    if (( SECONDS > deadline )); then echo "FAIL: the api still running after 60s"; return 1; fi
    sleep 0.2
  done
  wait "$PID"; echo "exit=$?"
}

# stop_api: stop the api and delete its data dir.
stop_api() {
  kill "$PID" 2>/dev/null
  wait "$PID" 2>/dev/null
  rm -rf "$DATA"
}

# pending_cookie SCHEME PORT: the rasputin-pending Set-Cookie from login/begin.
# The handler sets that cookie on every call, signed in or not.
pending_cookie() {
  curl -sik -X POST -H 'Origin: http://localhost:3000' "$1://127.0.0.1:$2/api/auth/login/begin" \
    | grep -i '^set-cookie: rasputin-pending'
}

# cookie_warns: this process's RASPUTIN_SECURE_COOKIES WARN lines.
cookie_warns() {
  grep 'level=WARN msg="rasputin-api: RASPUTIN_SECURE_COOKIES is not honoured; session cookies are Secure"' "$LOG"
}
```

### 5. RP ID and origins reach the auth config (TC-591-26)

**Run A: blank origins give the derived origins.**

```bash
start_api RASPUTIN_RP_ORIGINS=" , "
wait_for_log "http listening on 127.0.0.1:$HTTP_PORT"
grep 'rasputin-api: cluster identity:' "$LOG"
grep "node listener up" "$LOG" | grep "addr=127.0.0.1:$OBS_PORT"
grep "http listening on 127.0.0.1:$HTTP_PORT" "$LOG"
grep -E 'rasputin-api: bus:|node listener:|level=ERROR|panic' "$LOG" || echo "no fatal line"
lsof -a -p "$PID" -iTCP -sTCP:LISTEN -nP
echo "assigned: HTTP $HTTP_PORT, NATS $NATS_PORT, obs $OBS_PORT"
stop_api
```

**Pass:**

- the identity line reads
  `rasputin-api: cluster identity: rp-id="localhost" origins="http://localhost:3000,http://localhost:8080"`
  followed by the public base URL and cluster id. Before this change it read
  `origins="http://localhost:3000"` only: a blank value gave an empty list, and
  `auth.NewService` filled in its own single default;
- the node-listener and HTTP-listening lines name this run's ports, and `no fatal line` is
  printed;
- `lsof` lists exactly three listening sockets, all on `127.0.0.1`, on the three assigned
  ports.

**Run B: a malformed RP ID stops the api.**

```bash
start_api RASPUTIN_RP_ID="https://x.local"
wait_for_exit
grep 'rasputin-api: auth service:' "$LOG"
rm -rf "$DATA"
```

**Pass:** `exit=1`, and the log has `rasputin-api: auth service: … the scheme component must be
empty`.

### 6. The Secure decision reaches the cookie (TC-591-27)

Six runs, one api each. The first four serve plain HTTP only; the last two add an HTTPS
listener on another free loopback port. The api mints its own leaf for that listener at start,
so no mesh or certificate setup is needed; `curl -k` accepts the self-minted leaf.

**Plain HTTP only.**

```bash
for setting in ture on false unset; do
  if [ "$setting" = unset ]; then start_api; else start_api RASPUTIN_SECURE_COOKIES="$setting"; fi
  wait_for_log "http listening on 127.0.0.1:$HTTP_PORT" && grep -q 'rasputin-api: cluster identity:' "$LOG" || { stop_api; break; }
  echo "== RASPUTIN_SECURE_COOKIES=$setting, plain HTTP"
  pending_cookie http "$HTTP_PORT"
  cookie_warns || echo "(no WARN)"
  stop_api
done
```

**Pass:**

| Setting | `rasputin-pending` cookie | WARN |
|---|---|---|
| `ture` | has `Secure` | exactly one, `value=ture reason="not a recognised value (1\|true\|yes\|on\|0\|false\|no\|off)"`, with `fix=` |
| `on` | has `Secure` | none |
| `false` | no `Secure` | none |
| unset | no `Secure` | none |

**With an HTTPS listener.**

```bash
for setting in unset false; do
  HTTPS_PORT=$(free_port)
  if [ "$setting" = unset ]; then
    start_api RASPUTIN_HTTPS_ADDR="127.0.0.1:$HTTPS_PORT"
  else
    start_api RASPUTIN_HTTPS_ADDR="127.0.0.1:$HTTPS_PORT" RASPUTIN_SECURE_COOKIES="$setting"
  fi
  wait_for_log "https listening on 127.0.0.1:$HTTPS_PORT" && grep -q 'rasputin-api: cluster identity:' "$LOG" || { stop_api; break; }
  echo "== RASPUTIN_SECURE_COOKIES=$setting, HTTPS listener"
  pending_cookie https "$HTTPS_PORT"
  cookie_warns || echo "(no WARN)"
  stop_api
done
```

**Pass:**

| Setting | `rasputin-pending` cookie | WARN |
|---|---|---|
| unset | has `Secure` | none |
| `false` | has `Secure` | exactly one, `value=false reason="an off value is refused while an HTTPS listener is running (RASPUTIN_HTTPS_ADDR is set)"`, with `fix=` |

Before this change the `false` row's cookie had no `Secure`: a recognised off value overrode the
HTTPS listener.

### Cleanup

Every run above stops its api and deletes its data dir. Remove the built binary, and confirm
nothing is left:

```bash
rm -rf "$API_BIN_DIR"
pgrep -fl "$API_BIN" || echo "no api under test running"
git status --short
```

**Pass:** `no api under test running`, and `git status` shows only the change under test.

## Bench checks

These run in the normal batched bench pass for this body of work, **on `bench.local` only**,
on **an arm64 controlplane and an amd64 controlplane**. Never on the BitScope rack unless Bryce
names it for the run. Resolve every node by name (`<node>.local` or `GET /api/nodes`) each
time, and again after any restart; the bench has no DHCP reservations. Announce each restart in
the same message that does it.

`node.env` is `/var/lib/rasputin/node.env` on every node. The api's log is
`journalctl -u rasputin-api`, the agent's `journalctl -u rasputin-agent`.

### TC-591-28: an upgrade changes nothing, and an off value is refused on the appliance

On **each** controlplane, arm64 and amd64:

1. **Before the upgrade**, on the previous release, with `node.env` as shipped, record:
   - the api's `rasputin-api: cluster identity:` line
     (`journalctl -u rasputin-api -b | grep 'cluster identity'`);
   - the `rasputin-pending` cookie over HTTPS:
     `curl -sik -X POST -H 'Origin: https://<cluster>.local' https://<cluster>.local/api/auth/login/begin | grep -i '^set-cookie: rasputin-pending'`
     (`<cluster>`: the cluster id, `bench` on the bench);
   - every node's registration from `GET /api/nodes`: its backends and its `configFaults`
     metadata.
2. **Upgrade** to a build holding this change through the normal update path.
3. **After the upgrade**, record the same three things. **Pass:** the identity line is
   identical; the cookie carries `Secure`; `journalctl -u rasputin-api -b | grep
   RASPUTIN_SECURE_COOKIES` finds nothing; every node shows the same backends and no new
   configfault.
4. **Refused off value.** Announce it, then add `RASPUTIN_SECURE_COOKIES=false` to the
   controlplane's `node.env` and `systemctl restart rasputin-api`. **Pass:** the cookie from
   step 1's `curl` still carries `Secure`, and the api's start log has exactly one WARN
   `rasputin-api: RASPUTIN_SECURE_COOKIES is not honoured; session cookies are Secure` with
   `value=false` and `reason="an off value is refused while an HTTPS listener is running
   (RASPUTIN_HTTPS_ADDR is set)"`.
5. **Restore, in the same run.** Remove the line, restart the api, and confirm the WARN is gone
   from the new start log.

### TC-591-29: an agent survives and reports an unknown backend selector

On one compute node (record which, and its architecture):

1. Announce it, then add `RASPUTIN_DOCKER_BACKEND=Mock` (capital M) to the node's `node.env`
   and `systemctl restart rasputin-agent`.
2. **Pass:**
   - `systemctl is-active rasputin-agent` reads `active`, and stays so;
   - the node's registration in `GET /api/nodes` carries a `configFaults` entry naming
     `RASPUTIN_DOCKER_BACKEND` and the value `Mock`;
   - an app deploy to that node is refused (record the response);
   - no backend is serving, mock or real: the agent's start log
     (`journalctl -u rasputin-agent -b`) has a `CONFIG FAULT` line naming
     `RASPUTIN_DOCKER_BACKEND` and `Mock`, the agent registered no app handlers, and so the
     deploy above is refused rather than reported as `running`.
3. **Restore, in the same run.** Remove the line, restart the agent, and confirm the fault is
   gone from the node's registration.
