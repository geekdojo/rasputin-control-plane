#!/usr/bin/env bash
# test-app-upgrade.sh: the bench functional test for in-place app upgrade,
# custom compose edit, revert, the dropped-volume gate and delete, run against
# ONE real compute node with human-system as the fixture.
#
# Tracked as geekdojo/geekdojo-brain#415 (part of #181). It drives the merged
# api from rasputin-control-plane #272, #273, #274, #275 and #277:
#
#   PUT    /api/apps/{id}/compose   {"source":"catalog"} | {"composeYaml":…} | {"sha256":…}
#   DELETE /api/apps/{id}           {"deleteVolumes": true|false}
#   GET    /api/volumes/orphans     and POST /api/volumes/orphans/reclaim
#
# and then checks the NODE, over SSH, rather than trusting the api's own report.
#
# ============================================================================
# READ THIS BEFORE YOU RUN IT
# ============================================================================
#
# It creates, deploys, upgrades and deletes apps on a real cluster. Run it only
# against a bench cluster. It refuses to start unless you pass
# --i-am-on-the-bench AND a --cluster name that matches the install name the
# api reports (GET /api/setup/state → installName).
#
# ----------------------------------------------------------------------------
# Placeholders used below
# ----------------------------------------------------------------------------
#
#   <cluster>       The cluster's install name, as the Rasputin UI shows it and
#                   as GET https://<cluster>.local/api/setup/state reports it in
#                   "installName". The api is normally https://<cluster>.local.
#   <node-id>       The id of a COMPUTE node in that cluster, as listed by
#                   GET /api/nodes ("id"). Optional: without --node the first
#                   online compute node, sorted by id, is used.
#   <catalog-repo>  A local git clone of geekdojo/rasputin-app-catalog. The
#                   script only runs `git fetch` and `git show origin/main:…`
#                   in it. It never checks anything out.
#   <commit>        A commit in <catalog-repo> whose
#                   tiles/human-system/docker-compose.yml is the OLDER compose
#                   to start from.
#
# ----------------------------------------------------------------------------
# What must be installed on the machine you run it from
# ----------------------------------------------------------------------------
#
#   bash 3.2 or newer (macOS's /bin/bash is fine), curl, jq, git, ssh, awk, sed,
#   and one of `shasum` (macOS) or `sha256sum` (Linux). `shellcheck` is optional,
#   for linting the script itself.
#
#   Check with:   for t in bash curl jq git ssh awk sed; do command -v "$t" || echo "MISSING: $t"; done
#
# ----------------------------------------------------------------------------
# What must be true about the cluster and the node
# ----------------------------------------------------------------------------
#
#   1. You can SSH to the node as root with a key and no password prompt:
#        ssh -o BatchMode=yes root@<node lanIP> true
#      The script finds <node lanIP> itself from GET /api/nodes on every SSH
#      use. Never write an IP down: bench nodes get new DHCP leases on reboot.
#   2. The node's sshd allows TCP port forwarding (ssh -L). The script uses it
#      to reach the test app's loopback-only web port, 127.0.0.1:<port> on the
#      node. It runs no remote command over that connection (ssh -N).
#   3. The cluster's catalog carries the human-system tile (GET
#      /api/catalog/human-system answers 200).
#   4. The node can pull ghcr.io/geekdojo/human-system and postgres images.
#   5. The api and the node's agent are builds that carry the upgrade work
#      (#272-#277). The agent must answer docker.pull, docker.volumes.check and
#      docker.volumes.drop; proto/agentverbs.go records the first release that
#      does. E1 prints the node's agentVersion so the run records it.
#
# ----------------------------------------------------------------------------
# Authentication
# ----------------------------------------------------------------------------
#
# The api signs in with a passkey only, so this script cannot sign in itself.
# It uses the session of a browser you have ALREADY signed in with:
#
#   1. In Chrome, open https://<cluster>.local and sign in with your passkey.
#   2. Open DevTools → Application → Cookies → https://<cluster>.local.
#   3. Copy the Value of the cookie named `rasputin-session`.
#   4. In the terminal you run the script from, type (the value is not echoed
#      and does not land in your shell history):
#        read -rs RASPUTIN_SESSION && export RASPUTIN_SESSION
#
# The value is written only to a mode-0600 curl config file inside the run's
# temporary directory, which is deleted when the script exits. It is never
# printed and never passed on a command line.
#
# The human-system test apps get a throwaway account with a random password,
# generated per run and also kept only in that temporary directory.
#
# ----------------------------------------------------------------------------
# Flags
# ----------------------------------------------------------------------------
#
#   --cluster <cluster>        Required. Must equal the api's installName.
#   --i-am-on-the-bench        Required for a real run. Your statement that
#                              <cluster> is a bench cluster and not production.
#   --catalog-repo <path>      Required. The <catalog-repo> clone.
#   --api <url>                The api base URL. Default https://<cluster>.local.
#   --node <node-id>           The compute node to use. Default: first online
#                              compute node by id.
#   --from-commit <commit>     The catalog commit whose human-system compose the
#                              custom app starts from. Default: the commit just
#                              before the one whose compose the cluster's catalog
#                              currently serves (matched by sha256).
#   --cacert <file>            PEM file to verify the api's TLS certificate.
#   --insecure                 Skip TLS verification of the api (curl -k). Use
#                              only when you have no CA file for the bench.
#   --ssh-user <user>          SSH user on the node. Default root.
#   --ssh-identity <file>      SSH private key. Default: your ssh config/agent.
#   --agent-state-dir <path>   The agent's state directory on the node. Default
#                              /var/lib/rasputin/agent-state (rasputin-os's
#                              rasputin-agent.service sets this).
#   --expose-lan               Create the test apps with exposeLan:true. Needed
#                              only when the node is not on the tailnet, which
#                              makes a tailnet-only install answer 409.
#   --skip-catalog             Do not install from the catalog. Step B1 then
#                              uses a custom app, and B2 reports NOT EXERCISED.
#   --job-timeout <seconds>    Hard deadline for each api job. Default 900.
#   --app-timeout <seconds>    Hard deadline for an app to reach a status, or
#                              for its web port to answer. Default 600.
#   --keep                     Do not clean up the apps this run created. For
#                              debugging only; delete them yourself afterwards.
#   --dry-run                  Print every planned api call and node check and
#                              execute none of them. Contacts no cluster and no
#                              node. It does read <catalog-repo> (git fetch +
#                              git show), and stands in origin/main's compose
#                              for the cluster's tile.
#   -h, --help                 Print this header.
#
# Environment:
#
#   RASPUTIN_SESSION           Required for a real run. See Authentication.
#   RASPUTIN_NEVER_TARGET      Optional. Comma-separated install names this
#                              script must refuse, e.g. your production cluster.
#                              Kept out of this public repo on purpose; put it in
#                              your shell profile.
#
# ----------------------------------------------------------------------------
# Example
# ----------------------------------------------------------------------------
#
#   git clone https://github.com/geekdojo/rasputin-app-catalog ~/src/rasputin-app-catalog
#   read -rs RASPUTIN_SESSION && export RASPUTIN_SESSION
#   scripts/test-app-upgrade.sh --dry-run --cluster <cluster> \
#       --catalog-repo ~/src/rasputin-app-catalog
#   scripts/test-app-upgrade.sh --i-am-on-the-bench --cluster <cluster> \
#       --catalog-repo ~/src/rasputin-app-catalog --insecure 2>&1 | tee app-upgrade-run.log
#
# Exit codes: 0 every step passed (NOT EXERCISED, KNOWN and SKIP do not fail a
# run), 1 at least one step failed, 2 refused to start (bad flags, safety
# guard, preflight).
#
# ============================================================================
# What it does, step by step
# ============================================================================
#
#   E1  Record the node's `docker version`, `docker compose version`, agent and
#       image version, and the catalog in effect.
#
#   Chain A: custom app, compose edit (#410), revert (#411), gate (#412),
#   keep-data delete and reclaim (#413)
#   A1  Create a CUSTOM app from the OLDER human-system compose (read from the
#       catalog's git history), with its loopback port moved to a per-run port.
#       Deploy it.
#   A2  Write data through human-system's own HTTP api: the single user
#       (bootstrap), a system note, and an uploaded document. Read it back.
#   A3  PUT composeYaml with the cluster's CURRENT tile compose (same port
#       change). Verify: same ULID, same volume names and creation times, the
#       app container runs the new image digest, and the data reads back.
#   A4  PUT sha256 of the previous compose (revert). Verify the same things
#       against the old digest.
#   A5  PUT a compose that renames the hs-data volume key. Expect 409 naming
#       rasp_<id>_hs-data, and no change on the node or in the app row.
#   A6  DELETE with deleteVolumes:false. Every volume stays on the node and is
#       listed by GET /api/volumes/orphans.
#   A7  Reclaim those orphans. No volume of the app remains.
#
#   Chain B: catalog install, catalog upgrade (#409), delete with data (#413)
#   B1  Install human-system from the catalog (or, with --skip-catalog or when
#       the node already publishes the tile's port, a custom app from the
#       current compose). Deploy it and write data.
#   B2  Catalog upgrade. Runs only when the app reports upgradeAvailable:true.
#       Otherwise reports NOT EXERCISED and checks that {"source":"catalog"}
#       is the 200 no-op.
#   B3  DELETE with deleteVolumes:true. Nothing of the app's containers or
#       volumes remains on the node.
#
# After every delete the node is checked for residue by the app's compose
# project label, its recorded volume names, its anonymous-volume record, and
# the agent directories <agent-state-dir>/apps/<id> and
# <agent-state-dir>/proxy/certs/<id>. Residue that
# geekdojo/geekdojo-brain#421 has not fixed yet (networks, images, the app's
# agent directory, leaf files) is printed as KNOWN, not FAIL.
#
# ============================================================================
# Why the catalog path (#409) usually reports NOT EXERCISED
# ============================================================================
#
# Catalog install always copies the tile's CURRENT compose, so a fresh catalog
# install is already current and upgradeAvailable is false. The api offers no
# "install at an older pin", and this script will not fake one by editing the
# database or the catalog. The upgrade mechanics (same ULID, same project and
# volumes, pull then up) are shared with the custom-edit path, which chain A
# does exercise. What only B2 can prove is the catalog-mediated part:
# ResolveUpgrade, the tile's compose taken from the verified store, and the
# tile.json-based advisory volume check.
#
# A legitimate way to exercise it: install a catalog app on a cluster whose
# catalog in effect is an older bundle, write data, and then let the cluster
# apply a newer catalog bundle that carries a new human-system pin (the next
# catalog release, or POST /api/catalog/_refresh once one is published). The
# existing install's compose hash then differs from the tile and
# upgradeAvailable turns true. This script does not do that for you.
#
# ============================================================================
# Safety guards
# ============================================================================
#
#   * Refuses without --i-am-on-the-bench, a matching --cluster, and a
#     --cluster not listed in RASPUTIN_NEVER_TARGET.
#   * No hostnames, IPs or cluster ids are written in this file. The node is
#     resolved from GET /api/nodes at every SSH use.
#   * Every change goes through the api. The node is only READ, over SSH, and
#     node_ro refuses any command outside a fixed read-only allowlist (docker
#     ps / volume ls / volume inspect / network ls / image ls / inspect /
#     version / compose version, test, sha256sum, ls, and cat of the agent's
#     volumes.json).
#   * Test apps are named t415a-<run> and t415b-<run>, with a random <run> id.
#     Cleanup deletes (with volumes) and reclaims only the apps this run
#     created, and only by the ids it recorded.
#   * Every wait has a hard deadline and fails naming what never became true.

set -euo pipefail
umask 077

# ---------------------------------------------------------------------------
# Defaults and flags
# ---------------------------------------------------------------------------

TILE=human-system
TILE_PATH="tiles/$TILE/docker-compose.yml"
TILE_PORT_LINE='      - "127.0.0.1:8085:8080"'
TILE_HOST_PORT=8085
APP_IMAGE_PREFIX='ghcr.io/geekdojo/human-system@'
SIDECAR_IMAGE_PREFIX='postgres:'

API=""
CLUSTER=""
NODE=""
CATALOG_REPO=""
FROM_COMMIT=""
CACERT=""
INSECURE=0
SSH_USER=root
SSH_IDENTITY=""
AGENT_STATE_DIR=/var/lib/rasputin/agent-state
EXPOSE_LAN=false
SKIP_CATALOG=0
JOB_TIMEOUT=900
APP_TIMEOUT=600
KEEP=0
DRY=0
BENCH=0

usage() { sed -n '2,/^set -euo pipefail$/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }

die() { printf 'refused: %s\n' "$*" >&2; exit 2; }

while [ $# -gt 0 ]; do
    case $1 in
        --cluster) CLUSTER=${2:?--cluster needs a value}; shift 2 ;;
        --api) API=${2:?--api needs a value}; shift 2 ;;
        --node) NODE=${2:?--node needs a value}; shift 2 ;;
        --catalog-repo) CATALOG_REPO=${2:?--catalog-repo needs a value}; shift 2 ;;
        --from-commit) FROM_COMMIT=${2:?--from-commit needs a value}; shift 2 ;;
        --cacert) CACERT=${2:?--cacert needs a value}; shift 2 ;;
        --insecure) INSECURE=1; shift ;;
        --ssh-user) SSH_USER=${2:?--ssh-user needs a value}; shift 2 ;;
        --ssh-identity) SSH_IDENTITY=${2:?--ssh-identity needs a value}; shift 2 ;;
        --agent-state-dir) AGENT_STATE_DIR=${2:?--agent-state-dir needs a value}; shift 2 ;;
        --expose-lan) EXPOSE_LAN=true; shift ;;
        --skip-catalog) SKIP_CATALOG=1; shift ;;
        --job-timeout) JOB_TIMEOUT=${2:?--job-timeout needs a value}; shift 2 ;;
        --app-timeout) APP_TIMEOUT=${2:?--app-timeout needs a value}; shift 2 ;;
        --keep) KEEP=1; shift ;;
        --dry-run) DRY=1; shift ;;
        --i-am-on-the-bench) BENCH=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown flag: $1 (see --help)" ;;
    esac
done

# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------

TAB=$(printf '\t')
exec 3>&1
dry() { [ "$DRY" = 1 ]; }
not() { ! "$@"; }
lower() { printf '%s' "$1" | tr 'A-Z' 'a-z'; }
upper() { printf '%s' "$1" | tr 'a-z' 'A-Z'; }
now() { date +%s; }

sha256_file() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        sha256sum "$1" | awk '{print $1}'
    fi
}

rand_hex() { # bytes
    od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'
}

rand_port() { # 20000-29999
    local n
    n=$(od -An -N2 -tu2 /dev/urandom | tr -d ' \n')
    echo $((20000 + n % 10000))
}

hr() { printf '%s\n' "------------------------------------------------------------------------------"; }
say() { printf '%s\n' "$*"; }

# ---------------------------------------------------------------------------
# Preflight: flags, tools, safety guards
# ---------------------------------------------------------------------------

[ -n "$CLUSTER" ] || die "--cluster <cluster> is required (see --help)"
[ -n "$CATALOG_REPO" ] || die "--catalog-repo <path> is required (see --help)"
case $CLUSTER in
    *[!A-Za-z0-9._-]*) die "--cluster must be a plain name (letters, digits, . _ -)" ;;
esac
case $JOB_TIMEOUT$APP_TIMEOUT in
    *[!0-9]*) die "--job-timeout and --app-timeout take whole seconds" ;;
esac
[ -n "$API" ] || API="https://$CLUSTER.local"
API=${API%/}
case $NODE in
    *[!A-Za-z0-9._-]*) die "--node must be a node id as GET /api/nodes lists it" ;;
esac
case $AGENT_STATE_DIR in
    /*) ;;
    *) die "--agent-state-dir must be an absolute path" ;;
esac
case $AGENT_STATE_DIR in
    *[!A-Za-z0-9/._-]*) die "--agent-state-dir must contain only letters, digits and / . _ -" ;;
esac

if [ -n "${RASPUTIN_NEVER_TARGET:-}" ]; then
    oldifs=$IFS; IFS=,
    for never in $RASPUTIN_NEVER_TARGET; do
        if [ "$(lower "$never")" = "$(lower "$CLUSTER")" ]; then
            IFS=$oldifs
            die "cluster '$CLUSTER' is listed in RASPUTIN_NEVER_TARGET"
        fi
    done
    IFS=$oldifs
fi

if ! dry && [ "$BENCH" != 1 ]; then
    die "this changes apps on a real cluster. Pass --i-am-on-the-bench to confirm '$CLUSTER' is a bench cluster, or use --dry-run"
fi

for t in curl jq git ssh awk sed od; do
    command -v "$t" >/dev/null 2>&1 || die "'$t' is not installed; see 'What must be installed' in --help"
done
command -v shasum >/dev/null 2>&1 || command -v sha256sum >/dev/null 2>&1 \
    || die "neither shasum nor sha256sum is installed"
git -C "$CATALOG_REPO" rev-parse --git-dir >/dev/null 2>&1 \
    || die "--catalog-repo '$CATALOG_REPO' is not a git clone"
if [ -n "$CACERT" ] && [ ! -f "$CACERT" ]; then
    die "--cacert '$CACERT' does not exist"
fi
if [ -n "$SSH_IDENTITY" ] && [ ! -f "$SSH_IDENTITY" ]; then
    die "--ssh-identity '$SSH_IDENTITY' does not exist"
fi

set +x # never trace: the session value is written to a file below

if ! dry; then
    [ -n "${RASPUTIN_SESSION:-}" ] || die "RASPUTIN_SESSION is not set; see 'Authentication' in --help"
    case $RASPUTIN_SESSION in
        *[!A-Za-z0-9._~+/=-]*) die "RASPUTIN_SESSION contains characters a session cookie value does not; copy only the Value" ;;
    esac
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/test-app-upgrade.XXXXXX")
trap 'rm -rf "$WORK"' EXIT # replaced by the full cleanup once it is defined
RUN_ID=$(rand_hex 3)
A_NAME="t415a-$RUN_ID"
B_NAME="t415b-$RUN_ID"
CREATED="" # space-separated app ids this run created
TUNNEL_PID=""
LOCAL_PORT=""
: > "$WORK/steps.tsv"

if ! dry; then
    printf 'header = "Cookie: rasputin-session=%s"\n' "$RASPUTIN_SESSION" > "$WORK/auth.curl"
fi

# ---------------------------------------------------------------------------
# Step bookkeeping
# ---------------------------------------------------------------------------

CUR_ID=""
CUR_TITLE=""
CUR_FAILS=0
CUR_KNOWN=0
CUR_NOTE=""

step_begin() {
    CUR_ID=$1; CUR_TITLE=$2; CUR_FAILS=0; CUR_KNOWN=0; CUR_NOTE=""
    say ""
    hr
    say "[$CUR_ID] $CUR_TITLE"
    hr
}

ok() { say "    ok     $*"; }
fail() { say "    FAIL   $*"; CUR_FAILS=$((CUR_FAILS + 1)); }
known() { say "    KNOWN  $*"; CUR_KNOWN=1; }
info() { say "    ..     $*"; }
note() { CUR_NOTE=$*; }

# check <description> <command...>: ok when the command succeeds
check() {
    local desc=$1; shift
    if dry; then say "    check  $desc"; return 0; fi
    if "$@"; then ok "$desc"; else fail "$desc"; return 1; fi
}

step_end() { # [override result]
    local result
    if dry; then
        result=PLANNED
    elif [ "$CUR_FAILS" -gt 0 ]; then
        result=FAIL
    elif [ -n "${1:-}" ]; then
        result=$1
    elif [ "$CUR_KNOWN" = 1 ]; then
        result="PASS (KNOWN residue)"
    else
        result=PASS
    fi
    printf '%s\t%s\t%s\t%s\n' "$CUR_ID" "$CUR_TITLE" "$result" "$CUR_NOTE" >> "$WORK/steps.tsv"
    say "  => $result  [$CUR_ID] $CUR_TITLE${CUR_NOTE:+  ($CUR_NOTE)}"
}

step_blocked() { # id title reason
    printf '%s\t%s\t%s\t%s\n' "$1" "$2" "BLOCKED" "$3" >> "$WORK/steps.tsv"
    say ""
    say "  => BLOCKED  [$1] $2  ($3)"
}

# ---------------------------------------------------------------------------
# The api (every change to the cluster goes through here)
# ---------------------------------------------------------------------------

API_CODE=""
RESP="$WORK/resp.json"

describe_body() { # file
    [ -n "$1" ] || return 0
    printf '  body: %s' "$(jq -c 'if has("composeYaml") then .composeYaml = "<compose, \(.composeYaml | length) chars>" else . end
        | if has("password") then .password = "<redacted>" else . end' "$1")"
}

# api METHOD PATH [BODY_FILE]  → $API_CODE, response in $RESP
api() {
    local m=$1 p=$2 b=${3:-}
    if dry; then
        printf '    API    %-6s %s%s\n' "$m" "$p" "$(describe_body "$b")"
        API_CODE=DRY
        echo '{}' > "$RESP"
        return 0
    fi
    local tls=""
    if [ -n "$CACERT" ]; then tls="--cacert"; elif [ "$INSECURE" = 1 ]; then tls="-k"; fi
    local code
    if [ -n "$b" ]; then
        code=$(curl -sS --connect-timeout 10 --max-time 120 -K "$WORK/auth.curl" \
            ${tls:+$tls} ${CACERT:+"$CACERT"} \
            -o "$RESP" -w '%{http_code}' -X "$m" \
            -H 'Content-Type: application/json' --data-binary "@$b" "$API$p" 2>"$WORK/curl.err") || code=000
    else
        code=$(curl -sS --connect-timeout 10 --max-time 120 -K "$WORK/auth.curl" \
            ${tls:+$tls} ${CACERT:+"$CACERT"} \
            -o "$RESP" -w '%{http_code}' -X "$m" "$API$p" 2>"$WORK/curl.err") || code=000
    fi
    API_CODE=$code
    [ -s "$RESP" ] || echo '{}' > "$RESP"
    if [ "${API_QUIET:-0}" != 1 ]; then
        printf '    API    %-6s %s%s -> %s\n' "$m" "$p" "$(describe_body "$b")" "$code"
    fi
    if [ "$code" = 000 ]; then
        say "           curl: $(head -c 300 "$WORK/curl.err")"
    fi
    if [ "$code" = 401 ]; then
        say "           the api answered 401: RASPUTIN_SESSION is missing, expired or not this cluster's"
    fi
}

# jr FILTER PLACEHOLDER: a value from the last response, or the placeholder in a dry run
jr() {
    if dry; then printf '%s' "$2"; return 0; fi
    jq -r "$1" "$RESP" 2>/dev/null || printf ''
}

resp_error() { jq -r '.error // empty' "$RESP" 2>/dev/null | head -c 500; }

expect_code() { # want... : ok when API_CODE is one of them
    dry && { say "    check  api answers $*"; return 0; }
    local w
    for w in "$@"; do
        [ "$API_CODE" = "$w" ] && { ok "api answered $API_CODE"; return 0; }
    done
    fail "api answered $API_CODE, want $* $(resp_error)"
    return 1
}

body_json() { # name jq-args... : writes $WORK/<name>.json from jq -n
    local name=$1; shift
    jq -n "$@" > "$WORK/$name.json"
    printf '%s' "$WORK/$name.json"
}

# wait_job JOB_ID WHAT: 0 succeeded, 1 failed/cancelled/timeout
wait_job() {
    local id=$1 what=$2
    if dry; then say "    WAIT   GET /api/jobs/<job id> until succeeded|failed|cancelled (deadline ${JOB_TIMEOUT}s): $what"; return 0; fi
    if [ -z "$id" ]; then
        fail "the api returned no job id for $what: $(jq -c . "$RESP" | head -c 300)"
        return 1
    fi
    local deadline=$(( $(now) + JOB_TIMEOUT )) status=""
    while :; do
        API_QUIET=1 api GET "/api/jobs/$id"
        status=$(jq -r '.status // empty' "$RESP")
        case $status in
            succeeded) ok "job for $what succeeded"; return 0 ;;
            failed|cancelled)
                fail "job for $what ended $status: $(jq -r '.error // empty' "$RESP" | head -c 500)"
                API_QUIET=1 api GET "/api/jobs/$id/steps"
                jq -r '(if type == "array" then . else (.steps // []) end)[]
                    | select(.status == "failed") | "           step \(.name) failed: \(.error // "" | .[0:400])"' "$RESP" 2>/dev/null || true
                return 1 ;;
        esac
        if [ "$(now)" -ge "$deadline" ]; then
            fail "job for $what never reached succeeded/failed/cancelled within ${JOB_TIMEOUT}s (last status: ${status:-unreadable, http $API_CODE})"
            return 1
        fi
        sleep 3
    done
}

# wait_app_status APP_ID WANT: poll lastStatus
wait_app_status() {
    local id=$1 want=$2
    if dry; then say "    WAIT   GET /api/apps/$id until lastStatus=$want (deadline ${APP_TIMEOUT}s)"; return 0; fi
    local deadline=$(( $(now) + APP_TIMEOUT )) st=""
    while :; do
        API_QUIET=1 api GET "/api/apps/$id"
        st=$(jq -r '.lastStatus // empty' "$RESP")
        [ "$st" = "$want" ] && { ok "app reports lastStatus=$want"; return 0; }
        if [ "$(now)" -ge "$deadline" ]; then
            fail "app $id never reported lastStatus=$want within ${APP_TIMEOUT}s (last: ${st:-http $API_CODE} $(jq -r '.lastDetail // empty' "$RESP" | head -c 300))"
            return 1
        fi
        sleep 3
    done
}

# submit_and_wait WHAT: the last response was a 202 job; wait for it
job_from_resp() { jr '.id // empty' '<job id>'; }

# ---------------------------------------------------------------------------
# The node: read-only, over SSH, address resolved at every use
# ---------------------------------------------------------------------------

node_ip() {
    if dry; then printf '<lanIP of %s from GET /api/nodes>' "${NODE:-<node-id>}"; return 0; fi
    local ip saved_code=$API_CODE
    cp "$RESP" "$WORK/resp.saved" 2>/dev/null || echo '{}' > "$WORK/resp.saved"
    API_QUIET=1 api GET /api/nodes
    if [ "$API_CODE" = 200 ]; then
        ip=$(jq -r --arg n "$NODE" '.[] | select(.id == $n) | .lanIP // empty' "$RESP")
    else
        ip=""
    fi
    mv "$WORK/resp.saved" "$RESP"
    API_CODE=$saved_code
    case $ip in
        ""|*[!A-Za-z0-9.:-]*) return 1 ;;
    esac
    printf '%s' "$ip"
}

ssh_opts() {
    printf '%s\n' -o BatchMode=yes -o ConnectTimeout=8 -o ServerAliveInterval=5 \
        -o ServerAliveCountMax=3 -o "UserKnownHostsFile=$WORK/known_hosts" \
        -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR
    if [ -n "$SSH_IDENTITY" ]; then printf '%s\n' -i "$SSH_IDENTITY"; fi
}

# node_ro WORD...: run one allowlisted read-only command on the node.
# Every word is single-quoted for the remote shell, so no word can be
# interpreted as shell syntax there. Output on stdout; exit status is the
# command's, or 255 when SSH itself failed.
node_ro() {
    local joined="$*"
    case $joined in
        "docker ps "*|"docker volume ls "*|"docker volume inspect "*|"docker network ls "*|\
        "docker image ls "*|"docker inspect "*|"docker version"|"docker compose version"|\
        "test -d "*|"test -f "*|"sha256sum "*|"ls -A "*) ;;
        "cat $AGENT_STATE_DIR/apps/"*"/volumes.json") ;;
        *) printf 'internal error: refusing a node command outside the read-only allowlist: %s\n' "$1 ${2:-}" >&2; exit 2 ;;
    esac
    local remote="" w
    for w in "$@"; do
        case $w in *\'*) printf 'internal error: a quote in a node command word\n' >&2; exit 2 ;; esac
        remote="$remote '$w'"
    done
    if dry; then
        # fd 3 is the terminal's stdout, so the plan line shows even when the
        # caller captures or discards this function's output.
        say "    NODE   ssh $SSH_USER@$(node_ip) $joined" >&3
        return 0
    fi
    local ip
    ip=$(node_ip) || { printf 'could not resolve %s lanIP from /api/nodes\n' "$NODE" >&2; return 255; }
    # shellcheck disable=SC2046 # ssh_opts prints one option word per line
    ssh $(ssh_opts) "$SSH_USER@$ip" "$remote"
}

node_reachable() { dry || node_ro docker version >/dev/null 2>&1; }

project_of() { printf 'rasp_%s' "$(lower "$1")"; }

node_containers() { # app id → "name|state|image" lines
    node_ro docker ps -a --filter "label=com.docker.compose.project=$(project_of "$1")" \
        --format '{{.Names}}|{{.State}}|{{.Image}}' | sort
}

node_containers_started() { # app id → "name|id|startedAt|image" lines
    local ids id out=""
    ids=$(node_ro docker ps -aq --filter "label=com.docker.compose.project=$(project_of "$1")") || return 0
    for id in $ids; do
        case $id in *[!0-9a-f]*) continue ;; esac
        out="$out$(node_ro docker inspect --format '{{.Name}}|{{.Id}}|{{.State.StartedAt}}|{{.Config.Image}}' "$id")
"
    done
    printf '%s' "$out" | sed '/^$/d' | sort
}

node_service_image() { # app id, service → image ref of that service's container
    node_ro docker ps -a --filter "label=com.docker.compose.project=$(project_of "$1")" \
        --filter "label=com.docker.compose.service=$2" --format '{{.Image}}' | head -1
}

node_volumes() { # app id → volume names, by project label and by name prefix
    local p
    p=$(project_of "$1")
    {
        node_ro docker volume ls --filter "label=com.docker.compose.project=$p" --format '{{.Name}}' || true
        echo
        node_ro docker volume ls --filter "name=${p}_" --format '{{.Name}}' | grep "^${p}_" || true
    } | sed '/^$/d' | sort -u
}

node_volume_identity() { # names... → "name|createdAt" lines
    [ $# -gt 0 ] || return 0
    node_ro docker volume inspect --format '{{.Name}}|{{.CreatedAt}}' "$@" | sort
}

node_volume_exists() { node_ro docker volume inspect --format '{{.Name}}' "$1" >/dev/null 2>&1; }

node_networks() { # app id → network names
    node_ro docker network ls --filter "label=com.docker.compose.project=$(project_of "$1")" --format '{{.Name}}' | sort
}

node_anon_record() { # app id → recorded anonymous volume names
    local out
    out=$(node_ro cat "$AGENT_STATE_DIR/apps/$1/volumes.json" 2>/dev/null) || return 0
    printf '%s' "$out" | jq -r '.anonymous[]?.name // empty' 2>/dev/null || true
}

node_compose_sha() { # app id → sha256 of the live compose file on the node
    node_ro sha256sum "$AGENT_STATE_DIR/apps/$1/docker-compose.yml" 2>/dev/null | awk '{print $1}'
}

node_port_published() { # host port → 0 when some container publishes it
    local ports
    ports=$(node_ro docker ps --format '{{.Ports}}') || return 1
    printf '%s' "$ports" | grep -q ":$1->"
}

node_images_for() { # compose files... → image lines on the node whose digest a compose names
    local digests d all
    digests=$(cat "$@" | awk '/^[ \t]*image:/ {print $2}' | sed -n 's/.*@\(sha256:[0-9a-f]*\)$/\1/p' | sort -u)
    all=$(node_ro docker image ls --digests --format '{{.Repository}}@{{.Digest}}|{{.ID}}') || return 0
    for d in $digests; do
        printf '%s\n' "$all" | grep -F "@$d|" || true
    done
}

# ---------------------------------------------------------------------------
# human-system's own HTTP api, through an SSH tunnel to the node's loopback port
# ---------------------------------------------------------------------------

HS_SESSION=""
HS_CSRF=""
HS_CODE=""
HS_RESP="$WORK/hs-resp"
HS_USER="harness415"
HS_PASS=""

open_tunnel() { # host port on the node
    close_tunnel
    local hp=$1
    LOCAL_PORT=$(rand_port)
    if dry; then
        say "    TUNNEL ssh -N -L 127.0.0.1:<local port>:127.0.0.1:$hp $SSH_USER@$(node_ip)   (no remote command)"
        return 0
    fi
    local ip
    ip=$(node_ip) || { fail "could not resolve $NODE lanIP from /api/nodes for the tunnel"; return 1; }
    # shellcheck disable=SC2046
    ssh $(ssh_opts) -N -o ExitOnForwardFailure=yes \
        -L "127.0.0.1:$LOCAL_PORT:127.0.0.1:$hp" "$SSH_USER@$ip" 2>"$WORK/tunnel.err" &
    TUNNEL_PID=$!
    local deadline=$(( $(now) + 30 ))
    while :; do
        if ! kill -0 "$TUNNEL_PID" 2>/dev/null; then
            fail "SSH tunnel to 127.0.0.1:$hp on $NODE exited: $(head -c 300 "$WORK/tunnel.err") (does the node's sshd allow TCP forwarding?)"
            TUNNEL_PID=""
            return 1
        fi
        # Listening is all this waits for; whether the app answers behind it
        # is hs_wait_ready's question.
        if (exec 3<>"/dev/tcp/127.0.0.1/$LOCAL_PORT") 2>/dev/null; then
            ok "SSH tunnel listening: 127.0.0.1:$LOCAL_PORT -> $NODE 127.0.0.1:$hp"
            return 0
        fi
        if [ "$(now)" -ge "$deadline" ]; then
            fail "SSH tunnel to $NODE 127.0.0.1:$hp never started listening on 127.0.0.1:$LOCAL_PORT within 30s"
            return 1
        fi
        sleep 1
    done
}

close_tunnel() {
    if [ -n "$TUNNEL_PID" ]; then
        kill "$TUNNEL_PID" 2>/dev/null || true
        wait "$TUNNEL_PID" 2>/dev/null || true
        TUNNEL_PID=""
    fi
}

# hs_call METHOD PATH [curl args...] → $HS_CODE, body in $HS_RESP
hs_call() {
    local m=$1 p=$2; shift 2
    if dry; then
        say "    HS     $m $p   (human-system api via the tunnel)"
        HS_CODE=DRY; echo '{}' > "$HS_RESP"; return 0
    fi
    local cookie=""
    [ -n "$HS_SESSION" ] && cookie="hs_session=$HS_SESSION"
    [ -n "$HS_CSRF" ] && cookie="${cookie:+$cookie; }hs_csrf=$HS_CSRF"
    HS_CODE=$(curl -sS --connect-timeout 5 --max-time 60 -X "$m" \
        -D "$WORK/hs-headers" -o "$HS_RESP" -w '%{http_code}' \
        ${cookie:+-H "Cookie: $cookie"} ${HS_CSRF:+-H "X-CSRF-Token: $HS_CSRF"} \
        "$@" "http://127.0.0.1:$LOCAL_PORT$p" 2>/dev/null) || HS_CODE=000
    # The tile marks its cookies Secure, and curl will not replay a Secure
    # cookie over the tunnel's plain http, so they are carried by hand.
    local v
    v=$(tr -d '\r' < "$WORK/hs-headers" | sed -n 's/^[Ss]et-[Cc]ookie: hs_session=\([^;]*\).*/\1/p' | tail -1)
    if grep -qi '^set-cookie: hs_session=' "$WORK/hs-headers" 2>/dev/null; then HS_SESSION=$v; fi
    v=$(tr -d '\r' < "$WORK/hs-headers" | sed -n 's/^[Ss]et-[Cc]ookie: hs_csrf=\([^;]*\).*/\1/p' | tail -1)
    if grep -qi '^set-cookie: hs_csrf=' "$WORK/hs-headers" 2>/dev/null; then HS_CSRF=$v; fi
    say "    HS     $m $p -> $HS_CODE"
}

hs_json() { if dry; then printf '%s' "$2"; else jq -r "$1" "$HS_RESP" 2>/dev/null || true; fi; }

hs_wait_ready() {
    if dry; then say "    WAIT   human-system GET /api/v1/auth/me answers (deadline ${APP_TIMEOUT}s)"; return 0; fi
    local deadline=$(( $(now) + APP_TIMEOUT ))
    while :; do
        HS_SESSION=""; HS_CSRF=""
        hs_call GET /api/v1/auth/me >/dev/null
        case $HS_CODE in
            200|401) ok "human-system answers on its web port ($HS_CODE)"; return 0 ;;
        esac
        if [ "$(now)" -ge "$deadline" ]; then
            fail "human-system never answered GET /api/v1/auth/me within ${APP_TIMEOUT}s (last http $HS_CODE)"
            return 1
        fi
        sleep 3
    done
}

# hs_write_data PREFIX: bootstrap the user, write a note and a document, and
# remember what was written in <PREFIX>_NOTE_ID / _NOTE_BODY / _DOC_ID / _DOC_SHA.
hs_write_data() {
    local px=$1
    [ -n "$HS_PASS" ] || HS_PASS=$(rand_hex 16)
    HS_SESSION=""; HS_CSRF=""
    hs_call GET /api/v1/auth/me
    hs_call POST /api/v1/auth/bootstrap -H 'Content-Type: application/json' \
        --data-binary "@$(body_json hsboot --arg u "$HS_USER" --arg p "$HS_PASS" \
            '{username: $u, password: $p, display_name: "issue 415 harness"}')"
    rm -f "$WORK/hsboot.json"
    if ! dry && [ "$HS_CODE" != 200 ] && [ "$HS_CODE" != 201 ]; then
        fail "human-system bootstrap answered $HS_CODE: $(hs_json '.code // .error // empty' '')"
        return 1
    fi
    dry || ok "created the single human-system user (stored in hs-db)"

    hs_call GET /api/v1/systems
    local key
    key=$(hs_json '[.. | objects | select(has("key")) | .key][0] // empty' '<first body system key>')
    [ -n "$key" ] || { fail "GET /api/v1/systems returned no system key (http $HS_CODE)"; return 1; }

    local body="issue-415 run $RUN_ID marker $(rand_hex 8)"
    hs_call POST /api/v1/system-notes -H 'Content-Type: application/json' \
        --data-binary "@$(body_json hsnote --arg k "$key" --arg d "$(date +%Y-%m-%d)" --arg b "$body" \
            '{system_key: $k, noted_on: $d, body: $b}')"
    local note_id
    note_id=$(hs_json '.id // empty' '<note id>')
    if ! dry && { [ "$HS_CODE" != 201 ] || [ -z "$note_id" ]; }; then
        fail "POST /api/v1/system-notes answered $HS_CODE"; return 1
    fi
    dry || ok "wrote a system note (hs-db)"

    # A PNG signature followed by per-run bytes: human-system sniffs the type
    # from the first bytes, and the rest makes this run's blob unique.
    printf '\211PNG\r\n\032\nissue-415 run %s %s\n' "$RUN_ID" "$(rand_hex 16)" > "$WORK/$px-marker.png"
    local doc_sha
    doc_sha=$(sha256_file "$WORK/$px-marker.png")
    hs_call POST /api/v1/documents -F "file=@$WORK/$px-marker.png;type=image/png"
    local doc_id
    doc_id=$(hs_json '.id // empty' '<document id>')
    if ! dry && { [ "$HS_CODE" != 201 ] || [ -z "$doc_id" ]; }; then
        fail "POST /api/v1/documents answered $HS_CODE: $(hs_json '.code // .error // empty' '')"; return 1
    fi
    dry || ok "uploaded a document (bytes in hs-data, row in hs-db)"

    eval "${px}_NOTE_ID=\$note_id; ${px}_NOTE_BODY=\$body; ${px}_DOC_ID=\$doc_id; ${px}_DOC_SHA=\$doc_sha"
}

# hs_verify_data PREFIX LABEL: sign in afresh and read back what was written
hs_verify_data() {
    local px=$1 label=$2 note_id note_body doc_id doc_sha
    eval "note_id=\${${px}_NOTE_ID:-}; note_body=\${${px}_NOTE_BODY:-}; doc_id=\${${px}_DOC_ID:-}; doc_sha=\${${px}_DOC_SHA:-}"
    hs_wait_ready || return 1
    HS_SESSION=""; HS_CSRF=""
    hs_call GET /api/v1/auth/me
    hs_call POST /api/v1/auth/login -H 'Content-Type: application/json' \
        --data-binary "@$(body_json hslogin --arg u "$HS_USER" --arg p "$HS_PASS" '{username: $u, password: $p}')"
    rm -f "$WORK/hslogin.json"
    check "$label: signed in with the password set at bootstrap (user in hs-db; app reached Postgres with db-password from hs-secrets)" \
        test "$HS_CODE" = 200 || return 1
    hs_call GET "/api/v1/system-notes/${note_id:-<note id>}"
    check "$label: the system note reads back byte for byte (hs-db)" \
        test "$(hs_json '.body // empty' '')" = "$note_body"
    if dry; then
        say "    HS     GET /api/v1/documents/<document id>/file"
        say "    check  $label: the document's bytes hash to what was uploaded (hs-data)"
        return 0
    fi
    curl -sS --max-time 60 -o "$WORK/$px-readback" \
        -H "Cookie: hs_session=$HS_SESSION; hs_csrf=$HS_CSRF" \
        "http://127.0.0.1:$LOCAL_PORT/api/v1/documents/$doc_id/file" 2>/dev/null || true
    say "    HS     GET /api/v1/documents/<id>/file"
    check "$label: the document's bytes hash to what was uploaded (hs-data)" \
        test "$(sha256_file "$WORK/$px-readback" 2>/dev/null)" = "$doc_sha"
}

# ---------------------------------------------------------------------------
# Composes: from the catalog's git history and the cluster's catalog
# ---------------------------------------------------------------------------

compose_app_digest() { awk -v p="$APP_IMAGE_PREFIX" '$1 == "image:" && index($2, p) == 1 {print $2; exit}' "$1"; }
compose_sidecar_image() { awk -v p="$SIDECAR_IMAGE_PREFIX" '$1 == "image:" && index($2, p) == 1 {print $2; exit}' "$1"; }
compose_volume_keys() { awk '/^volumes:/ {v=1; next} /^[^ #]/ {v=0} v && /^  [A-Za-z0-9_.-]+:[ \t]*$/ {gsub(/[ :\t]/, ""); print}' "$1" | sort; }

# rewrite_port IN OUT PORT: move the tile's loopback host port. Exactly one line changes.
rewrite_port() {
    local n
    n=$(grep -cxF -- "$TILE_PORT_LINE" "$1" || true)
    [ "$n" = 1 ] || { say "    the compose has $n lines equal to '$TILE_PORT_LINE', want exactly 1" >&2; return 1; }
    awk -v from="$TILE_PORT_LINE" -v to="      - \"127.0.0.1:$3:8080\"" '$0 == from {print to; next} {print}' "$1" > "$2"
    [ "$(wc -l < "$1")" = "$(wc -l < "$2")" ] || return 1
    [ "$(diff "$1" "$2" | grep -c '^[<>]')" = 2 ]
}

# rename_volume_key IN OUT FROM TO: rename one volume key in a service mount and
# at the top level. Exactly two lines change.
rename_volume_key() {
    local mount_from="      - $3:/data" mount_to="      - $4:/data" top_from="  $3:" top_to="  $4:"
    [ "$(grep -cxF -- "$mount_from" "$1" || true)" = 1 ] || return 1
    [ "$(grep -cxF -- "$top_from" "$1" || true)" = 1 ] || return 1
    awk -v a="$mount_from" -v b="$mount_to" -v c="$top_from" -v d="$top_to" \
        '$0 == a {print b; next} $0 == c {print d; next} {print}' "$1" > "$2"
    [ "$(wc -l < "$1")" = "$(wc -l < "$2")" ] || return 1
    [ "$(diff "$1" "$2" | grep -c '^[<>]')" = 4 ]
}

# ---------------------------------------------------------------------------
# Cleanup: only what this run created
# ---------------------------------------------------------------------------

cleanup() {
    local rc=$?
    close_tunnel
    if ! dry && [ "$KEEP" != 1 ] && [ -n "$CREATED" ]; then
        say ""
        hr
        say "[cleanup] apps this run created: $CREATED"
        hr
        local id j
        for id in $CREATED; do
            API_QUIET=1 api GET "/api/apps/$id"
            if [ "$API_CODE" = 200 ]; then
                api DELETE "/api/apps/$id" "$(body_json cdel '{deleteVolumes: true}')"
                if [ "$API_CODE" = 202 ]; then
                    j=$(jq -r '.id // empty' "$RESP")
                    [ -n "$j" ] && wait_job "$j" "cleanup delete of $id" || true
                else
                    say "    cleanup could not delete $id (http $API_CODE): delete it by hand, with volumes"
                fi
            fi
        done
        API_QUIET=1 api GET /api/volumes/orphans
        local names
        for id in $CREATED; do
            names=$(jq -c --arg a "$(upper "$id")" --arg n "$NODE" \
                '[.volumes[]? | select((.appId | ascii_upcase) == $a and .nodeId == $n) | .name]' "$RESP" 2>/dev/null || echo '[]')
            if [ "$names" != "[]" ] && [ -n "$names" ]; then
                api POST /api/volumes/orphans/reclaim \
                    "$(body_json creclaim --arg n "$NODE" --argjson v "$names" '{nodeId: $n, names: $v}')"
                API_QUIET=1 api GET /api/volumes/orphans
            fi
        done
    elif [ "$KEEP" = 1 ] && [ -n "$CREATED" ]; then
        say "--keep: left these apps in place; delete them (with volumes) yourself: $CREATED"
    fi
    rm -rf "$WORK"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# ===========================================================================
# Preflight against the cluster
# ===========================================================================

say "test-app-upgrade.sh: geekdojo/geekdojo-brain#415"
say "run id:   $RUN_ID"
say "cluster:  $CLUSTER"
say "api:      $API"
say "mode:     $([ "$DRY" = 1 ] && echo 'DRY RUN: nothing is executed against the cluster or the node' || echo 'REAL RUN on a bench cluster')"

if dry; then
    say ""
    say "PREFLIGHT (would run)"
    api GET /healthz
    api GET /api/setup/state
    say "    check  installName == '$CLUSTER', else refuse"
    api GET /api/nodes
    say "    check  ${NODE:-first online compute node by id} is role=compute, status=online, has a lanIP"
    api GET "/api/catalog/$TILE"
    api GET /api/catalog/_status
    NODE=${NODE:-<node-id>}
else
    API_QUIET=1 api GET /healthz
    [ "$API_CODE" = 200 ] || die "GET $API/healthz answered $API_CODE; is --api right, and does TLS need --cacert or --insecure?"
    API_QUIET=1 api GET /api/setup/state
    install_name=$(jq -r '.installName // empty' "$RESP")
    [ -n "$install_name" ] || die "the api reports no installName, so the cluster cannot be confirmed"
    [ "$install_name" = "$CLUSTER" ] || die "the api at $API is install '$install_name', not '$CLUSTER'"
    if [ -n "${RASPUTIN_NEVER_TARGET:-}" ]; then
        case ",$(lower "$RASPUTIN_NEVER_TARGET")," in
            *",$(lower "$install_name"),"*) die "install '$install_name' is listed in RASPUTIN_NEVER_TARGET" ;;
        esac
    fi
    API_QUIET=1 api GET /api/nodes
    [ "$API_CODE" = 200 ] || die "GET /api/nodes answered $API_CODE"
    if [ -z "$NODE" ]; then
        NODE=$(jq -r '[.[] | select(.role == "compute" and .status == "online" and (.lanIP // "") != "")] | sort_by(.id) | .[0].id // empty' "$RESP")
        [ -n "$NODE" ] || die "no online compute node with a lanIP in /api/nodes"
    fi
    node_row=$(jq -c --arg n "$NODE" '.[] | select(.id == $n)' "$RESP")
    [ -n "$node_row" ] || die "node '$NODE' is not in /api/nodes"
    [ "$(printf '%s' "$node_row" | jq -r .role)" = compute ] || die "node '$NODE' is not a compute node"
    [ "$(printf '%s' "$node_row" | jq -r .status)" = online ] || die "node '$NODE' is not online"
    node_ip >/dev/null || die "node '$NODE' has no usable lanIP in /api/nodes"
    node_reachable || die "cannot SSH to $NODE as $SSH_USER (BatchMode, key only), or docker does not answer there"
    API_QUIET=1 api GET "/api/catalog/$TILE"
    [ "$API_CODE" = 200 ] || die "GET /api/catalog/$TILE answered $API_CODE: the cluster's catalog does not carry the fixture tile"
fi
say "node:     $NODE"
say ""
say "Test apps this run will create: $A_NAME (chain A), $B_NAME (chain B)"

# --- composes -------------------------------------------------------------

say ""
say "COMPOSES"
git -C "$CATALOG_REPO" fetch -q origin 2>/dev/null || say "    (git fetch in $CATALOG_REPO failed; using the origin/main it already has)"
if dry; then
    git -C "$CATALOG_REPO" show "origin/main:$TILE_PATH" > "$WORK/tile-current.yml"
    say "    the cluster's tile compose is GET /api/catalog/$TILE .composeYaml; this dry run stands in origin/main's"
else
    API_QUIET=1 api GET "/api/catalog/$TILE"
    jq -j '.composeYaml // empty' "$RESP" > "$WORK/tile-current.yml"
    [ -s "$WORK/tile-current.yml" ] || die "the cluster's $TILE tile carries no composeYaml"
    TILE_STATUS=$(jq -r '.status // empty' "$RESP")
fi
CUR_SHA=$(sha256_file "$WORK/tile-current.yml")

HISTORY=$(git -C "$CATALOG_REPO" log --format='%h' origin/main -- "$TILE_PATH")
CUR_COMMIT=""
PREV_COMMIT=""
found=0
for c in $HISTORY; do
    git -C "$CATALOG_REPO" show "$c:$TILE_PATH" > "$WORK/hist.yml" 2>/dev/null || continue
    h=$(sha256_file "$WORK/hist.yml")
    if [ "$found" = 1 ] && [ -z "$PREV_COMMIT" ] && [ "$h" != "$CUR_SHA" ]; then
        PREV_COMMIT=$c
    fi
    if [ "$h" = "$CUR_SHA" ] && [ "$found" = 0 ]; then
        CUR_COMMIT=$c; found=1
    fi
done
if [ -n "$FROM_COMMIT" ]; then
    git -C "$CATALOG_REPO" show "$FROM_COMMIT:$TILE_PATH" > "$WORK/tile-old.yml" 2>/dev/null \
        || die "--from-commit $FROM_COMMIT has no $TILE_PATH in $CATALOG_REPO"
    FROM_USED=$FROM_COMMIT
else
    [ -n "$CUR_COMMIT" ] || die "the cluster's $TILE compose (sha256 $CUR_SHA) matches no commit on $CATALOG_REPO origin/main; pass --from-commit"
    [ -n "$PREV_COMMIT" ] || die "no older $TILE compose before $CUR_COMMIT in $CATALOG_REPO; pass --from-commit"
    git -C "$CATALOG_REPO" show "$PREV_COMMIT:$TILE_PATH" > "$WORK/tile-old.yml"
    FROM_USED=$PREV_COMMIT
fi
OLD_TILE_SHA=$(sha256_file "$WORK/tile-old.yml")
[ "$OLD_TILE_SHA" != "$CUR_SHA" ] || die "the older compose is identical to the cluster's current tile; pick another --from-commit"

say "    current (cluster tile): sha256 ${CUR_SHA}  catalog commit ${CUR_COMMIT:-<not found in history>}  $([ -n "$CUR_COMMIT" ] && git -C "$CATALOG_REPO" log -1 --format=%s "$CUR_COMMIT")"
say "        app image: $(compose_app_digest "$WORK/tile-current.yml")"
say "    older (from history):   sha256 ${OLD_TILE_SHA}  catalog commit ${FROM_USED}  $(git -C "$CATALOG_REPO" log -1 --format=%s "$FROM_USED")"
say "        app image: $(compose_app_digest "$WORK/tile-old.yml")"

FIXTURE_NOTES=""
[ "$(compose_app_digest "$WORK/tile-old.yml")" != "$(compose_app_digest "$WORK/tile-current.yml")" ] \
    || die "the older and current composes pin the same app image; the upgrade would not change the app"
if [ "$(compose_sidecar_image "$WORK/tile-old.yml")" != "$(compose_sidecar_image "$WORK/tile-current.yml")" ]; then
    FIXTURE_NOTES="the postgres sidecar image differs between the two composes, so this is not the 'only the app pin changed' case"
    say "    NOTE: $FIXTURE_NOTES"
fi
if [ "$(compose_volume_keys "$WORK/tile-old.yml")" != "$(compose_volume_keys "$WORK/tile-current.yml")" ]; then
    die "the two composes declare different volume keys; the #412 gate would refuse the upgrade itself. Pick another --from-commit"
fi
other=$(diff "$WORK/tile-old.yml" "$WORK/tile-current.yml" | grep '^[<>]' | grep -vcF "$APP_IMAGE_PREFIX" || true)
[ "$other" = 0 ] || say "    NOTE: the composes also differ in $other line(s) besides the app image pin"

A_PORT=$(rand_port)
rewrite_port "$WORK/tile-old.yml" "$WORK/a-old.yml" "$A_PORT" || die "could not move the loopback port in the older compose"
rewrite_port "$WORK/tile-current.yml" "$WORK/a-new.yml" "$A_PORT" || die "could not move the loopback port in the current compose"
A_OLD_SHA=$(sha256_file "$WORK/a-old.yml")
A_NEW_SHA=$(sha256_file "$WORK/a-new.yml")
A_OLD_IMAGE=$(compose_app_digest "$WORK/a-old.yml")
A_NEW_IMAGE=$(compose_app_digest "$WORK/a-new.yml")
rename_volume_key "$WORK/a-old.yml" "$WORK/a-gate.yml" hs-data hs-data-renamed \
    || die "could not build the renamed-volume-key compose (want exactly one '- hs-data:/data' and one top-level 'hs-data:')"
say "    chain A custom composes use loopback port $A_PORT: old sha256 $A_OLD_SHA, new sha256 $A_NEW_SHA"
say "    gate compose: the older compose with volume key hs-data renamed to hs-data-renamed (2 lines)"

# ===========================================================================
# E1: environment record
# ===========================================================================

step_begin E1 "Environment: node Docker and Compose versions, agent, catalog"
if dry; then
    node_ro docker version
    node_ro docker compose version
    api GET /api/catalog/_status
else
    API_QUIET=1 api GET /api/nodes
    jq -r --arg n "$NODE" '.[] | select(.id == $n) | "    node   \(.id) role=\(.role) arch=\(.architecture // "?") agent=\(.agentVersion) image=\(.imageVersion)"' "$RESP"
    say "    --- docker version (on $NODE) ---"
    if out=$(node_ro docker version 2>&1); then
        printf '%s\n' "$out" | sed 's/^/    | /'
        ok "recorded docker version"
    else
        fail "docker version did not run on $NODE: $out"
    fi
    say "    --- docker compose version (on $NODE) ---"
    if out=$(node_ro docker compose version 2>&1); then
        printf '%s\n' "$out" | sed 's/^/    | /'
        ok "recorded docker compose version"
    else
        fail "docker compose version did not run on $NODE: $out"
    fi
    API_QUIET=1 api GET /api/catalog/_status
    say "    catalog status: $(jq -c . "$RESP" | head -c 600)"
    say "    $TILE tile status in the catalog in effect: ${TILE_STATUS:-?}"
fi
[ -n "$FIXTURE_NOTES" ] && note "$FIXTURE_NOTES"
step_end

# ===========================================================================
# Chain A: custom app, edit, revert, gate, keep-data delete, reclaim
# ===========================================================================

A_ID=""
chain_a() {
    # --- A1 ---------------------------------------------------------------
    step_begin A1 "Create a custom app from the older compose ($FROM_USED) and deploy it"
    api POST /api/apps "$(body_json acreate --arg n "$A_NAME" --rawfile c "$WORK/a-old.yml" --arg t "$NODE" \
        --argjson l "$EXPOSE_LAN" '{name: $n, composeYaml: $c, targetNode: $t, exposeLan: $l}')"
    expect_code 201 || { step_end; return 1; }
    A_ID=$(jr '.id // empty' '<A id>')
    dry || { CREATED="$CREATED $A_ID"; info "app $A_NAME id $A_ID, compose project $(project_of "$A_ID")"; }
    api POST "/api/apps/$A_ID/deploy"
    expect_code 202 || { step_end; return 1; }
    wait_job "$(job_from_resp)" "deploy of $A_NAME" || { step_end; return 1; }
    wait_app_status "$A_ID" running || { step_end; return 1; }
    api GET "/api/apps/$A_ID"
    check "row composeSha256 is the older compose's ($A_OLD_SHA)" test "$(jr .composeSha256 '')" = "$A_OLD_SHA"
    check "row has no sourceTile (a custom app)" test -z "$(jr '.sourceTile // empty' '')"
    check "node: the app service runs the older image $A_OLD_IMAGE" test "$(node_service_image "$A_ID" app)" = "$A_OLD_IMAGE"
    node_volumes "$A_ID" > "$WORK/a-vols-1.txt"
    check "node: named volumes rasp_<id>_hs-data, _hs-db, _hs-secrets exist" \
        test "$(tr '\n' ' ' < "$WORK/a-vols-1.txt")" = "$(printf '%s_hs-data %s_hs-db %s_hs-secrets ' "$(project_of "$A_ID")" "$(project_of "$A_ID")" "$(project_of "$A_ID")")"
    step_end

    # --- A2 ---------------------------------------------------------------
    step_begin A2 "Write data into $A_NAME through human-system's api, and read it back"
    open_tunnel "$A_PORT" || { step_end; return 1; }
    hs_wait_ready || { step_end; return 1; }
    hs_write_data A || { step_end; return 1; }
    hs_verify_data A "baseline"
    # shellcheck disable=SC2046
    node_volume_identity $(cat "$WORK/a-vols-1.txt") > "$WORK/a-ident-1.txt"
    dry || sed 's/^/    volume /' "$WORK/a-ident-1.txt"
    step_end

    # --- A3 ---------------------------------------------------------------
    step_begin A3 "#410: PUT composeYaml with the cluster's current compose; data, ULID and volumes survive"
    api PUT "/api/apps/$A_ID/compose" "$(body_json aedit --rawfile c "$WORK/a-new.yml" '{composeYaml: $c}')"
    if ! dry && [ "$API_CODE" = 409 ]; then
        info "409 body: $(jq -c . "$RESP" | head -c 600)"
    fi
    expect_code 202 || { step_end; return 1; }
    wait_job "$(job_from_resp)" "compose edit of $A_NAME" || { step_end; return 1; }
    wait_app_status "$A_ID" running || { step_end; return 1; }
    api GET "/api/apps/$A_ID"
    check "row id is unchanged ($A_ID)" test "$(jr .id '')" = "$A_ID"
    check "row name is unchanged ($A_NAME)" test "$(jr .name '')" = "$A_NAME"
    check "row composeSha256 is the current compose's ($A_NEW_SHA)" test "$(jr .composeSha256 '')" = "$A_NEW_SHA"
    check "row revertAvailable is true" test "$(jr .revertAvailable '')" = true
    check "row previousComposeSha256 is the older compose's" test "$(jr '.previousComposeSha256 // empty' '')" = "$A_OLD_SHA"
    check "node: the app service now runs $A_NEW_IMAGE" test "$(node_service_image "$A_ID" app)" = "$A_NEW_IMAGE"
    check "node: the live compose file is the current compose" test "$(node_compose_sha "$A_ID")" = "$A_NEW_SHA"
    node_volumes "$A_ID" > "$WORK/a-vols-2.txt"
    # shellcheck disable=SC2046
    node_volume_identity $(cat "$WORK/a-vols-2.txt") > "$WORK/a-ident-2.txt"
    check "node: same volume names, same creation times (the same volumes, not new empty ones)" \
        cmp -s "$WORK/a-ident-1.txt" "$WORK/a-ident-2.txt"
    hs_verify_data A "after edit"
    api PUT "/api/apps/$A_ID/compose" "$(body_json aedit2 --rawfile c "$WORK/a-new.yml" '{composeYaml: $c}')"
    check "the same composeYaml again is the 200 no-op" test "$API_CODE" = 200 -o "$API_CODE" = DRY
    step_end

    # --- A4 ---------------------------------------------------------------
    step_begin A4 "#411: PUT sha256 of the previous compose (revert); data survives"
    info "an older image cannot undo a database migration the newer one ran; if the two releases' migrations differ, this revert can fail for that reason"
    api PUT "/api/apps/$A_ID/compose" "$(body_json arevert --arg s "$A_OLD_SHA" '{sha256: $s}')"
    expect_code 202 || { step_end; return 1; }
    wait_job "$(job_from_resp)" "revert of $A_NAME" || { step_end; return 1; }
    wait_app_status "$A_ID" running || { step_end; return 1; }
    api GET "/api/apps/$A_ID"
    check "row id is unchanged" test "$(jr .id '')" = "$A_ID"
    check "row composeSha256 is the older compose's again" test "$(jr .composeSha256 '')" = "$A_OLD_SHA"
    check "row previousComposeSha256 is now the current compose's" test "$(jr '.previousComposeSha256 // empty' '')" = "$A_NEW_SHA"
    check "node: the app service runs $A_OLD_IMAGE again" test "$(node_service_image "$A_ID" app)" = "$A_OLD_IMAGE"
    node_volumes "$A_ID" > "$WORK/a-vols-3.txt"
    # shellcheck disable=SC2046
    node_volume_identity $(cat "$WORK/a-vols-3.txt") > "$WORK/a-ident-3.txt"
    check "node: same volume names and creation times" cmp -s "$WORK/a-ident-1.txt" "$WORK/a-ident-3.txt"
    hs_verify_data A "after revert"
    step_end

    # --- A5 ---------------------------------------------------------------
    step_begin A5 "#412: a compose that renames the hs-data key is refused with 409 and changes nothing"
    api GET "/api/apps/$A_ID"
    local row_sha row_status
    row_sha=$(jr .composeSha256 '<sha>'); row_status=$(jr .lastStatus '<status>')
    node_containers_started "$A_ID" > "$WORK/a-gate-c1.txt"
    # shellcheck disable=SC2046
    node_volume_identity $(node_volumes "$A_ID") > "$WORK/a-gate-v1.txt"
    local live1
    live1=$(node_compose_sha "$A_ID")
    api PUT "/api/apps/$A_ID/compose" "$(body_json agate --rawfile c "$WORK/a-gate.yml" '{composeYaml: $c}')"
    if ! dry && [ "$API_CODE" = 202 ]; then
        fail "api answered 202: the advisory check got no node answer and fell open to the job; waiting for the job's authoritative refusal"
        wait_job "$(job_from_resp)" "gate compose on $A_NAME (expected to FAIL)" && fail "the job SUCCEEDED: the renamed key was applied" || info "the job refused, as the saga's gate should"
    else
        expect_code 409
        dry || info "409 body: $(jq -c . "$RESP" | head -c 600)"
        check "409 droppedVolumes names $(project_of "$A_ID")_hs-data with key hs-data" \
            test "$(jq -r --arg n "$(project_of "$A_ID")_hs-data" '[.droppedVolumes[]? | select(.name == $n and .volume == "hs-data")] | length' "$RESP" 2>/dev/null)" = 1
    fi
    api GET "/api/apps/$A_ID"
    check "row composeSha256 unchanged" test "$(jr .composeSha256 '')" = "$row_sha"
    check "row lastStatus unchanged ($row_status)" test "$(jr .lastStatus '')" = "$row_status"
    node_containers_started "$A_ID" > "$WORK/a-gate-c2.txt"
    # shellcheck disable=SC2046
    node_volume_identity $(node_volumes "$A_ID") > "$WORK/a-gate-v2.txt"
    check "node: same containers, same ids, same start times, same images" cmp -s "$WORK/a-gate-c1.txt" "$WORK/a-gate-c2.txt"
    check "node: same volumes, same creation times" cmp -s "$WORK/a-gate-v1.txt" "$WORK/a-gate-v2.txt"
    check "node: the live compose file is unchanged" test "$(node_compose_sha "$A_ID")" = "$live1"
    check "node: no volume $(project_of "$A_ID")_hs-data-renamed was created" \
        not node_volume_exists "$(project_of "$A_ID")_hs-data-renamed"
    step_end

    # --- A6 ---------------------------------------------------------------
    step_begin A6 "#413: DELETE with deleteVolumes:false keeps every volume and lists each as an orphan"
    close_tunnel
    node_volumes "$A_ID" > "$WORK/a-del-vols.txt"
    node_anon_record "$A_ID" > "$WORK/a-del-anon.txt"
    dry || info "named volumes: $(tr '\n' ' ' < "$WORK/a-del-vols.txt"); anonymous recorded: $(wc -l < "$WORK/a-del-anon.txt" | tr -d ' ')"
    api DELETE "/api/apps/$A_ID" "$(body_json adel '{deleteVolumes: false}')"
    expect_code 202 || { step_end; return 1; }
    wait_job "$(job_from_resp)" "keep-data delete of $A_NAME" || { step_end; return 1; }
    api GET "/api/apps/$A_ID"
    check "the app row is gone (404)" test "$API_CODE" = 404 -o "$API_CODE" = DRY
    check "node: no container of project $(project_of "$A_ID") remains" test -z "$(node_containers "$A_ID")"
    local v missing=""
    if ! dry; then
        for v in $(cat "$WORK/a-del-vols.txt" "$WORK/a-del-anon.txt"); do
            node_volume_exists "$v" || missing="$missing $v"
        done
    fi
    check "node: every named and recorded anonymous volume is still there${missing:+ (missing:$missing)}" test -z "$missing"
    api GET /api/volumes/orphans
    local listed notlisted=""
    listed=$(jq -r --arg a "$(upper "$A_ID")" --arg n "$NODE" \
        '.volumes[]? | select((.appId | ascii_upcase) == $a and .nodeId == $n) | .name' "$RESP" 2>/dev/null | sort)
    printf '%s\n' "$listed" | sed '/^$/d' > "$WORK/a-orphans.txt"
    if ! dry; then
        for v in $(cat "$WORK/a-del-vols.txt" "$WORK/a-del-anon.txt"); do
            grep -qxF "$v" "$WORK/a-orphans.txt" || notlisted="$notlisted $v"
        done
    fi
    check "GET /api/volumes/orphans lists every kept volume${notlisted:+ (not listed:$notlisted)}" test -z "$notlisted"
    check "GET /api/volumes/orphans did not report $NODE unreachable" \
        test "$(jq -r --arg n "$NODE" '[.unreachable[]? | select(.nodeId == $n)] | length' "$RESP" 2>/dev/null || echo 0)" = 0
    residue "$A_ID" "keep-data delete"
    step_end

    # --- A7 ---------------------------------------------------------------
    step_begin A7 "#413: reclaim the orphans; no volume of $A_NAME remains"
    local names
    names=$(jq -Rn '[inputs | select(length > 0)]' < "$WORK/a-orphans.txt")
    dry && names='["<every orphan listed for A on the node>"]'
    api POST /api/volumes/orphans/reclaim "$(body_json areclaim --arg n "$NODE" --argjson v "$names" '{nodeId: $n, names: $v}')"
    expect_code 200
    check "reclaim ok:true with nothing refused" test "$(jr '"\(.ok) \(.refused | length)"' '')" = "true 0"
    check "reclaim removed every listed orphan" \
        test "$(jr '.removed | sort | join(" ")' '')" = "$(tr '\n' ' ' < "$WORK/a-orphans.txt" | sed 's/ $//')"
    check "node: no volume of project $(project_of "$A_ID") remains" test -z "$(node_volumes "$A_ID")"
    missing=""
    if ! dry; then
        for v in $(cat "$WORK/a-del-anon.txt"); do
            node_volume_exists "$v" && missing="$missing $v"
        done
    fi
    check "node: no recorded anonymous volume remains${missing:+ (still there:$missing)}" test -z "$missing"
    api GET /api/volumes/orphans
    check "GET /api/volumes/orphans lists nothing for $A_ID" \
        test "$(jq -r --arg a "$(upper "$A_ID")" '[.volumes[]? | select((.appId | ascii_upcase) == $a)] | length' "$RESP" 2>/dev/null || echo 0)" = 0
    residue "$A_ID" "after reclaim"
    dry || CREATED=$(printf '%s' "$CREATED" | sed "s/ $A_ID//")
    step_end
}

# residue APP_ID LABEL: record what #421 will fix, as KNOWN
residue() {
    local id=$1 label=$2 out
    if dry; then
        node_ro docker network ls --filter "label=com.docker.compose.project=$(project_of "$id")" --format '{{.Name}}' 2>&1
        node_ro test -d "$AGENT_STATE_DIR/apps/$id" 2>&1
        node_ro test -d "$AGENT_STATE_DIR/proxy/certs/$id" 2>&1
        node_ro docker image ls --digests --format '{{.Repository}}@{{.Digest}}|{{.ID}}' 2>&1
        say "    record KNOWN residue (#421): networks, $AGENT_STATE_DIR/apps/<id>, proxy/certs/<id>, images the composes named"
        return 0
    fi
    out=$(node_networks "$id" | tr '\n' ' ')
    if [ -n "$out" ]; then known "$label: project networks remain: $out(#421 class 5)"; else ok "$label: no project network remains"; fi
    if node_ro test -d "$AGENT_STATE_DIR/apps/$id"; then
        known "$label: agent directory $AGENT_STATE_DIR/apps/$id remains (#421 class 1)"
    else
        ok "$label: agent directory $AGENT_STATE_DIR/apps/$id is gone"
    fi
    if node_ro test -d "$AGENT_STATE_DIR/proxy/certs/$id"; then
        known "$label: leaf directory $AGENT_STATE_DIR/proxy/certs/$id remains (#421 class 6)"
    else
        ok "$label: no leaf directory for $id"
    fi
    out=$(node_images_for "$WORK/tile-old.yml" "$WORK/tile-current.yml" | tr '\n' ' ')
    if [ -n "$out" ]; then
        known "$label: images the composes named are still on the node (#421 class 3; another app may share them): $out"
    else
        ok "$label: no image the composes named is on the node"
    fi
}

# ===========================================================================
# Chain B: catalog install, catalog upgrade, delete with data
# ===========================================================================

B_ID=""
B_KIND=""
B_WHY=""
chain_b() {
    # --- B1 ---------------------------------------------------------------
    step_begin B1 "Install human-system for chain B, deploy it, and write data"
    local b_port
    if [ "$SKIP_CATALOG" = 1 ]; then
        B_KIND=custom; B_WHY="--skip-catalog was passed"
    elif ! dry && [ "${TILE_STATUS:-}" != available ]; then
        B_KIND=custom; B_WHY="the $TILE tile's status in the catalog in effect is '${TILE_STATUS:-?}', not available"
    elif ! dry && node_port_published "$TILE_HOST_PORT"; then
        B_KIND=custom; B_WHY="$NODE already publishes port $TILE_HOST_PORT (another $TILE install?), and the tile's port is fixed"
    else
        B_KIND=catalog
    fi
    if dry; then
        say "    check  node port $TILE_HOST_PORT is free (docker ps .Ports); if taken, or --skip-catalog, chain B uses a custom app"
    fi
    if [ "$B_KIND" = catalog ]; then
        api POST "/api/catalog/$TILE/install" "$(body_json binstall --arg t "$NODE" --arg n "$B_NAME" \
            --argjson l "$EXPOSE_LAN" '{targetNode: $t, name: $n, exposeLan: $l, acknowledgeNoBackup: true}')"
        b_port=$TILE_HOST_PORT
    else
        info "chain B uses a custom app: $B_WHY"
        b_port=$(rand_port)
        rewrite_port "$WORK/tile-current.yml" "$WORK/b-new.yml" "$b_port"
        api POST /api/apps "$(body_json bcreate --arg n "$B_NAME" --rawfile c "$WORK/b-new.yml" --arg t "$NODE" \
            --argjson l "$EXPOSE_LAN" '{name: $n, composeYaml: $c, targetNode: $t, exposeLan: $l}')"
    fi
    expect_code 201 || { step_end; return 1; }
    B_ID=$(jr '.id // empty' '<B id>')
    dry || { CREATED="$CREATED $B_ID"; info "app $B_NAME ($B_KIND) id $B_ID"; }
    api POST "/api/apps/$B_ID/deploy"
    expect_code 202 || { step_end; return 1; }
    wait_job "$(job_from_resp)" "deploy of $B_NAME" || { step_end; return 1; }
    wait_app_status "$B_ID" running || { step_end; return 1; }
    open_tunnel "$b_port" || { step_end; return 1; }
    hs_wait_ready || { step_end; return 1; }
    hs_write_data B || { step_end; return 1; }
    hs_verify_data B "baseline"
    note "$B_KIND install${B_WHY:+: $B_WHY}"
    step_end
}

chain_b_upgrade() {
    # --- B2 ---------------------------------------------------------------
    step_begin B2 "#409: catalog upgrade in place (runs only when upgradeAvailable is true)"
    if [ "$B_KIND" != catalog ]; then
        info "not exercised: chain B has no catalog install ($B_WHY)"
        note "no catalog install: $B_WHY"
        step_end "NOT EXERCISED"
        return 0
    fi
    api GET "/api/apps/$B_ID"
    local avail
    avail=$(jr .upgradeAvailable '<true|false>')
    if dry; then
        say "    if upgradeAvailable is false (a fresh catalog install always copies the current tile):"
        api PUT "/api/apps/$B_ID/compose" "$(body_json src '{source: "catalog"}')"
        say "    check  {\"source\":\"catalog\"} answers the 200 no-op; step reports NOT EXERCISED"
        say "    if upgradeAvailable is true:"
        say "    check  volumes identity, then PUT {\"source\":\"catalog\"} -> 202, job succeeds, app running,"
        say "           same ULID, upgradeAvailable false, composeSha256 = tile compose, same volumes and creation times,"
        say "           app image = the tile's digest, data reads back"
        step_end
        return 0
    fi
    info "upgradeAvailable=$avail composeSha256=$(jr .composeSha256 '') upgradeCatalogVersion=$(jr '.upgradeCatalogVersion // "-"' '')"
    body_json src '{source: "catalog"}' >/dev/null
    if [ "$avail" != true ]; then
        api PUT "/api/apps/$B_ID/compose" "$WORK/src.json"
        check '{"source":"catalog"} on a current catalog app is the 200 no-op' test "$API_CODE" = 200
        info "NOT EXERCISED: the install's compose is already the cluster's current tile. See 'Why the catalog path usually reports NOT EXERCISED' in --help"
        note "installed compose is the current tile (catalog install copies the current tile); the no-op branch was checked"
        step_end "NOT EXERCISED"
        return 0
    fi
    # shellcheck disable=SC2046
    node_volume_identity $(node_volumes "$B_ID") > "$WORK/b-ident-1.txt"
    api PUT "/api/apps/$B_ID/compose" "$WORK/src.json"
    [ "$API_CODE" = 409 ] && info "409 body: $(jq -c . "$RESP" | head -c 600)"
    expect_code 202 || { step_end; return 1; }
    wait_job "$(job_from_resp)" "catalog upgrade of $B_NAME" || { step_end; return 1; }
    wait_app_status "$B_ID" running || { step_end; return 1; }
    API_QUIET=1 api GET "/api/catalog/$TILE"
    jq -j '.composeYaml // empty' "$RESP" > "$WORK/tile-now.yml"
    api GET "/api/apps/$B_ID"
    check "row id is unchanged" test "$(jr .id '')" = "$B_ID"
    check "row upgradeAvailable is now false" test "$(jr .upgradeAvailable '')" = false
    check "row composeSha256 is the tile's compose" test "$(jr .composeSha256 '')" = "$(sha256_file "$WORK/tile-now.yml")"
    check "row revertAvailable is true" test "$(jr .revertAvailable '')" = true
    check "node: the app service runs the tile's image" test "$(node_service_image "$B_ID" app)" = "$(compose_app_digest "$WORK/tile-now.yml")"
    # shellcheck disable=SC2046
    node_volume_identity $(node_volumes "$B_ID") > "$WORK/b-ident-2.txt"
    check "node: same volume names and creation times" cmp -s "$WORK/b-ident-1.txt" "$WORK/b-ident-2.txt"
    hs_verify_data B "after catalog upgrade"
    step_end
}

chain_b_delete() {
    # --- B3 ---------------------------------------------------------------
    step_begin B3 "#413: DELETE with deleteVolumes:true; nothing of $B_NAME remains on the node"
    close_tunnel
    node_volumes "$B_ID" > "$WORK/b-del-vols.txt"
    node_anon_record "$B_ID" > "$WORK/b-del-anon.txt"
    dry || info "named volumes: $(tr '\n' ' ' < "$WORK/b-del-vols.txt"); anonymous recorded: $(wc -l < "$WORK/b-del-anon.txt" | tr -d ' ')"
    api DELETE "/api/apps/$B_ID" "$(body_json bdel '{deleteVolumes: true}')"
    expect_code 202 || { step_end; return 1; }
    wait_job "$(job_from_resp)" "delete-with-data of $B_NAME" || { step_end; return 1; }
    api GET "/api/apps/$B_ID"
    check "the app row is gone (404)" test "$API_CODE" = 404 -o "$API_CODE" = DRY
    check "node: no container of project $(project_of "$B_ID") remains" test -z "$(node_containers "$B_ID")"
    check "node: no volume by project label or rasp_<id>_ name remains" test -z "$(node_volumes "$B_ID")"
    local v left=""
    if ! dry; then
        for v in $(cat "$WORK/b-del-vols.txt" "$WORK/b-del-anon.txt"); do
            node_volume_exists "$v" && left="$left $v"
        done
    fi
    check "node: none of the volumes it had before the delete remains${left:+ (still there:$left)}" test -z "$left"
    api GET /api/volumes/orphans
    check "GET /api/volumes/orphans lists nothing for $B_ID" \
        test "$(jq -r --arg a "$(upper "$B_ID")" '[.volumes[]? | select((.appId | ascii_upcase) == $a)] | length' "$RESP" 2>/dev/null || echo 0)" = 0
    residue "$B_ID" "delete-with-data"
    dry || CREATED=$(printf '%s' "$CREATED" | sed "s/ $B_ID//")
    step_end
}

if chain_a; then :; else
    say "  chain A stopped at [$CUR_ID]; later chain A steps are not run"
    for s in A1 A2 A3 A4 A5 A6 A7; do
        grep -q "^$s$TAB" "$WORK/steps.tsv" || step_blocked "$s" "chain A" "an earlier chain A step failed"
    done
fi
close_tunnel

if chain_b; then
    chain_b_upgrade || true
    chain_b_delete || true
else
    say "  chain B stopped at [$CUR_ID]; later chain B steps are not run"
    for s in B2 B3; do
        grep -q "^$s$TAB" "$WORK/steps.tsv" || step_blocked "$s" "chain B" "B1 failed"
    done
fi
close_tunnel

# ===========================================================================
# Summary
# ===========================================================================

say ""
hr
say "SUMMARY  run $RUN_ID  cluster $CLUSTER  node $NODE  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
hr
say ""
say "| Step | What | Result | Note |"
say "|---|---|---|---|"
while IFS=$TAB read -r sid stitle sres snote; do
    printf '| %s | %s | %s | %s |\n' "$sid" "$stitle" "$sres" "$snote"
done < "$WORK/steps.tsv"
say ""
say "KNOWN means residue geekdojo/geekdojo-brain#421 has not fixed yet; it does not fail the run."
say "NOT EXERCISED means the path could not be reached legitimately on this cluster; see --help."

if dry; then
    say "Dry run: nothing was executed against $CLUSTER or its nodes."
    exit 0
fi
if grep -q "${TAB}FAIL${TAB}" "$WORK/steps.tsv"; then
    exit 1
fi
exit 0
