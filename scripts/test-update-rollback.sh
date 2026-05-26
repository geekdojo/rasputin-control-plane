#!/usr/bin/env bash
# test-update-rollback.sh — exercise the OS update saga end-to-end
# against the mock backend. Covers Phase 2's "rolls back on simulated
# failure" exit-gate criterion.
#
# Prereqs:
#   - rasputin-api running at $API (default http://localhost:8080)
#   - one rasputin-agent already registered as $NODE_ID (default node-dev)
#     with RASPUTIN_UPDATE_BACKEND=mock
#   - a session cookie jar at $COOKIES (default ./cookies.txt) for the
#     authenticated API calls (use scripts/dev-login.sh or curl the auth
#     endpoints to populate it)
#   - the PKI bootstrapped + a leaf cert available
#   - root-ca.pem copied to data/trust/root-ca.pem so the api verifies
#
# Each scenario:
#   1. builds a fresh mock bundle with a unique version
#   2. uploads it
#   3. starts a node.update job
#   4. polls the job to completion
#   5. asserts the expected outcome (committed | rolled_back)
#
# Scenarios:
#   A — kernel panic in new slot     (RASPUTIN_UPDATE_FAIL_MODE=panic)
#   B — userspace health-check fail   (RASPUTIN_UPDATE_FAIL_MODE=health)
#   C — network loss during download  (RASPUTIN_UPDATE_FAIL_MODE=download)

set -euo pipefail

API=${API:-http://localhost:8080}
NODE_ID=${NODE_ID:-node-dev}
COOKIES=${COOKIES:-./cookies.txt}
PKI=${PKI:-./pki-out}

cdir=$(mktemp -d)
trap 'rm -rf "$cdir"' EXIT

if [[ ! -f $COOKIES ]]; then
    echo "error: $COOKIES not found. Authenticate first." >&2
    exit 2
fi
if [[ ! -f $PKI/leaf-001.key || ! -f $PKI/leaf-001.pem ]]; then
    echo "error: $PKI/leaf-001.{key,pem} not found. Run scripts/pki-init.sh." >&2
    exit 2
fi

curl_auth() {
    curl -sS -b "$COOKIES" "$@"
}

wait_job() {
    local job_id=$1 deadline=$(( $(date +%s) + 600 ))
    while true; do
        local status
        status=$(curl_auth "$API/api/jobs/$job_id" | jq -r .status)
        case $status in
            succeeded|failed|cancelled)
                echo "$status"
                return
                ;;
        esac
        if (( $(date +%s) > deadline )); then
            echo "timeout"
            return
        fi
        sleep 1
    done
}

run_scenario() {
    local name=$1 fail_mode=$2 expect=$3 desc=$4
    echo
    echo "=== Scenario $name: $desc ==="
    echo "    RASPUTIN_UPDATE_FAIL_MODE=$fail_mode  expected outcome: $expect"

    # 1. Build the bundle.
    local version="0.test-$name-$(date +%s)"
    local bundle="$cdir/bundle-$name.raspbundle"
    ./scripts/build-bundle.sh \
        --version "$version" \
        --out "$bundle" \
        --leaf-cert "$PKI/leaf-001.pem" \
        --leaf-key "$PKI/leaf-001.key" \
        --description "test scenario $name" \
        >/dev/null

    # 2. Upload.
    local upload_resp
    upload_resp=$(curl_auth -X POST \
        -H 'Content-Type: application/octet-stream' \
        --data-binary "@$bundle" \
        "$API/api/bundles")
    local sha
    sha=$(echo "$upload_resp" | jq -r .sha256)
    if [[ -z $sha || $sha == null ]]; then
        echo "    FAIL: upload returned no sha256: $upload_resp"
        return 1
    fi
    echo "    bundle uploaded: $sha"

    # 3. Set the fail-mode env on the agent.
    #    The dev harness expects the operator to have the agent under
    #    `direnv` or a small wrapper that reads RASPUTIN_UPDATE_FAIL_MODE
    #    from a file. We write the file and instruct the operator to
    #    restart the agent before running. To avoid that ceremony every
    #    time, the mock backend re-reads RASPUTIN_UPDATE_FAIL_MODE at
    #    *every relevant operation* (download, reboot) — set it in the
    #    same shell that's running the agent, then re-run this script.
    if [[ ${RASPUTIN_UPDATE_FAIL_MODE:-} != "$fail_mode" ]]; then
        echo "    NOTE: this scenario expects the agent to be started with"
        echo "          RASPUTIN_UPDATE_FAIL_MODE=$fail_mode"
        echo "          (export it in the agent's shell, then re-run)."
    fi

    # 4. Submit the update job.
    local job_resp
    job_resp=$(curl_auth -X POST \
        -H 'Content-Type: application/json' \
        -d "{\"nodeId\": \"$NODE_ID\", \"bundleSha256\": \"$sha\"}" \
        "$API/api/updates")
    local job_id
    job_id=$(echo "$job_resp" | jq -r .id)
    echo "    job: $job_id"

    # 5. Wait + assert.
    local status
    status=$(wait_job "$job_id")
    echo "    final job status: $status"
    local nu
    nu=$(curl_auth "$API/api/updates?nodeId=$NODE_ID&limit=1" | jq -r ".[0].status")
    echo "    update row status: $nu"

    if [[ $nu == "$expect" ]]; then
        echo "    PASS"
        return 0
    else
        echo "    FAIL: expected '$expect', got '$nu'"
        return 1
    fi
}

passed=0
failed=0

run_scenario A panic    rolled_back "bootloader watchdog reverts on kernel panic" \
    && passed=$((passed + 1)) || failed=$((failed + 1))

run_scenario B health   rolled_back "health check fails → mark-bad → revert to old slot" \
    && passed=$((passed + 1)) || failed=$((failed + 1))

run_scenario C download rolled_back "network loss → download retries → job fails before any slot mutation" \
    && passed=$((passed + 1)) || failed=$((failed + 1))

echo
echo "=== Results: $passed passed, $failed failed ==="
exit $failed
