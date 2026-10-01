#!/usr/bin/env bash
# test-bus-tls.sh — the bus TLS functional tests (geekdojo/geekdojo-brain#448,
# #517), run alone and verbosely. CI runs the same tests with the rest of
# ./api/...
#
# What runs (api/internal/bustls/functional_test.go and
# functional_api_test.go): the real embedded bus, TLS required, with the auth
# callout enforced; the real inventory and join-token store; and the REAL
# rasputin-agent and rasputin-api binaries, built from this workspace:
#
#   * the controlplane's own agent joins from the pin file its api writes, a
#     compute node from its seeded pin, and a node migrated in place from the
#     pin file an older agent saved — which nothing changes;
#   * nothing on a node answers the retired bus.pin verb;
#   * an agent with no usable pin exits FATAL and never dials;
#   * a controlplane agent started before its pin file exists joins on the
#     unit's restart; one pinned to a key a restore replaced refuses the new
#     key, logs why, and joins after a restart;
#   * the real api refuses plaintext on the wire whatever a stale mode row or
#     RASPUTIN_BUS_TLS says, and warns once about the variable;
#   * the real api with an unusable bus key, or certificate, keeps running
#     with no bus listener, a crit alert naming the file, and coded 503s;
#   * clock independence, the controlplane agent's minted token, and the
#     persisted bus certificate;
#   * the real api records every node that registers at the first moment the
#     bus admits it, once, during start-up (geekdojo/geekdojo-brain#623).
#
# --compat instead builds rasputin-agent and rasputin-api from the floor
# release tag (v2026.09.5) and runs the -tags buscompat tests against them:
# the floor agent on this api, and this agent on the floor api. It fails on a
# missing tag, a failed build, any skipped or failed test, or fewer than two
# top-level TestCompat* passes. The backend CI job runs exactly this.
#
# No bench, no hardware, no root. What it does NOT cover: the OS firstboot and
# firewall apply-seed consumers, mDNS, real hardware clocks — see the PR's
# bench plan.
#
# Usage:
#   scripts/test-bus-tls.sh [extra go test flags]
#   scripts/test-bus-tls.sh --compat

set -euo pipefail
cd "$(dirname "$0")/.."

export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.4}"

if [ "${1:-}" != "--compat" ]; then
	exec go test -count=1 -race -v -run 'TestFunctional' ./api/internal/bustls/ "$@"
fi

floor_tag="v2026.09.5"
if ! git rev-parse -q --verify "refs/tags/${floor_tag}^{commit}" >/dev/null; then
	echo "test-bus-tls: tag ${floor_tag} is not in this clone; fetch it with: git fetch --depth=1 origin tag ${floor_tag}" >&2
	exit 1
fi

work="$(mktemp -d)"
src="${work}/src"
cleanup() {
	git worktree remove --force "${src}" >/dev/null 2>&1 || true
	rm -rf "${work}"
}
trap cleanup EXIT

git worktree add --detach "${src}" "${floor_tag}" >/dev/null
echo "test-bus-tls: building the floor binaries from ${floor_tag} ($(git -C "${src}" rev-parse HEAD))"
for bin in agent api; do
	if ! (cd "${src}" && env -u GOWORK go build -o "${work}/rasputin-${bin}" "./${bin}/cmd/rasputin-${bin}"); then
		echo "test-bus-tls: go build rasputin-${bin} from ${floor_tag} failed" >&2
		exit 1
	fi
done

go vet -tags buscompat ./api/internal/bustls/

results="${work}/compat.json"
RASPUTIN_BUSCOMPAT_OLD_AGENT="${work}/rasputin-agent" \
RASPUTIN_BUSCOMPAT_OLD_API="${work}/rasputin-api" \
	go test -count=1 -race -tags buscompat -json -run '^TestCompat' ./api/internal/bustls/ | tee "${results}"

python3 - "${results}" <<'PY'
import json, sys

passed, failed, skipped = set(), set(), set()
for line in open(sys.argv[1], encoding="utf-8"):
    line = line.strip()
    if not line.startswith("{"):
        continue
    ev = json.loads(line)
    test, action = ev.get("Test"), ev.get("Action")
    if not test:
        if action == "fail":
            failed.add("(package)")
        continue
    if action == "fail":
        failed.add(test)
    elif action == "skip":
        skipped.add(test)
    elif action == "pass" and "/" not in test and test.startswith("TestCompat"):
        passed.add(test)

problems = []
if failed:
    problems.append("failed: " + ", ".join(sorted(failed)))
if skipped:
    problems.append("skipped (a skip is not a pass): " + ", ".join(sorted(skipped)))
if len(passed) < 2:
    problems.append(f"{len(passed)} top-level TestCompat* test(s) passed, want at least 2: {sorted(passed)}")
if problems:
    for p in problems:
        print("test-bus-tls: " + p, file=sys.stderr)
    sys.exit(1)
print("test-bus-tls: compatibility passed: " + ", ".join(sorted(passed)))
PY
