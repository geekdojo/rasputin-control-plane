#!/usr/bin/env bash
#
# identity-on-mac.sh — a signed-in console on a Mac, through the real
# sign-in (geekdojo/geekdojo-brain#989). It runs the console stack test,
# TestIdentitySystemd_ConsoleSignIn, in hold mode inside a container with
# systemd as PID 1: the real rasputin-api built from this tree, serving the
# UI export built from this tree, against the pinned Keycloak and PostgreSQL
# as keycloak.service and keycloak-db.service. A synthetic fixture account
# (never a real person's) signs in through the launcher's route, and its
# session cookie is written to data/identity-on-mac/session.cookie (0600).
#
# Usage:
#   scripts/identity-on-mac.sh up [--api-env K=V]...   build and start; prints /api/auth/me
#   scripts/identity-on-mac.sh shots PATH...            screenshot console pages, signed in
#   scripts/identity-on-mac.sh down                     stop and remove everything it started
#
# Needs: Docker (Rancher Desktop or Docker Desktop) running, and Go on the
# Mac for `shots`. Everything else is fetched and checked by hash: the
# container's Go and Node (identity-on-mac.Dockerfile), the identity service
# and its runtime (scripts/install-identity.sh), and the screenshot browser
# (api/internal/identitytest/cmd/consoleshots). Nothing is written into
# rasputin.db by hand, and there is no sign-in bypass: the session comes
# from the real sign-in only.
#
# The api's https listener is on 127.0.0.1:9443 as ci.local. The identity
# service's back-channel logout posts to port 443, so that leg is not live
# here; CI and the bench prove it.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
out="$repo/data/identity-on-mac"
name="rasputin-identity-on-mac"
image="rasputin-identity-on-mac:local"
port=9443

# up_deadline bounds the wait for the stack: image build, installs, builds,
# and Keycloak's start under emulation (measured at 172 s). It bounds the
# wait only; the fact waited on is the test's ready file, and the wait also
# ends at once if the container or the test stops.
up_deadline=$((60 * 60))
# down_deadline bounds the wait for the test's own teardown to finish.
down_deadline=$((10 * 60))

die() { echo "identity-on-mac: $*" >&2; exit 1; }

running() { [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || true)" = "true" ]; }

# inside CMD...: run CMD in the container at the repo root.
inside() { docker exec -w "$repo" "$name" "$@"; }

up() {
  local api_env=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --api-env)
        [ "$#" -ge 2 ] || die "--api-env needs K=V"
        case "$2" in *=*) ;; *) die "--api-env needs K=V, got $2" ;; esac
        api_env+="$2"$'\n'
        shift 2
        ;;
      *) die "unknown argument $1 (usage: up [--api-env K=V]...)" ;;
    esac
  done
  command -v docker >/dev/null || die "docker is not installed: install Rancher Desktop or Docker Desktop"
  docker info >/dev/null 2>&1 || die "docker is not running: start Rancher Desktop or Docker Desktop"
  if docker inspect "$name" >/dev/null 2>&1; then
    die "a stack is already up ($name); run: scripts/identity-on-mac.sh down"
  fi
  local kc_platform=""
  case "$(docker info -f '{{.Architecture}}')" in
    aarch64|arm64) kc_platform="linux/amd64" ;;
  esac
  mkdir -p "$out"
  rm -f "$out/ready" "$out/stop" "$out/exit" "$out/me.json" "$out/session.cookie" "$out/api-spki"

  echo "identity-on-mac: building the container image"
  docker build -q -t "$image" -f "$repo/scripts/identity-on-mac.Dockerfile" "$repo/scripts" >/dev/null
  docker run -d --name "$name" --privileged --cgroupns=host --network host \
    -v /var/run/docker.sock:/var/run/docker.sock -v "$repo:$repo" "$image" >/dev/null

  echo "identity-on-mac: installing the pinned identity service"
  inside scripts/install-identity.sh --no-browser "$out/identity" "$out/download"
  echo "identity-on-mac: building the sign-in theme, the UI export, the api and the test"
  inside node ui/identity-theme/build.mjs "$out/identity-theme"
  inside rsync -a --delete --exclude node_modules --exclude .next --exclude out --exclude .test-out ui/ "$out/ui/"
  inside sh -c "cd '$out/ui' && npm ci --no-audit --no-fund && npm run build"
  inside go build -o "$out/bin/rasputin-api" ./api/cmd/rasputin-api
  inside go test -c -o "$out/bin/identitytest.test" ./api/internal/identitytest

  echo "identity-on-mac: starting the console stack"
  docker exec -d -w "$repo/api/internal/identitytest" \
    -e RASPUTIN_IDENTITY_HOME="$out/identity" \
    -e RASPUTIN_IDENTITY_SYSTEMD_FUNCTIONAL=required \
    -e RASPUTIN_IDENTITY_THEME="$out/identity-theme" \
    -e RASPUTIN_UI_DIR="$out/ui/out" \
    -e RASPUTIN_API_BIN="$out/bin/rasputin-api" \
    -e RASPUTIN_CONSOLE_RIG=hold \
    -e RASPUTIN_CONSOLE_OUT="$out" \
    -e RASPUTIN_CONSOLE_PORT="$port" \
    -e RASPUTIN_CONSOLE_KC_PLATFORM="$kc_platform" \
    -e RASPUTIN_CONSOLE_API_ENV="$api_env" \
    "$name" sh -c "'$out/bin/identitytest.test' -test.v -test.count=1 -test.timeout=24h -test.run '^TestIdentitySystemd_ConsoleSignIn\$' > '$out/test.log' 2>&1; echo \$? > '$out/exit'"

  local start=$SECONDS
  until [ -f "$out/ready" ]; do
    running || die "the container stopped before the stack was ready; see $out/test.log"
    if [ -f "$out/exit" ]; then
      tail -n 40 "$out/test.log" >&2 || true
      die "the console stack test ended (exit $(cat "$out/exit")) before it was ready; see $out/test.log"
    fi
    [ $((SECONDS - start)) -lt "$up_deadline" ] || die "the stack was not ready within ${up_deadline}s; see $out/test.log"
    sleep 5
  done
  echo "identity-on-mac: signed in as the synthetic fixture. /api/auth/me:"
  cat "$out/me.json"; echo
  echo "identity-on-mac: the session cookie is in $out/session.cookie (send it as __Host-rasputin-session to https://ci.local, mapped to 127.0.0.1:$port)"
}

shots() {
  [ "$#" -ge 1 ] || die "name at least one console path, such as /"
  [ -f "$out/ready" ] || die "the stack is not up; run: scripts/identity-on-mac.sh up"
  command -v go >/dev/null || die "go is not installed on this Mac (https://go.dev/dl/)"
  (cd "$repo" && go run ./api/internal/identitytest/cmd/consoleshots -out "$out" "$@")
  echo "identity-on-mac: screenshots are in $out/shots"
}

down() {
  if ! docker inspect "$name" >/dev/null 2>&1; then
    echo "identity-on-mac: no stack is up"
    return 0
  fi
  if running && [ ! -f "$out/exit" ]; then
    touch "$out/stop"
    local start=$SECONDS
    until [ -f "$out/exit" ]; do
      running || break
      [ $((SECONDS - start)) -lt "$down_deadline" ] || { echo "identity-on-mac: the test did not finish its teardown within ${down_deadline}s" >&2; break; }
      sleep 2
    done
  fi
  if [ -f "$out/exit" ]; then
    echo "identity-on-mac: the console stack test exited $(cat "$out/exit")"
    tail -n 5 "$out/test.log" || true
  fi
  docker rm -f "$name" >/dev/null
  rm -rf "${out:?}/stop" "${out:?}/ready" "${out:?}/session.cookie" "${out:?}/ui" "${out:?}/bin" "${out:?}/work"
  echo "identity-on-mac: removed the container; the image $image and the downloads in $out stay for the next run"
}

case "${1:-}" in
  up) shift; up "$@" ;;
  shots) shift; shots "$@" ;;
  down) shift; down ;;
  *) echo "usage: $0 up [--api-env K=V]... | shots PATH... | down" >&2; exit 2 ;;
esac
