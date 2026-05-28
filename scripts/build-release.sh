#!/usr/bin/env bash
#
# build-release.sh — cross-build the Rasputin control-plane binaries for the
# OS-image pipeline and package them as the tarballs rasputin-os vendors.
#
# These are pure-Go binaries (modernc.org/sqlite, embedded NATS — no cgo), so
# CGO_ENABLED=0 produces fully static, libc-independent ELF binaries. The
# same linux-amd64 agent therefore runs on both the Buildroot OS and the
# OpenWrt firewall (no separate musl build needed).
#
# Output layout (matches rasputin-os package/*/*.mk):
#   dist/rasputin-agent-<version>-linux-<arch>.tar.gz   (+ .sha256, + .hash)
#   dist/rasputin-api-<version>-linux-<arch>.tar.gz     (+ .sha256, + .hash)
#
# The .hash files are in Buildroot's format (`sha256  <hex>  <file>`) so the
# OS repo can drop them next to the package .mk for download verification.
#
# Usage:
#   scripts/build-release.sh <version>
#   VERSION env also accepted. Version is WITHOUT a leading 'v'
#   (e.g. 0.1.0); the git tag carries the 'v' (v0.1.0).
#
set -euo pipefail

VERSION="${1:-${VERSION:-}}"
if [ -z "$VERSION" ]; then
	echo "usage: $0 <version>   (e.g. 0.1.0)" >&2
	exit 1
fi
VERSION="${VERSION#v}"   # tolerate a leading v

cd "$(dirname "$0")/.."
ROOT="$PWD"
DIST="$ROOT/dist"
rm -rf "$DIST"
mkdir -p "$DIST"

# (component, module-relative main package)
COMPONENTS="agent:./cmd/rasputin-agent api:./cmd/rasputin-api"
ARCHES="amd64 arm64"

# -trimpath for reproducibility; -s -w to strip debug info (smaller image).
# -X stamps the version into the binary (the agent/api expose it as AgentVersion).
LDFLAGS="-s -w"

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
	else shasum -a 256 "$1" | awk '{print $1}'; fi
}

for comp in $COMPONENTS; do
	name="${comp%%:*}"          # agent | api
	pkg="${comp##*:}"           # ./cmd/rasputin-agent
	moddir="$ROOT/$name"        # ./agent | ./api
	bin="rasputin-$name"
	for arch in $ARCHES; do
		echo ">> building $bin linux/$arch"
		out="$DIST/$bin"
		( cd "$moddir" && \
		  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
		  go build -trimpath -ldflags "$LDFLAGS" -o "$out" "$pkg" )

		# TODO(ui): the api needs its built web UI bundled here once the api
		# learns to serve static assets in production. For now we ship the
		# binary alone; rasputin-os's rasputin-api.mk tolerates a missing ui/.

		tarball="$DIST/$bin-$VERSION-linux-$arch.tar.gz"
		tar -C "$DIST" -czf "$tarball" "$bin"
		rm -f "$out"

		sum=$(sha256_of "$tarball")
		echo "$sum" > "$tarball.sha256"
		# Buildroot .hash format
		echo "sha256  $sum  $(basename "$tarball")" > "$tarball.hash"
		echo "   $(basename "$tarball")  sha256=$sum"
	done
done

echo
echo "release artifacts in $DIST:"
ls -1 "$DIST"
