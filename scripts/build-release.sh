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
# Tarball contents:
#   agent: rasputin-agent                 (binary at root)
#   api:   rasputin-api + ui/             (binary + Next.js static export;
#          rasputin-os installs ui/ to /usr/share/rasputin/ui, which is the
#          api's RASPUTIN_UI_DIR default)
#
# Requires: go, node/npm (for the UI build).
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

# Web UI: one static export, shared by every api tarball (it's plain
# HTML/JS — nothing arch-specific). `npm ci` keeps the build reproducible
# from package-lock.json.
echo ">> building web UI (next static export)"
( cd "$ROOT/ui" && npm ci --no-audit --no-fund && npm run build )
[ -f "$ROOT/ui/out/index.html" ] || { echo "ui build produced no out/index.html" >&2; exit 1; }
cp -R "$ROOT/ui/out" "$DIST/ui"

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

		tarball="$DIST/$bin-$VERSION-linux-$arch.tar.gz"
		if [ "$name" = "api" ]; then
			tar -C "$DIST" -czf "$tarball" "$bin" ui
		else
			tar -C "$DIST" -czf "$tarball" "$bin"
		fi
		rm -f "$out"

		sum=$(sha256_of "$tarball")
		echo "$sum" > "$tarball.sha256"
		# Buildroot .hash format
		echo "sha256  $sum  $(basename "$tarball")" > "$tarball.hash"
		echo "   $(basename "$tarball")  sha256=$sum"
	done
done

rm -rf "$DIST/ui"   # packed into the api tarballs; not an artifact itself

echo
echo "release artifacts in $DIST:"
ls -1 "$DIST"
