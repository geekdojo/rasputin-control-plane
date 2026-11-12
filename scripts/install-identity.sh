#!/usr/bin/env bash
#
# install-identity.sh — install the pinned identity service, its runtime, its
# database image, the mesh coordinator image and the browser for the identity
# functional tests (docs/testing-identity.md).
#
# Usage: scripts/install-identity.sh <dest-dir> [<download-dir>]
#
# Downloads the Keycloak distribution (Maven Central), the Temurin JRE
# (Adoptium) and Chrome for Testing that api/internal/identitytest/pin.go pins,
# checks each against its pinned sha256, and extracts them to
# <dest-dir>/keycloak, <dest-dir>/jre and <dest-dir>/chrome-linux64. It then
# builds Keycloak with the production build options
# (identity/keycloak-build.conf), pulls the pinned PostgreSQL image and the
# Headscale image api/internal/mesh/mesh-images.json pins (both by digest, so
# docker verifies their content), and prints kc.sh --version. The versions and
# hashes are READ from pin.go, never repeated here.
#
# Linux x86_64 only: the pins are the x64 tarballs' and the linux64 zip's
# hashes. Anything else is refused before any download.
#
# The Keycloak and JRE hashes in pin.go come only from signature-verified
# downloads, and Chrome for Testing's from the first download (it publishes no
# checksum); see the comment there. This script checks bytes against those
# hashes; it does not verify signatures itself.
#
# With <download-dir>, the downloads are kept there, and one already there is
# used instead of downloading it again. CI restores that directory from the
# Actions cache. A kept file gets the same sha256 check as a fresh download,
# and one that fails it is refused, never replaced.
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ] || [ -z "$1" ]; then
  echo "usage: $0 <dest-dir> [<download-dir>]" >&2
  exit 2
fi
dest="$1"
keep="${2:-}"

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
pin="$repo_root/api/internal/identitytest/pin.go"
mesh_images="$repo_root/api/internal/mesh/mesh-images.json"
build_conf="$repo_root/identity/keycloak-build.conf"

# read_const NAME prints the string value of `NAME = "value"` in pin.go,
# anchored to a line of its own.
read_const() {
  sed -n -E 's/^[[:space:]]*'"$1"'[[:space:]]*=[[:space:]]*"([^"]+)"[[:space:]]*$/\1/p' "$pin"
}

need() {
  local v
  v="$(read_const "$1")"
  if [ -z "$v" ]; then
    echo "install-identity: cannot read $1 from $pin" >&2
    exit 1
  fi
  printf '%s' "$v"
}

kc_release="$(need KeycloakRelease)"
kc_sha256="$(need KCDistSHA256)"
jre_release="$(need JRERelease)"
jre_sha256="$(need JRELinuxX64SHA256)"
pg_image="$(need PostgresImage)"
cft_release="$(need ChromeForTestingRelease)"
cft_sha256="$(need ChromeLinux64SHA256)"

os="$(uname -s)"
arch="$(uname -m)"
if [ "$os" != "Linux" ] || [ "$arch" != "x86_64" ]; then
  echo "install-identity: this is $os $arch; only Linux x86_64 is accepted (the pins are the x64 and linux64 downloads)" >&2
  exit 1
fi

hs_image="$(jq -r '.images.headscale.ref // empty' "$mesh_images")"
if [ -z "$hs_image" ]; then
  echo "install-identity: cannot read the headscale ref from $mesh_images" >&2
  exit 1
fi

kc_version="${kc_release##*:}"                # 26.8.2
jre_version="${jre_release##*:}"              # 25.0.5+8
jre_repo="${jre_release%:*}"                  # adoptium/temurin25-binaries
cft_version="${cft_release##*:}"              # 157.0.8103.78

kc_file="keycloak-quarkus-dist-${kc_version}.tar.gz"
kc_url="https://repo1.maven.org/maven2/org/keycloak/keycloak-quarkus-dist/${kc_version}/${kc_file}"
jre_file="OpenJDK${jre_version%%.*}U-jre_x64_linux_hotspot_${jre_version/+/_}.tar.gz"
jre_url="https://github.com/${jre_repo}/releases/download/jdk-${jre_version/+/%2B}/${jre_file}"
cft_file="chrome-linux64.zip"
cft_url="https://storage.googleapis.com/chrome-for-testing-public/${cft_version}/linux64/${cft_file}"

if [ -n "$keep" ]; then
  mkdir -p "$keep"
  work="$keep"
else
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
fi

# fetch FILE URL SHA256: use the kept FILE or download it, then check it
# against the pin. A file that fails is left where it is and refused.
fetch() {
  local file="$1" url="$2" sum="$3"
  if [ -f "$work/$file" ]; then
    echo "install-identity: using the kept $work/$file"
  else
    echo "install-identity: downloading $url"
    curl -fsSL --retry 2 -o "$work/$file.part" "$url"
    mv "$work/$file.part" "$work/$file"
  fi
  if ! (cd "$work" && echo "${sum}  ${file}" | sha256sum -c -); then
    echo "install-identity: $work/$file does not match the pinned sha256 $sum; refusing it (it is left in place, not replaced)" >&2
    exit 1
  fi
}

fetch "$kc_file" "$kc_url" "$kc_sha256"
fetch "$jre_file" "$jre_url" "$jre_sha256"
fetch "$cft_file" "$cft_url" "$cft_sha256"

mkdir -p "$dest"
rm -rf "$dest/keycloak" "$dest/jre" "$dest/chrome-linux64"
mkdir -p "$dest/keycloak" "$dest/jre"
tar -xzf "$work/$kc_file" -C "$dest/keycloak" --strip-components=1
tar -xzf "$work/$jre_file" -C "$dest/jre" --strip-components=1
unzip -q "$work/$cft_file" -d "$dest"

echo "install-identity: kc.sh --config-file=$build_conf build"
JAVA_HOME="$dest/jre" "$dest/keycloak/bin/kc.sh" --config-file="$build_conf" build

docker pull "$pg_image"
docker pull "$hs_image"

JAVA_HOME="$dest/jre" "$dest/keycloak/bin/kc.sh" --version
"$dest/chrome-linux64/chrome" --version
