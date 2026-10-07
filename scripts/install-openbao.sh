#!/usr/bin/env bash
#
# install-openbao.sh — install the pinned secret store binary for the
# functional tests (docs/testing-secret-store.md).
#
# Usage: scripts/install-openbao.sh <dest-dir>
#
# Downloads the OpenBao linux_amd64 release tarball that
# api/internal/secretstoretest/pin.go pins, checks it against the pinned
# sha256, and extracts only the `bao` binary into <dest-dir>. The version and
# the hash are READ from pin.go, never repeated here, so CI downloads exactly
# what the Go const names and gatereg checks the capability rows against.
#
# Linux x86_64 only: the pin is the linux_amd64 tarball's hash. Anything else
# is refused before any download.
#
# The hash in pin.go comes only from a signature-verified checksums.txt (see
# the comment there). This script checks the tarball against that hash; it
# does not verify signatures itself.
set -euo pipefail

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  echo "usage: $0 <dest-dir>" >&2
  exit 2
fi
dest="$1"

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
pin="$repo_root/api/internal/secretstoretest/pin.go"

# read_const NAME prints the string value of `NAME = "value"` in pin.go,
# anchored to a line of its own.
read_const() {
  sed -n -E 's/^[[:space:]]*'"$1"'[[:space:]]*=[[:space:]]*"([^"]+)"[[:space:]]*$/\1/p' "$pin"
}

release="$(read_const OpenBaoRelease)"
sha256="$(read_const OpenBaoLinuxAMD64SHA256)"
if [ -z "$release" ]; then
  echo "install-openbao: cannot read OpenBaoRelease from $pin" >&2
  exit 1
fi
if [ -z "$sha256" ]; then
  echo "install-openbao: cannot read OpenBaoLinuxAMD64SHA256 from $pin" >&2
  exit 1
fi

os="$(uname -s)"
arch="$(uname -m)"
if [ "$os" != "Linux" ] || [ "$arch" != "x86_64" ]; then
  echo "install-openbao: this is $os $arch; only Linux x86_64 is accepted (the pin is the linux_amd64 tarball)" >&2
  exit 1
fi

owner_repo="${release%:*}"   # openbao/openbao
tag="${release##*:}"         # v2.7.0
version="${tag#v}"           # 2.7.0
tarball="openbao_${version}_linux_amd64.tar.gz"
url="https://github.com/${owner_repo}/releases/download/${tag}/${tarball}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "install-openbao: downloading $url"
curl -fsSL -o "$work/$tarball" "$url"
(cd "$work" && echo "${sha256}  ${tarball}" | sha256sum -c -)

mkdir -p "$dest"
tar -xzf "$work/$tarball" -C "$dest" bao
"$dest/bao" version
