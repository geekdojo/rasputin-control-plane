#!/usr/bin/env bash
#
# pack-store-policy.sh — copy the node secrets store's fixed policy text into
# the api release tarball's staging tree (geekdojo/geekdojo-brain#804;
# ADR-0010 S9).
#
# Usage: scripts/pack-store-policy.sh SRC DEST
#
#   SRC   the policy source, api/internal/secretstore/storepolicy
#   DEST  the directory to create, <dist>/openbao-policy
#
# Every SRC/*.hcl is copied, byte for byte, into DEST at mode 0644. rasputin-os
# installs DEST's files to /usr/share/rasputin/openbao-policy/, where the
# store's self-init reads them, and its drift check compares them with SRC at
# the release tag. So this repository, which owns the text, publishes the file
# that ships, as it does mesh-images.json.
#
# Exit status: 0 copied; 1 SRC holds no .hcl, or a copy failed; 2 bad usage.
# Each failure prints one sentence on stderr.
set -euo pipefail

if [ "$#" -ne 2 ] || [ -z "$1" ] || [ -z "$2" ]; then
	echo "Usage: $0 SRC DEST, where SRC holds the store's policy files and DEST is the directory to create." >&2
	exit 2
fi
src=$1 dest=$2

shopt -s nullglob
files=("$src"/*.hcl)
shopt -u nullglob
if [ "${#files[@]}" -eq 0 ]; then
	echo "The policy source $src holds no .hcl file, so the api tarball would ship without the store's policy text." >&2
	exit 1
fi

mkdir -p "$dest"
for f in "${files[@]}"; do
	if ! install -m 0644 "$f" "$dest/$(basename "$f")"; then
		echo "The policy file $f could not be copied into $dest." >&2
		exit 1
	fi
done
echo "   openbao-policy: ${#files[@]} policy file(s) from $src"
