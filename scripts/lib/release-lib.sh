# shellcheck shell=bash
#
# release-lib.sh — the pin reader and the hash helper the release and install
# scripts share (geekdojo/geekdojo-brain#980). Source it; it defines functions
# and runs nothing.
#
# Sourced by scripts/pack-identity.sh, scripts/build-release.sh,
# scripts/install-identity.sh, scripts/install-openbao.sh and release.yml's
# "api tarballs carry the identity release" step. Its tests are TC-980-18 in
# scripts/test-pack-identity.sh.

# pin_const FILE NAME prints the string value of `NAME = "value"` in the Go
# file FILE, anchored to a line of its own, so `NAMEX = ...` and a commented
# `// NAME = ...` never match. It prints nothing when no line matches.
pin_const() {
	sed -n -E 's/^[[:space:]]*'"$2"'[[:space:]]*=[[:space:]]*"([^"]+)"[[:space:]]*$/\1/p' "$1"
}

# sha256_of FILE prints FILE's sha256 as lowercase hex.
sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
	else shasum -a 256 "$1" | awk '{print $1}'; fi
}
