#!/usr/bin/env bash
#
# assert-release-tag.sh — refuse a Go binary that was not built with
# `-tags release` (geekdojo/geekdojo-brain#529).
#
# A release build ignores the development overrides (RASPUTIN_TRUST_ROOT,
# RASPUTIN_CATALOG_REPO, RASPUTIN_CATALOG_API_BASE), so a shipped binary
# without the tag would let node.env re-point publisher trust and the app
# catalog. build-release.sh runs this on every binary before packing it.
#
# Reads the build settings Go records in the binary (`go version -m`). On a
# binary without the tag it prints which one, deletes it so nothing downstream
# can pack it, and exits 1. Exit 2 on bad usage or an unreadable binary.
#
# Usage:  scripts/assert-release-tag.sh <binary>
set -euo pipefail

if [ "$#" -ne 1 ]; then
	echo "usage: $0 <binary>" >&2
	exit 2
fi
bin="$1"

if ! info="$(go version -m "$bin" 2>&1)"; then
	echo "Cannot read the build settings of $bin: $info" >&2
	exit 2
fi

# The settings line is "<tab>build<tab>-tags=a,b,c".
tags="$(printf '%s\n' "$info" | awk -F'\t' '$2 == "build" && $3 ~ /^-tags=/ { sub(/^-tags=/, "", $3); print $3 }')"
case ",$tags," in
*,release,*)
	echo "   $(basename "$bin"): built with -tags=$tags"
	;;
*)
	rm -f -- "$bin"
	echo "$bin was built without -tags release, so it would honour development overrides; it has been deleted and will not be packaged." >&2
	exit 1
	;;
esac
