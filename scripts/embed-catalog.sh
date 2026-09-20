#!/usr/bin/env bash
# embed-catalog.sh — refresh the embedded offline catalog floor.
#
# Fetches the app-catalog release named by catalog-version.txt, VERIFIES its
# detached signature against the Rasputin root CA, and writes the verified pair
# into api/internal/catalog/floor/ where go:embed picks it up.
#
# USAGE
#   ./scripts/embed-catalog.sh              # use the version in catalog-version.txt
#   ./scripts/embed-catalog.sh --version 7  # pin to 7, updating the file too
#   ./scripts/embed-catalog.sh --verify     # CI: re-check the COMMITTED floor,
#                                           # download nothing, change nothing
#
# The root CA is needed to verify what we are about to embed. It is public.
# Supplied, in order of preference:
#   RASPUTIN_ROOT_CA_PEM   the PEM itself, in the environment (how CI does it)
#   --root-ca <path>       a file
#   otherwise              read from the geekdojo org variable via `gh`
#
# PREREQUISITES
#   gh   GitHub CLI, authenticated.  brew install gh   then: gh auth login
#   go   for the signature check — it runs api/cmd/rasputin-catalog-verify,
#        the SAME verifier the api applies to a catalog it fetches at runtime.
#        This used to be `openssl cms -verify -purpose any`, which could not ask
#        about the catalog's private purpose OID and so checked only that the
#        signer chained to the root: a catalog signed with the RELEASE leaf
#        verified and got embedded. See that command's package doc.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PIN_FILE="$REPO_ROOT/catalog-version.txt"
OUT_DIR="$REPO_ROOT/api/internal/catalog/floor"
CATALOG_REPO="${CATALOG_REPO:-geekdojo/rasputin-app-catalog}"

VERSION=""
ROOT_CA_PATH=""
VERIFY_ONLY=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --version)  VERSION=$2; shift 2 ;;
        --root-ca)  ROOT_CA_PATH=$2; shift 2 ;;
        --verify)   VERIFY_ONLY=1; shift ;;
        -h|--help)  sed -n '2,25p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

# The pin is the bare integer on the last non-comment, non-blank line.
if [[ -z "$VERSION" ]]; then
    VERSION="$(grep -vE '^\s*#|^\s*$' "$PIN_FILE" | tail -1 | tr -d '[:space:]')"
fi
case "$VERSION" in
    ''|*[!0-9]*) echo "error: catalog version must be a positive integer, got '$VERSION'" >&2; exit 2 ;;
esac

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# verify_catalog <bundle> <sig> — the ONE signature check in this script, so
# the --verify path and the embed path cannot drift apart in what they accept.
# It refuses a bundle whose signer is not authorized for the app-catalog
# purpose, which is the check `openssl -purpose any` could not express.
verify_catalog() {
    command -v go >/dev/null \
        || { echo "error: go is required to verify a catalog signature (see the PREREQUISITES note above)" >&2; return 2; }
    ( cd "$REPO_ROOT/api" && go run ./cmd/rasputin-catalog-verify \
        -catalog "$1" -sig "$2" -root-ca "$TMP/root-ca.pem" )
}

# Resolve the trust anchor before downloading anything, so a missing root CA
# fails before we have an unverified bundle sitting on disk.
if [[ -n "${RASPUTIN_ROOT_CA_PEM:-}" ]]; then
    printf '%s' "$RASPUTIN_ROOT_CA_PEM" > "$TMP/root-ca.pem"
elif [[ -n "$ROOT_CA_PATH" ]]; then
    cp "$ROOT_CA_PATH" "$TMP/root-ca.pem"
else
    gh api orgs/geekdojo/actions/variables/RASPUTIN_ROOT_CA_PEM --jq '.value' > "$TMP/root-ca.pem" 2>/dev/null \
        || { echo "error: no root CA. Set RASPUTIN_ROOT_CA_PEM, pass --root-ca <path>, or authenticate gh." >&2; exit 2; }
fi
[[ -s "$TMP/root-ca.pem" ]] || { echo "error: the root CA is empty" >&2; exit 2; }

if [[ $VERIFY_ONLY -eq 1 ]]; then
    # Re-verify what is COMMITTED, so a hand-edited floor fails CI. The Go test
    # checks the bundle parses and matches the pin; only this checks that the
    # bytes are still the ones the publisher signed.
    echo "==> Verifying the committed floor in ${OUT_DIR#"$REPO_ROOT"/}"
    verify_catalog "$OUT_DIR/catalog.json" "$OUT_DIR/catalog.json.sig" \
        || { echo "error: the embedded floor does not verify as an app-catalog bundle signed by the Rasputin root CA" >&2; exit 1; }
    echo "    floor signature OK"
    exit 0
fi

echo "==> Fetching catalog-v${VERSION} from ${CATALOG_REPO}"
gh release download "catalog-v${VERSION}" --repo "$CATALOG_REPO" \
    -p catalog.json -p catalog.json.sig -D "$TMP" \
    || { echo "error: no such catalog release: catalog-v${VERSION}" >&2; exit 1; }

echo "==> Verifying the signature before embedding anything"
verify_catalog "$TMP/catalog.json" "$TMP/catalog.json.sig" \
    || { echo "error: catalog-v${VERSION} does not verify as an app-catalog bundle signed by the Rasputin root CA — refusing to embed it" >&2; exit 1; }

# The release tag and the bundle's own version field are separate claims. If
# they disagree, something is wrong with the publish and embedding either one
# would bake in the disagreement.
claimed="$(grep -oE '"version"[[:space:]]*:[[:space:]]*[0-9]+' "$TMP/catalog.json" | head -1 | grep -oE '[0-9]+$')"
if [[ "$claimed" != "$VERSION" ]]; then
    echo "error: release catalog-v${VERSION} contains a bundle claiming version ${claimed}" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"
cp "$TMP/catalog.json" "$TMP/catalog.json.sig" "$OUT_DIR/"

# Rewrite the pin, preserving the comment block and appending to the history.
if ! grep -qE "^\s*#\s+${VERSION}\s" "$PIN_FILE"; then
    today="$(date -u +%Y-%m-%d)"
    tiles="$(grep -oE '"id"' "$TMP/catalog.json" | wc -l | tr -d ' ')"
    awk -v v="$VERSION" -v d="$today" -v n="$tiles" '
        /^# History:/ { print; inhist=1; next }
        inhist && /^#   [0-9]/ { hist[++h]=$0; next }
        inhist { printf "#   %-2s %s  %s tiles\n", v, d, n; for(i=1;i<=h;i++) print hist[i]; inhist=0 }
        /^[0-9]+$/ { next }
        { print }
    ' "$PIN_FILE" > "$PIN_FILE.tmp"
    printf '%s\n' "$VERSION" >> "$PIN_FILE.tmp"
    mv "$PIN_FILE.tmp" "$PIN_FILE"
fi

echo "==> Embedded catalog-v${VERSION} ($(wc -c < "$OUT_DIR/catalog.json" | tr -d ' ') bytes) into ${OUT_DIR#"$REPO_ROOT"/}"
