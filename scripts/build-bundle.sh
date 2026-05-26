#!/usr/bin/env bash
# build-bundle.sh — produce a signed mock Rasputin update bundle.
#
# In v0 this builds the *mock* bundle format only — a JSON envelope:
#   { manifest, payload (hex), signature (hex), certPem }
# that the api's verifier understands. When we have hardware images
# we'll add a --rauc mode that runs `rauc bundle` instead.
#
# The mock format is dev-only; real production updates require RAUC.

set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 --version V --out FILE \\
          --leaf-cert PEM --leaf-key KEY \\
          [--compatible STR] [--architecture STR] \\
          [--description STR] [--payload FILE]

Options:
  --version V         Bundle version, e.g. 0.1.0
  --out FILE          Output bundle file (will be overwritten)
  --leaf-cert PEM     Path to leaf signing cert (from pki-init.sh)
  --leaf-key KEY      Path to leaf signing key (from pki-init.sh)
  --compatible STR    Compatible string (default: rasputin-pi5-cm5)
  --architecture STR  arm64 | amd64 (default: arm64)
  --description STR   Free-text description
  --payload FILE      Bytes to wrap as the "OS image" (default: a 256KB
                      pseudo-random blob, sufficient for end-to-end tests)

Output: a single .raspbundle JSON file ready to upload to /api/bundles.
EOF
    exit 1
}

VERSION=""
OUT=""
LEAF_CERT=""
LEAF_KEY=""
COMPATIBLE="rasputin-pi5-cm5"
ARCH="arm64"
DESCRIPTION=""
PAYLOAD=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --version) VERSION=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        --leaf-cert) LEAF_CERT=$2; shift 2 ;;
        --leaf-key) LEAF_KEY=$2; shift 2 ;;
        --compatible) COMPATIBLE=$2; shift 2 ;;
        --architecture) ARCH=$2; shift 2 ;;
        --description) DESCRIPTION=$2; shift 2 ;;
        --payload) PAYLOAD=$2; shift 2 ;;
        -h|--help) usage ;;
        *) echo "unknown arg: $1" >&2; usage ;;
    esac
done

[[ -z $VERSION || -z $OUT || -z $LEAF_CERT || -z $LEAF_KEY ]] && usage

# Stage in tmpdir.
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if [[ -n $PAYLOAD ]]; then
    cp "$PAYLOAD" "$TMP/payload.bin"
else
    # 256 KB pseudo-random "rootfs" placeholder.
    dd if=/dev/urandom of="$TMP/payload.bin" bs=1024 count=256 status=none
fi

# Hex-encode payload (avoids JSON escaping pain).
if command -v xxd >/dev/null; then
    xxd -p -c0 "$TMP/payload.bin" > "$TMP/payload.hex"
else
    # macOS without xxd — fall back to od.
    od -An -v -tx1 "$TMP/payload.bin" | tr -d ' \n' > "$TMP/payload.hex"
fi
PAYLOAD_HEX=$(cat "$TMP/payload.hex")

# Sign sha256(payload) with leaf key (PKCS#1v15 + SHA-256).
openssl dgst -sha256 -sign "$LEAF_KEY" -out "$TMP/sig.bin" "$TMP/payload.bin"
if command -v xxd >/dev/null; then
    SIG_HEX=$(xxd -p -c0 "$TMP/sig.bin")
else
    SIG_HEX=$(od -An -v -tx1 "$TMP/sig.bin" | tr -d ' \n')
fi

# Read leaf cert as a single-line PEM (escape newlines for JSON). If an
# intermediate-ca.pem sits next to the leaf cert, append it so the api
# verifier can complete the chain to the root.
LEAF_PEM=$(awk '{printf "%s\\n", $0}' "$LEAF_CERT")
INT_PEM_PATH="$(dirname "$LEAF_CERT")/intermediate-ca.pem"
if [[ -f "$INT_PEM_PATH" ]]; then
    INT_PEM=$(awk '{printf "%s\\n", $0}' "$INT_PEM_PATH")
    LEAF_PEM="${LEAF_PEM}${INT_PEM}"
fi

BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

cat > "$OUT" <<EOF
{
  "manifest": {
    "version": "$VERSION",
    "compatible": "$COMPATIBLE",
    "architecture": "$ARCH",
    "description": "$DESCRIPTION",
    "buildDate": "$BUILD_DATE",
    "sha256": "",
    "sizeBytes": 0,
    "signedBy": ""
  },
  "payload": "$PAYLOAD_HEX",
  "signature": "$SIG_HEX",
  "certPem": "$LEAF_PEM"
}
EOF

# Print the resulting file size + sha256 for the operator.
SHA=$(shasum -a 256 "$OUT" | awk '{print $1}')
SIZE=$(wc -c < "$OUT" | tr -d ' ')
echo "wrote $OUT"
echo "  sha256: $SHA"
echo "  size:   $SIZE bytes"
echo "  upload: curl --data-binary @$OUT -H 'Content-Type: application/octet-stream' \\"
echo "            -b cookies.txt http://localhost:8080/api/bundles"
