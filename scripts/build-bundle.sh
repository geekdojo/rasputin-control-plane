#!/usr/bin/env bash
# build-bundle.sh — produce a mock Rasputin update artifact and its DETACHED
# CMS signature, for dev, CI and air-gapped upload rehearsals.
#
# It emits the same two files a real release publishes:
#
#   <out>       the artifact bytes
#   <out>.sig   a detached CMS SignedData over them, DER
#
# and the signing command below is a copy of the one the release pipelines run
# (rasputin-openwrt-firewall .github/workflows/release.yml, "CMS-sign images"),
# so an artifact from here is verified by exactly the code path that verifies a
# published one — in the api at upload and on the node at install.
#
# THIS REPLACED THE `.raspbundle` JSON ENVELOPE, which wrapped the payload,
# a manifest, a raw signature and a cert chain into one file. That format was
# dev-only, so the thing operators hand-carried into an air-gapped cluster was
# the one thing nothing else in the system spoke — and it had a verifier of its
# own, which signed only sha256(payload) and left the manifest unauthenticated.
#
# The leaf must be a RELEASE leaf: scripts/pki-init.sh mints one carrying
# 1.3.6.1.4.1.66587.1.1.1, and a leaf without that purpose is refused. That is
# the same rule the fleet enforces, so a bundle that verifies here verifies
# there.

set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 --version V --out FILE \\
          --leaf-cert PEM --leaf-key KEY \\
          [--compatible STR] [--architecture STR] \\
          [--description STR] [--payload FILE]

Options:
  --version V         Bundle version, e.g. 0.1.0
  --out FILE          Output artifact (overwritten; FILE.sig is written too)
  --leaf-cert PEM     Path to a RELEASE leaf signing cert (from pki-init.sh)
  --leaf-key KEY      Path to its private key
  --compatible STR    Compatible string (default: rasputin-pi5-cm5)
  --architecture STR  arm64 | amd64 (default: arm64)
  --description STR   Free-text description
  --payload FILE      Bytes to use as the "OS image" (default: a 256KB
                      pseudo-random blob, sufficient for end-to-end tests)

Output: the artifact plus its detached .sig, ready to upload to /api/bundles.
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

if [[ -n $PAYLOAD ]]; then
    cp "$PAYLOAD" "$OUT"
else
    # 256 KB pseudo-random "rootfs" placeholder.
    dd if=/dev/urandom of="$OUT" bs=1024 count=256 status=none
fi

# The pipeline's sign_file(), modulo paths: detached (no -nodetach), DER, with
# the intermediate travelling in the CMS object so a verifier holding only the
# root can complete the chain.
SIGN_ARGS=(-sign -binary -in "$OUT" -signer "$LEAF_CERT" -inkey "$LEAF_KEY" -outform DER -out "$OUT.sig")
INT_PEM_PATH="$(dirname "$LEAF_CERT")/intermediate-ca.pem"
if [[ -f "$INT_PEM_PATH" ]]; then
    SIGN_ARGS+=(-certfile "$INT_PEM_PATH")
fi
openssl cms "${SIGN_ARGS[@]}"

# Prove the pair is what we think it is before handing it to anyone. If
# openssl will not verify what it just signed, the upload was never going to.
ROOT_CA_PATH="$(dirname "$LEAF_CERT")/root-ca.pem"
if [[ -f "$ROOT_CA_PATH" ]]; then
    openssl cms -verify -binary -inform DER -in "$OUT.sig" -content "$OUT" \
        -CAfile "$ROOT_CA_PATH" -purpose any -out /dev/null 2>/dev/null \
        || { echo "error: the signature this script just produced does not verify against $ROOT_CA_PATH" >&2; exit 1; }
    echo "self-check: $OUT.sig verifies against $ROOT_CA_PATH"
fi

SHA=$(shasum -a 256 "$OUT" | awk '{print $1}')
SIZE=$(wc -c < "$OUT" | tr -d ' ')
echo "wrote $OUT and $OUT.sig"
echo "  version:    $VERSION"
echo "  compatible: $COMPATIBLE"
echo "  arch:       $ARCH"
[[ -n $DESCRIPTION ]] && echo "  description: $DESCRIPTION"
echo "  sha256:     $SHA"
echo "  size:       $SIZE bytes"
echo "  upload:"
echo "    curl -b cookies.txt -X POST http://localhost:8080/api/bundles \\"
echo "      -F signature=@$OUT.sig \\"
echo "      -F version=$VERSION -F architecture=$ARCH -F compatible=$COMPATIBLE \\"
echo "      -F artifact=@$OUT"
