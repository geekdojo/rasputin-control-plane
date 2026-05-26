#!/usr/bin/env bash
# pki-init.sh — one-shot bootstrap of the Rasputin update-signing PKI.
#
# Produces, in --out-dir:
#   root-ca.key        — Rasputin Root CA private key (KEEP OFFLINE)
#   root-ca.pem        — Rasputin Root CA certificate (ship to every node + api)
#   intermediate-ca.key
#   intermediate-ca.pem
#   leaf-001.key       — first release leaf signing key (used by build-bundle.sh)
#   leaf-001.pem
#
# After this script completes:
#   1. Copy root-ca.pem to the api: <data-dir>/trust/root-ca.pem
#   2. Copy root-ca.pem into your OS image build so every node's rootfs
#      ships with it under /etc/rasputin/trust/root-ca.pem
#   3. MOVE root-ca.key OFFLINE — a YubiKey, a 1Password vault entry, or
#      an air-gapped encrypted USB. The api never needs the root key.
#   4. The intermediate-ca.key can live on the release machine (or a
#      sealed CI secret), used quarterly to issue new leaf certs.
#   5. leaf-001.key + leaf-001.pem are what build-bundle.sh consumes.
#
# Re-running this script with --rotate-leaf will issue a new leaf-NNN pair
# under the existing intermediate without touching the root.

set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 [--out-dir DIR] [--cn-prefix STR] [--rotate-leaf]

Options:
  --out-dir DIR      Output directory (default: ./pki-out)
  --cn-prefix STR    CN prefix for issued certs (default: "Rasputin")
  --rotate-leaf      Issue a new leaf under the existing intermediate
                     (requires intermediate-ca.{key,pem} already in --out-dir)
EOF
    exit 1
}

OUT_DIR="./pki-out"
CN_PREFIX="Rasputin"
ROTATE_LEAF=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --out-dir) OUT_DIR=$2; shift 2 ;;
        --cn-prefix) CN_PREFIX=$2; shift 2 ;;
        --rotate-leaf) ROTATE_LEAF=1; shift ;;
        -h|--help) usage ;;
        *) echo "unknown arg: $1" >&2; usage ;;
    esac
done

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

if [[ $ROTATE_LEAF -eq 1 ]]; then
    if [[ ! -f intermediate-ca.key || ! -f intermediate-ca.pem ]]; then
        echo "error: intermediate-ca.{key,pem} not found in $OUT_DIR; cannot rotate" >&2
        exit 2
    fi
    # Find next leaf number.
    last=$(ls -1 leaf-*.pem 2>/dev/null | sed 's/leaf-\([0-9]*\)\.pem/\1/' | sort -n | tail -1 || true)
    if [[ -z "$last" ]]; then
        next="001"
    else
        next=$(printf "%03d" $((10#$last + 1)))
    fi
    echo "==> Issuing leaf-${next} under existing intermediate"
    openssl genrsa -out "leaf-${next}.key" 4096
    openssl req -new -key "leaf-${next}.key" -out "leaf-${next}.csr" \
        -subj "/CN=${CN_PREFIX} Bundle Signing leaf-${next}"
    openssl x509 -req -in "leaf-${next}.csr" \
        -CA intermediate-ca.pem -CAkey intermediate-ca.key -CAcreateserial \
        -out "leaf-${next}.pem" -days 90 -sha256 \
        -extfile <(printf "keyUsage=digitalSignature\nextendedKeyUsage=codeSigning")
    rm -f "leaf-${next}.csr"
    echo "done: leaf-${next}.{key,pem}"
    exit 0
fi

if [[ -f root-ca.key ]]; then
    echo "error: root-ca.key already exists in $OUT_DIR" >&2
    echo "       refusing to overwrite. delete it or pick a different --out-dir." >&2
    exit 2
fi

echo "==> Generating Rasputin Root CA"
openssl genrsa -out root-ca.key 4096
openssl req -x509 -new -key root-ca.key -out root-ca.pem -days 7300 -sha256 \
    -subj "/CN=${CN_PREFIX} Root CA" \
    -extensions v3_ca -config <(cat <<EOF
[req]
distinguished_name = dn
[dn]
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF
)

echo "==> Generating Rasputin Update Signing CA (intermediate)"
openssl genrsa -out intermediate-ca.key 4096
openssl req -new -key intermediate-ca.key -out intermediate-ca.csr \
    -subj "/CN=${CN_PREFIX} Update Signing CA"
openssl x509 -req -in intermediate-ca.csr \
    -CA root-ca.pem -CAkey root-ca.key -CAcreateserial \
    -out intermediate-ca.pem -days 3650 -sha256 \
    -extfile <(cat <<EOF
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
EOF
)
rm -f intermediate-ca.csr

echo "==> Generating first release leaf cert (leaf-001)"
openssl genrsa -out leaf-001.key 4096
openssl req -new -key leaf-001.key -out leaf-001.csr \
    -subj "/CN=${CN_PREFIX} Bundle Signing leaf-001"
openssl x509 -req -in leaf-001.csr \
    -CA intermediate-ca.pem -CAkey intermediate-ca.key -CAcreateserial \
    -out leaf-001.pem -days 90 -sha256 \
    -extfile <(printf "keyUsage=digitalSignature\nextendedKeyUsage=codeSigning")
rm -f leaf-001.csr

chmod 600 *.key

cat <<EOF

==> Done. PKI material in $OUT_DIR:
    root-ca.key         — OFFLINE THIS. Air-gapped USB, YubiKey, vault.
    root-ca.pem         — Public root cert. Ship to every node + api.
    intermediate-ca.key — Release machine. Sealed CI secret.
    intermediate-ca.pem — Public intermediate cert.
    leaf-001.{key,pem}  — Used by build-bundle.sh.

Next steps:
    cp $OUT_DIR/root-ca.pem ../data/trust/root-ca.pem
    # ... and bake the same file into the OS image build (/etc/rasputin/trust/)

For rotation:
    $0 --out-dir $OUT_DIR --rotate-leaf
EOF
