#!/usr/bin/env bash
# Regenerate the signed FIREWALL release manifest the firewall-image tests use
# (geekdojo/geekdojo-brain#527).
#
# The firewall-image endpoint has to forward a release's manifest.json and its
# detached manifest.json.sig to flash.sh, and flash.sh has to verify them. A test
# of that needs a manifest that really is signed, by a chain that really
# verifies, so this mints one. The chain shape and the signing command are the
# ones artifactsig/testdata/gen-fixtures.sh uses — which are themselves copies of
# the production PKI (root -> intermediate -> leaf carrying the release purpose
# OID) and of the firewall release pipeline's sign_file(). If either changes,
# change both scripts and regenerate.
#
# The manifest is shaped on the real firewall manifest: the image checksum is in
# `sha256` (on the OS that field covers the RAUC bundle and the image digest is
# `imageSha256`), and the version is above the firewall's signing floor
# (releases.Components: SignedManifestFrom 2026.09.4-dev.127), so the control
# plane REQUIRES the signature rather than tolerating its absence.
#
# Validity is 100 years on every cert, for the reason given in the artifactsig
# script: a realistically-dated fixture turns into a CI failure on a date nobody
# would connect to this file. Private keys are deleted at the end; nothing here
# can sign anything after the fact.
#
# Usage: ./gen-fixtures.sh    (from this directory; needs openssl 3.x)
set -euo pipefail
cd "$(dirname "$0")"

DAYS=36500
VERSION="2026.09.4-dev.130"
IMAGE="rasputin-fw-n100-${VERSION}-ab.img.gz"
SHA="455e19da50a95802d2684bae259edce8668a07c6a80aa4a7e3efb87a1d45dafd"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

openssl req -x509 -newkey rsa:4096 -noenc -keyout "$work/root.key" -out root-ca.pem \
  -days "$DAYS" -sha256 -subj "/C=US/O=Geekdojo Test/CN=Rasputin Test Root CA (firewall manifest)"

openssl req -newkey rsa:4096 -noenc -keyout "$work/int.key" -out "$work/int.csr" \
  -subj "/C=US/O=Geekdojo Test/CN=Rasputin Test Intermediate CA (firewall manifest)"
openssl x509 -req -in "$work/int.csr" -CA root-ca.pem -CAkey "$work/root.key" \
  -CAcreateserial -CAserial "$work/root.srl" -out "$work/int.pem" -days "$DAYS" -sha256 \
  -extfile <(printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n')

openssl req -newkey rsa:2048 -noenc -keyout "$work/leaf.key" -out "$work/leaf.csr" \
  -subj "/C=US/O=Geekdojo Test/CN=Rasputin Test Release Leaf (firewall manifest)"
openssl x509 -req -in "$work/leaf.csr" -CA "$work/int.pem" -CAkey "$work/int.key" \
  -CAcreateserial -CAserial "$work/int.srl" -out "$work/leaf.pem" -days "$DAYS" -sha256 \
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning,emailProtection,1.3.6.1.4.1.66587.1.1.1\n')

printf '{"version":"%s","channel":"dev","artifacts":[{"sku":"fw-n100","architecture":"amd64","compatible":"rasputin-fw-n100","kind":"ab","image":"%s","sha256":"%s","sizeBytes":60127009}]}\n' \
  "$VERSION" "$IMAGE" "$SHA" > manifest.json

# VERBATIM from the release pipeline's sign_file(), modulo paths.
openssl cms -sign -binary \
  -in manifest.json \
  -signer   "$work/leaf.pem" \
  -certfile "$work/int.pem" \
  -inkey    "$work/leaf.key" \
  -outform DER \
  -out manifest.json.sig

# Prove the pair before anyone relies on it.
openssl cms -verify -purpose any -binary -inform DER -in manifest.json.sig \
  -content manifest.json -CAfile root-ca.pem -out /dev/null
