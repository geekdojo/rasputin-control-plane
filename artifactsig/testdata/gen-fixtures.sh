#!/usr/bin/env bash
# NOTE: leaves carry extendedKeyUsage=codeSigning because the real PKI issues
# them that way (pki-init.sh, and the deployed leaf-001). They previously
# carried no EKU at all, which is a shape Rasputin has never issued — harmless
# until #192 made the verifier ask what a leaf is authorized to do, at which
# point the only thing failing was the fixtures' unrealism.
# Regenerate the checked-in CMS fixtures for the artifactsig tests.
#
# These are NOT hand-rolled: the signing command below is a copy of the one the
# firewall release pipeline runs (rasputin-openwrt-firewall
# .github/workflows/release.yml, "CMS-sign images + emit manifest.json"), and
# the chain shape is a copy of the production PKI's — root → intermediate →
# leaf, leaf with CA:FALSE + digitalSignature and no EKU. The point of the
# fixtures is to prove the verifier accepts exactly what the pipeline emits, so
# any divergence here quietly destroys their value. If the pipeline's sign_file
# changes, change this to match and regenerate.
#
# Validity is 100 years on every cert on purpose. The production leaf is
# 2-yearly and the verifier checks the chain at time.Now() (see the package
# doc), so a realistically-dated fixture would turn into a CI failure on a date
# nobody would connect to this file.
#
# Usage: ./gen-fixtures.sh    (from this directory; needs openssl 3.x)
set -euo pipefail
cd "$(dirname "$0")"

DAYS=36500

rm -f root-ca.pem root-ca.key intermediate.pem intermediate.key leaf.pem leaf.key \
      other-root-ca.pem other-root-ca.key other-leaf.pem other-leaf.key \
      payload.bin payload.bin.sig payload.bin.other.sig *.csr *.srl

# --- the trusted chain ------------------------------------------------------
openssl req -x509 -newkey rsa:4096 -noenc -keyout root-ca.key -out root-ca.pem \
  -days "$DAYS" -sha256 -subj "/C=US/O=Geekdojo Test/CN=Rasputin Test Root CA"

openssl req -newkey rsa:4096 -noenc -keyout intermediate.key -out intermediate.csr \
  -subj "/C=US/O=Geekdojo Test/CN=Rasputin Test Intermediate CA"
openssl x509 -req -in intermediate.csr -CA root-ca.pem -CAkey root-ca.key \
  -CAcreateserial -out intermediate.pem -days "$DAYS" -sha256 \
  -extfile <(printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n')

openssl req -newkey rsa:2048 -noenc -keyout leaf.key -out leaf.csr \
  -subj "/C=US/O=Geekdojo Test/CN=Rasputin Test Release Leaf"
openssl x509 -req -in leaf.csr -CA intermediate.pem -CAkey intermediate.key \
  -CAcreateserial -out leaf.pem -days "$DAYS" -sha256 \
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\n')

# --- a CATALOG-purpose leaf under the SAME root -----------------------------
# Carries the catalog OID and deliberately NOT codeSigning, exactly as
# pki-init.sh --catalog-leaf mints it. This is what makes the cross-purpose
# tests possible: without a leaf that is legitimate for one purpose and not
# the other, "the release leaf cannot sign a catalog" is untestable, and an
# authorization bug there looks identical to a working system.
openssl req -newkey rsa:2048 -noenc -keyout catalog-leaf.key -out catalog-leaf.csr \
  -subj "/C=US/O=Geekdojo Test/CN=Rasputin Test Catalog Leaf"
openssl x509 -req -in catalog-leaf.csr -CA intermediate.pem -CAkey intermediate.key \
  -CAcreateserial -out catalog-leaf.pem -days "$DAYS" -sha256 \
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=1.3.6.1.4.1.66587.1.1.2\n')

# --- an equally well-formed chain under a DIFFERENT root --------------------
# The "attacker signed it properly, just not with our key" case. Without this,
# a verifier that parses the CMS and forgets to pin the root still passes every
# other test in the file.
openssl req -x509 -newkey rsa:4096 -noenc -keyout other-root-ca.key -out other-root-ca.pem \
  -days "$DAYS" -sha256 -subj "/C=US/O=Someone Else/CN=Not Rasputin Root CA"
openssl req -newkey rsa:2048 -noenc -keyout other-leaf.key -out other-leaf.csr \
  -subj "/C=US/O=Someone Else/CN=Not Rasputin Leaf"
openssl x509 -req -in other-leaf.csr -CA other-root-ca.pem -CAkey other-root-ca.key \
  -CAcreateserial -out other-leaf.pem -days "$DAYS" -sha256 \
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\n')

# --- the payload + its detached signatures ----------------------------------
# Deliberately not a round number of blocks, so an off-by-one in streaming
# hashing shows up as a failure rather than as luck.
head -c 65537 /dev/urandom > payload.bin

# VERBATIM from the release pipeline's sign_file(), modulo paths.
openssl cms -sign -binary \
  -in payload.bin \
  -signer   leaf.pem \
  -certfile intermediate.pem \
  -inkey    leaf.key \
  -outform DER \
  -out payload.bin.sig

openssl cms -sign -binary \
  -in payload.bin \
  -signer other-leaf.pem \
  -inkey  other-leaf.key \
  -outform DER \
  -out payload.bin.other.sig

# The same payload signed by the CATALOG leaf. Pairing it with payload.bin.sig
# (release leaf) over the SAME bytes is the point: the two differ only in what
# the signer was authorized to do, so a purpose check that does nothing passes
# both and a correct one passes exactly one each way.
openssl cms -sign -binary \
  -in payload.bin \
  -signer   catalog-leaf.pem \
  -certfile intermediate.pem \
  -inkey    catalog-leaf.key \
  -outform DER \
  -out payload.bin.catalog.sig

# Prove the fixtures are what we think they are before checking them in: if
# openssl itself will not verify them, the Go tests are testing nothing.
openssl cms -verify -binary -inform DER -in payload.bin.sig -content payload.bin \
  -CAfile root-ca.pem > /dev/null
echo "ok: payload.bin.sig verifies against root-ca.pem"

# Everything that is not needed to VERIFY is removed before the fixtures are
# checked in. No private key of any kind survives this line, and neither do the
# leaf or intermediate certs — those travel inside the CMS object itself, so the
# tests never read them from disk. What remains is two public root certificates
# and the signed payload.
#
# This matters because the repo is public and .gitignore blanket-ignores *.key
# and *.pem for that reason. The *.pem ignore carries one narrow, commented
# negation for this directory; the *.key ignore has none, and nothing here
# should ever make anyone want one.
rm -f *.csr *.srl *.key intermediate.pem leaf.pem other-leaf.pem
echo "fixtures regenerated"
