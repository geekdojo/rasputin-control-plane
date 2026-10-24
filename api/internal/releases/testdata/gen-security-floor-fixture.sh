#!/usr/bin/env bash
# Regenerate the signed security-floor fixture for security_test.go
# (geekdojo/geekdojo-brain#772, TC-772-12).
#
# It exists so the watch can be driven end to end through the real release
# source AND the real verifier: a manifest carrying securityFloor, signed the
# way the release pipeline signs, under a root this directory checks in. A fake
# verifier would prove the watch reads the field, not that a floor only ever
# comes from bytes the verifier accepted.
#
# The chain shape copies the production PKI's (root -> intermediate -> leaf,
# the leaf carrying the release purpose OID) and the signing command copies the
# release pipeline's sign_file(), as artifactsig/testdata/gen-fixtures.sh does.
# Validity is 100 years so no future date turns the test red.
#
# Only the root, the manifest and its .sig are checked in. The keys are
# discarded: nothing should ever be able to make a new signature with them.
#
# Usage: ./gen-security-floor-fixture.sh    (from this directory; needs openssl 3.x)
set -euo pipefail
cd "$(dirname "$0")"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
DAYS=36500

printf '%s' '{"version":"2026.10.2","channel":"stable","artifacts":[],"securityFloor":"2026.10.2"}' > security-floor-manifest.json

openssl req -x509 -newkey rsa:2048 -noenc -keyout "$WORK/root.key" -out security-floor-root-ca.pem \
  -days "$DAYS" -sha256 -subj "/C=US/O=Geekdojo Test/CN=Rasputin Security-Floor Fixture Root CA" >/dev/null 2>&1

openssl req -newkey rsa:2048 -noenc -keyout "$WORK/int.key" -out "$WORK/int.csr" \
  -subj "/C=US/O=Geekdojo Test/CN=Rasputin Security-Floor Fixture Intermediate" >/dev/null 2>&1
openssl x509 -req -in "$WORK/int.csr" -CA security-floor-root-ca.pem -CAkey "$WORK/root.key" \
  -CAcreateserial -CAserial "$WORK/root.srl" -out "$WORK/int.pem" -days "$DAYS" -sha256 \
  -extfile <(printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n') >/dev/null 2>&1

openssl req -newkey rsa:2048 -noenc -keyout "$WORK/leaf.key" -out "$WORK/leaf.csr" \
  -subj "/C=US/O=Geekdojo Test/CN=Rasputin Security-Floor Fixture Release Leaf" >/dev/null 2>&1
openssl x509 -req -in "$WORK/leaf.csr" -CA "$WORK/int.pem" -CAkey "$WORK/int.key" \
  -CAcreateserial -CAserial "$WORK/int.srl" -out "$WORK/leaf.pem" -days "$DAYS" -sha256 \
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning,emailProtection,1.3.6.1.4.1.66587.1.1.1\n') >/dev/null 2>&1

# The release pipeline's sign_file(), verbatim in shape.
openssl cms -sign -binary \
  -in security-floor-manifest.json \
  -signer "$WORK/leaf.pem" \
  -certfile "$WORK/int.pem" \
  -inkey "$WORK/leaf.key" \
  -outform DER \
  -out security-floor-manifest.json.sig

echo "wrote security-floor-manifest.json, security-floor-manifest.json.sig, security-floor-root-ca.pem"
