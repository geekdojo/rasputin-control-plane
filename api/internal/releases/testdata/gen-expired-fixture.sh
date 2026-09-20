#!/usr/bin/env bash
# Regenerate the EXPIRED-signer fixture for manifestsig_test.go.
#
# It exists for one assertion: that an intact signature made by a leaf which
# has aged out is reported as a stale release rather than as tampering
# (dec 24, geekdojo/geekdojo-brain#576). That distinction is read out of the
# real DER by artifactsig.SignerExpiry, so a fake cannot stand in for it.
#
# The chain shape copies the production PKI's and the signing command copies the
# release pipeline's, for the same reason artifactsig/testdata/gen-fixtures.sh
# gives: a fixture that is not what the pipeline emits quietly proves nothing.
#
# The validity window is in the PAST and fixed, so this fixture is expired today
# and stays expired — no date in the future turns this test red for a reason
# nobody would connect to this file.
#
# Only the .sig is checked in. The key is discarded: nothing should ever be able
# to make a NEW signature with it.
#
# Usage: ./gen-expired-fixture.sh    (from this directory; needs openssl 3.x)
set -euo pipefail
cd "$(dirname "$0")"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

printf '%s' '{"version":"2026.09.3","channel":"stable","artifacts":[]}' > "$WORK/manifest.json"

openssl req -x509 -newkey rsa:2048 -noenc -keyout "$WORK/root.key" -out "$WORK/root.pem" \
  -days 36500 -sha256 -subj "/C=US/O=Geekdojo Test/CN=Rasputin Expired-Fixture Root CA" >/dev/null 2>&1

openssl req -newkey rsa:2048 -noenc -keyout "$WORK/int.key" -out "$WORK/int.csr" \
  -subj "/C=US/O=Geekdojo Test/CN=Rasputin Expired-Fixture Intermediate" >/dev/null 2>&1
openssl x509 -req -in "$WORK/int.csr" -CA "$WORK/root.pem" -CAkey "$WORK/root.key" \
  -CAcreateserial -out "$WORK/int.pem" -days 36500 -sha256 \
  -extfile <(printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n') >/dev/null 2>&1

openssl req -newkey rsa:2048 -noenc -keyout "$WORK/leaf.key" -out "$WORK/leaf.csr" \
  -subj "/C=US/O=Geekdojo Test/CN=Rasputin Expired-Fixture Signing leaf" >/dev/null 2>&1

# The leaf's window is 2024 — over before this fixture was written. `openssl ca`
# rather than `x509 -req -not_before`, because the latter needs OpenSSL 3.5+ and
# this has to regenerate on whatever is to hand.
mkdir -p "$WORK/ca/newcerts"; : > "$WORK/ca/index.txt"; echo 1000 > "$WORK/ca/serial"
cat > "$WORK/ca.cnf" <<EOF
[ca]
default_ca = CA_default
[CA_default]
dir = $WORK/ca
database = \$dir/index.txt
new_certs_dir = \$dir/newcerts
serial = \$dir/serial
certificate = $WORK/int.pem
private_key = $WORK/int.key
default_md = sha256
policy = pol
email_in_dn = no
rand_serial = no
unique_subject = no
[pol]
commonName = supplied
countryName = optional
organizationName = optional
[leaf_release]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,codeSigning,emailProtection,1.3.6.1.4.1.66587.1.1.1
EOF
openssl ca -batch -config "$WORK/ca.cnf" -in "$WORK/leaf.csr" -out "$WORK/leaf.pem" -notext \
  -startdate 240101000000Z -enddate 250101000000Z \
  -extfile "$WORK/ca.cnf" -extensions leaf_release >/dev/null 2>&1

# The release pipeline's sign_file(), verbatim in shape.
openssl cms -sign -binary \
  -in "$WORK/manifest.json" \
  -signer "$WORK/leaf.pem" \
  -certfile "$WORK/int.pem" \
  -inkey "$WORK/leaf.key" \
  -outform DER \
  -out expired-manifest.json.sig

echo "wrote expired-manifest.json.sig"
openssl x509 -in "$WORK/leaf.pem" -noout -subject -dates
