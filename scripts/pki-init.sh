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
#      sealed CI secret), used to issue new leaf certs. Leaves are minted for
#      LEAF_DAYS (2 years) — see that constant for why the number matters.
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
  --rotate-leaf      Issue a new RELEASE leaf under the existing intermediate
  --catalog-leaf     Issue a new APP-CATALOG leaf under the existing intermediate.
                     Carries the catalog purpose only, so it cannot sign an OS
                     or firmware artifact even though it shares the trust root.
                     (requires intermediate-ca.{key,pem} already in --out-dir)
EOF
    exit 1
}

OUT_DIR="./pki-out"
CN_PREFIX="Rasputin"
ROTATE_LEAF=0
CATALOG_LEAF=0
LEAF_NUM=""

# Leaf validity, in days. 730 = 2 years, matching the deployed leaf-001
# (notAfter 2028-05-29). This was hardcoded 90 in both leaf paths while the
# leaf actually in production was minted for two years, so the script did not
# reproduce the PKI it claims to bootstrap and --rotate-leaf would have quietly
# issued a 90-day cert.
#
# The number is load-bearing, not a preference: artifactsig
# verifies the chain at time.Now() rather than at the signature's signingTime,
# so when a leaf expires every artifact it ever signed stops being installable
# OTA until re-signed. Shortening this shortens the shelf life of every release
# it touches, retroactively. Expiry alarm + rotation runbook: geekdojo/geekdojo-brain#191.
LEAF_DAYS=730

# The deployed PKI is EC P-384 with ecdsa-with-SHA384 throughout — root,
# intermediate and leaf-001 all secp384r1. This script generated RSA-4096, so
# a leaf it issued was RSA under an EC intermediate: valid, but not the PKI
# this script claims to bootstrap. Same class of drift as the LEAF_DAYS note
# below, found the same way — by reading the certs actually in use.
EC_CURVE="secp384r1"

# Purpose OIDs under Geekdojo's IANA Private Enterprise Number 66587, assigned
# 2026-08-20. These MUST stay identical to artifactsig/eku.go —
# a leaf minted under a different arc than the verifier expects is refused by
# the whole fleet, and the symptom is "updates stopped working", not an error
# anyone can read. eku.go pins the same strings in TestOIDArc_IsPinned.
OID_RELEASE="1.3.6.1.4.1.66587.1.1.1"
OID_CATALOG="1.3.6.1.4.1.66587.1.1.2"

# A RELEASE leaf carries the release OID, generic codeSigning, AND
# emailProtection. All three are load-bearing; none is decoration.
#
# codeSigning is transitional: agents predating the EKU check authorize on
# chain-to-root and a leaf without it may not satisfy their purpose check, so
# dropping it now would strand any node that has not taken the update. Remove
# it once no such node remains (ADR-0006 Decision 3's tracked trigger).
#
# emailProtection is here for a reason that looks absurd and is not: OpenSSL's
# CMS_verify() defaults to the S/MIME SIGNING purpose, and that purpose requires
# emailProtection in the leaf's EKU. RAUC verifies bundles with CMS_verify and
# only overrides the purpose when [keyring] check-purpose is set in system.conf
# — which NO deployed Rasputin board sets. So the effective requirement on every
# node already in the field is the S/MIME purpose, whatever we think we are
# issuing.
#
# This is not theory. leaf-001 carried NO EKU at all, so every purpose was
# satisfied vacuously and nobody noticed the rule existed. leaf-002 carried
# codeSigning + the release OID and nothing else, and rasputin-os release run
# #171 died in `rauc bundle` with:
#
#     Verify error: unsuitable certificate purpose
#
# which is X509_V_ERR_INVALID_PURPOSE (error 26). Reproduced directly against
# the real leaf and the public root:
#
#     openssl verify -purpose smimesign leaf-002.pem  -> error 26
#     openssl verify -purpose codesign  leaf-002.pem  -> OK
#
# Because `rauc bundle --signing-keyring` runs the SAME check a device runs at
# install, that failure was not merely a build error: it was a demonstration
# that the deployed fleet would refuse the bundle. Dropping emailProtection
# again is safe only once every node runs an image whose rauc-system.conf sets
# `[keyring] check-purpose=codesign`, at which point the S/MIME default no
# longer applies to anyone.
#
# It does NOT weaken the purpose split. artifactsig authorizes on the Rasputin
# arc under UnknownExtKeyUsage; emailProtection is a KNOWN usage in Go and lands
# in ExtKeyUsage, so it is invisible to that check. A catalog leaf still cannot
# sign a release, which is the property Decision 3 buys.
EKU_RELEASE="codeSigning,emailProtection,${OID_RELEASE}"

# A CATALOG leaf carries the catalog OID and NOTHING ELSE — deliberately not
# codeSigning. That single omission is the whole blast-radius separation: a
# holder of the catalog key cannot produce a signature the OTA path accepts,
# and cannot grant themselves the release purpose without the intermediate key,
# which is offline.
EKU_CATALOG="${OID_CATALOG}"

while [[ $# -gt 0 ]]; do
    case $1 in
        --out-dir) OUT_DIR=$2; shift 2 ;;
        --cn-prefix) CN_PREFIX=$2; shift 2 ;;
        --rotate-leaf) ROTATE_LEAF=1; shift ;;
        --leaf-num) LEAF_NUM=$2; shift 2 ;;
        --catalog-leaf) CATALOG_LEAF=1; shift ;;
        -h|--help) usage ;;
        *) echo "unknown arg: $1" >&2; usage ;;
    esac
done

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

if [[ $CATALOG_LEAF -eq 1 ]]; then
    if [[ ! -f intermediate-ca.key || ! -f intermediate-ca.pem ]]; then
        echo "error: intermediate-ca.{key,pem} not found in $OUT_DIR; cannot issue a catalog leaf" >&2
        exit 2
    fi
    last=$(ls -1 catalog-leaf-*.pem 2>/dev/null | sed 's/catalog-leaf-\([0-9]*\)\.pem/\1/' | sort -n | tail -1 || true)
    if [[ -z "$last" ]]; then next="001"; else next=$(printf "%03d" $((10#$last + 1))); fi

    echo "==> Issuing catalog-leaf-${next} under existing intermediate"
    openssl ecparam -genkey -name "$EC_CURVE" -noout -out "catalog-leaf-${next}.key"
    openssl req -new -key "catalog-leaf-${next}.key" -out "catalog-leaf-${next}.csr" \
        -subj "/CN=${CN_PREFIX} App Catalog Signing catalog-leaf-${next}"
    openssl x509 -req -in "catalog-leaf-${next}.csr" \
        -CA intermediate-ca.pem -CAkey intermediate-ca.key -CAcreateserial \
        -out "catalog-leaf-${next}.pem" -days "$LEAF_DAYS" -sha384 \
        -extfile <(printf "keyUsage=critical,digitalSignature\nextendedKeyUsage=critical,%s" "$EKU_CATALOG")
    rm -f "catalog-leaf-${next}.csr"

    # Prove what was minted rather than trusting the flags. A leaf that
    # silently acquired codeSigning would re-merge the blast radii this
    # separation exists to keep apart, and nothing downstream would notice.
    if openssl x509 -in "catalog-leaf-${next}.pem" -noout -text | grep -q "Code Signing"; then
        echo "error: catalog leaf carries codeSigning — it must not" >&2
        exit 1
    fi
    if ! openssl x509 -in "catalog-leaf-${next}.pem" -noout -text | grep -q "$OID_CATALOG"; then
        echo "error: catalog leaf is missing the catalog purpose $OID_CATALOG" >&2
        exit 1
    fi
    openssl verify -CAfile root-ca.pem -untrusted intermediate-ca.pem \
        -purpose any "catalog-leaf-${next}.pem" >/dev/null \
        || { echo "error: catalog leaf does not chain to the root" >&2; exit 1; }

    chmod 600 "catalog-leaf-${next}.key"
    cat <<EOF

done: catalog-leaf-${next}.{key,pem}
  purpose: ${OID_CATALOG} (app-catalog bundles only; NOT codeSigning)
  expires: $(openssl x509 -in "catalog-leaf-${next}.pem" -noout -enddate | cut -d= -f2)

Load into the catalog repo as repository secrets:
  RASPUTIN_CATALOG_LEAF_CERT   cat catalog-leaf-${next}.pem intermediate-ca.pem
  RASPUTIN_CATALOG_LEAF_KEY    catalog-leaf-${next}.key

The CERT secret is the leaf AND the intermediate, in that order — the publish
workflow splits them, and the signature must embed both so a node holding only
the root can build the chain.
EOF
    exit 0
fi

# Prove a freshly minted RELEASE leaf satisfies every purpose its consumers
# actually demand, before it can reach a CI secret.
#
# The check this replaces ran `openssl verify` with no -purpose, which checks
# the chain and skips purpose ENTIRELY. That is precisely how leaf-002 shipped:
# a perfectly valid chain that no CMS verifier would accept. The failure then
# surfaced 50 minutes into a release build as RAUC's "unsuitable certificate
# purpose", with nothing pointing at the certificate.
#
# Each purpose below has a named consumer, so a failure says who would refuse it.
verify_release_leaf() {
    local leaf=$1
    local anchor=(-CAfile root-ca.pem -untrusted intermediate-ca.pem)
    if [[ ! -f root-ca.pem ]]; then
        # Rotating with only the intermediate to hand is normal — the root is
        # offline, and only the intermediate key is needed to issue. Anchor on
        # the intermediate instead.
        #
        # -partial_chain is REQUIRED here and is not optional politeness: the
        # intermediate is not self-signed, so without it openssl refuses to
        # treat it as a trust anchor and BOTH purposes fail identically. That
        # false failure is indistinguishable from the real one this function
        # exists to catch, which would send someone hunting a certificate bug
        # that isn't there. The purposes being checked are properties of the
        # leaf, so the shorter chain tests exactly the same thing.
        echo "    (root-ca.pem absent; anchoring the purpose check on the intermediate)"
        anchor=(-CAfile intermediate-ca.pem -partial_chain)
    fi

    local failed=0

    # smimesign — OpenSSL CMS_verify's DEFAULT purpose, and therefore what
    # `rauc bundle` and every deployed board enforce today, because no
    # rasputin-os board sets [keyring] check-purpose. Needs emailProtection.
    # This purpose has existed forever, so it is safe to ask for by name.
    if openssl verify "${anchor[@]}" -purpose smimesign "$leaf" >/dev/null 2>&1; then
        echo "    purpose smimesign: OK"
    else
        echo "    purpose smimesign: FAILED — the deployed fleet will refuse every artifact this leaf signs" >&2
        failed=1
    fi

    # RAUC's codesign semantics, checked on the extensions rather than through
    # OpenSSL's "codesign" purpose.
    #
    # Do NOT switch this to `-purpose codesign`. That purpose is absent from
    # OpenSSL 3.0.13 (ubuntu-latest), where it yields "Invalid purpose
    # codesign" — a failure about the tool, not the certificate. It cost a
    # release build once already, on a leaf that was correct. Local openssl
    # being newer is exactly what makes the trap hard to see from a Mac.
    #
    # It is also the more faithful test: RAUC does not use OpenSSL's purpose.
    # It registers its own with X509_PURPOSE_add ("codesign-rauc",
    # src/signature.c), and that callback asks a leaf for precisely these two.
    local eku ku
    eku=$(openssl x509 -in "$leaf" -noout -ext extendedKeyUsage 2>/dev/null || true)
    ku=$(openssl x509 -in "$leaf" -noout -ext keyUsage 2>/dev/null || true)
    if grep -q "Code Signing" <<<"$eku" && grep -q "Digital Signature" <<<"$ku"; then
        echo "    RAUC codesign semantics (EKU codeSigning + KU digitalSignature): OK"
    else
        echo "    RAUC codesign semantics: FAILED — a board with check-purpose=codesign will refuse this leaf" >&2
        echo "      extendedKeyUsage: ${eku:-<none>}" >&2
        echo "      keyUsage:         ${ku:-<none>}" >&2
        failed=1
    fi

    if ! openssl x509 -in "$leaf" -noout -text | grep -q "$OID_RELEASE"; then
        echo "    release purpose $OID_RELEASE: MISSING — artifactsig will refuse it" >&2
        failed=1
    else
        echo "    release purpose $OID_RELEASE: present"
    fi

    if [[ $failed -ne 0 ]]; then
        echo "error: $leaf is not usable as a release signing leaf; refusing to hand it over." >&2
        return 1
    fi
    echo "    $leaf is accepted by every consumer checked."
}

if [[ $ROTATE_LEAF -eq 1 ]]; then
    if [[ ! -f intermediate-ca.key || ! -f intermediate-ca.pem ]]; then
        echo "error: intermediate-ca.{key,pem} not found in $OUT_DIR; cannot rotate" >&2
        exit 2
    fi
    # Pick the leaf number.
    #
    # Auto-derivation reads leaf-*.pem in OUT_DIR, which is only correct when
    # this directory still holds the previous leaves. It usually does not: the
    # working copies are moved into 1Password and the directory is wiped, which
    # is the RIGHT thing to do with private keys and makes the highest-numbered
    # file on disk an unreliable record of what has been issued. An empty
    # directory silently re-derives "001" and mints a SECOND leaf-001 — two
    # different keys sharing a common name, which is unresolvable after the
    # fact from a signature alone.
    #
    # So --leaf-num is explicit and always available, and auto-derivation is
    # kept only for the case where the evidence is actually present.
    if [[ -n "$LEAF_NUM" ]]; then
        if [[ ! "$LEAF_NUM" =~ ^[0-9]{1,3}$ ]]; then
            echo "error: --leaf-num must be 1-3 digits, got '$LEAF_NUM'" >&2
            exit 2
        fi
        next=$(printf "%03d" $((10#$LEAF_NUM)))
    else
        last=$(ls -1 leaf-*.pem 2>/dev/null | sed 's/leaf-\([0-9]*\)\.pem/\1/' | sort -n | tail -1 || true)
        if [[ -z "$last" ]]; then
            echo "error: no leaf-*.pem in $OUT_DIR to derive the next number from." >&2
            echo "       This is expected when the directory was wiped after archiving to" >&2
            echo "       1Password. Pass the number explicitly so a name is never reused:" >&2
            echo "         $0 --rotate-leaf --leaf-num 003" >&2
            exit 2
        fi
        next=$(printf "%03d" $((10#$last + 1)))
    fi
    if [[ -e "leaf-${next}.pem" || -e "leaf-${next}.key" ]]; then
        echo "error: leaf-${next}.{pem,key} already exists in $OUT_DIR — refusing to overwrite." >&2
        exit 2
    fi
    echo "==> Issuing leaf-${next} under existing intermediate"
    openssl ecparam -genkey -name "$EC_CURVE" -noout -out "leaf-${next}.key"
    openssl req -new -key "leaf-${next}.key" -out "leaf-${next}.csr" \
        -subj "/CN=${CN_PREFIX} Bundle Signing leaf-${next}"
    openssl x509 -req -in "leaf-${next}.csr" \
        -CA intermediate-ca.pem -CAkey intermediate-ca.key -CAcreateserial \
        -out "leaf-${next}.pem" -days "$LEAF_DAYS" -sha384 \
        -extfile <(printf "keyUsage=critical,digitalSignature\nextendedKeyUsage=critical,%s" "$EKU_RELEASE")
    rm -f "leaf-${next}.csr"
    echo "==> Verifying leaf-${next} against every consumer's purpose"
    verify_release_leaf "leaf-${next}.pem" || exit 1
    chmod 600 "leaf-${next}.key"
    echo "done: leaf-${next}.{key,pem}"
    exit 0
fi

if [[ -f root-ca.key ]]; then
    echo "error: root-ca.key already exists in $OUT_DIR" >&2
    echo "       refusing to overwrite. delete it or pick a different --out-dir." >&2
    exit 2
fi

echo "==> Generating Rasputin Root CA"
openssl ecparam -genkey -name "$EC_CURVE" -noout -out root-ca.key
openssl req -x509 -new -key root-ca.key -out root-ca.pem -days 7300 -sha384 \
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
openssl ecparam -genkey -name "$EC_CURVE" -noout -out intermediate-ca.key
openssl req -new -key intermediate-ca.key -out intermediate-ca.csr \
    -subj "/CN=${CN_PREFIX} Update Signing CA"
openssl x509 -req -in intermediate-ca.csr \
    -CA root-ca.pem -CAkey root-ca.key -CAcreateserial \
    -out intermediate-ca.pem -days 3650 -sha384 \
    -extfile <(cat <<EOF
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
EOF
)
rm -f intermediate-ca.csr

echo "==> Generating first release leaf cert (leaf-001)"
openssl ecparam -genkey -name "$EC_CURVE" -noout -out leaf-001.key
openssl req -new -key leaf-001.key -out leaf-001.csr \
    -subj "/CN=${CN_PREFIX} Bundle Signing leaf-001"
openssl x509 -req -in leaf-001.csr \
    -CA intermediate-ca.pem -CAkey intermediate-ca.key -CAcreateserial \
    -out leaf-001.pem -days "$LEAF_DAYS" -sha384 \
    -extfile <(printf "keyUsage=critical,digitalSignature\nextendedKeyUsage=critical,%s" "$EKU_RELEASE")
rm -f leaf-001.csr

echo "==> Verifying leaf-001 against every consumer's purpose"
verify_release_leaf "leaf-001.pem" || exit 1

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
