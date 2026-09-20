#!/usr/bin/env bash
#
# rasputin flash.sh — one-command node flasher (OS nodes AND the firewall).
#
# Served by the control plane at GET /flash.sh. The Add-node wizard hands the
# operator a single line to paste on their laptop:
#
#   curl -fsSL https://rasputin.local/flash.sh | sudo RASPUTIN_SEED_B64='…' bash
#
# It downloads the image that matches the cluster, verifies it, flashes a
# plugged-in SSD/USB, writes the node's enrollment seed onto the boot partition,
# and — critically — READS THE SEED BACK at the block level and fails loudly if
# it didn't land. A silent seed write that never reached the medium is exactly
# what stranded the first bench add-node (2026-06-22); the read-back is the
# point of this script, not a nicety.
#
# "Verifies it" means two things as of geekdojo/geekdojo-brain#527. The control
# plane hands over the release's SIGNED manifest along with the descriptor; this
# script checks that signature against a root CA pinned by fingerprint in its
# own source, requires the signer to be authorized for firmware, and then takes
# the image's checksum from the manifest it verified rather than from the
# descriptor. Before that, the checksum was simply relayed — and it is the value
# that decides whether a download gets written to a disk. See the shared
# verifier block below for what that does and does not cover.
#
# One script, both images — the seed's RASPUTIN_NODE_ROLE decides which:
#   role=firewall → the x86-only firewall image (/api/cluster/firewall-image, a
#                   .img.gz) seeded onto the RASPUTIN-FW FAT;
#   any other role → the per-arch OS image (/api/cluster/node-image, a .img.xz)
#                   seeded onto the RASPUTIN-OS FAT.
# There is deliberately no "if firewall" flag on the command line: the seed
# already carries the difference, so the firewall one-liner is byte-identical to
# the OS one-liner apart from its (opaque) base64 seed. The decompressor is
# picked from the image's own filename below, not hard-coded per role.
#
# Secret handling: the only secret is the seed (it carries the one-time, node-
# bound join token). It is passed in via RASPUTIN_SEED_B64 (base64) and never
# placed in a URL or fetched from the server — this script itself contains no
# secrets. Image version/URL/sha are non-secret and fetched from the control
# plane's image endpoint (node-image or firewall-image; see above).
#
# Cross-platform: macOS (diskutil + mtools/diskutil) and Linux (lsblk + mtools/
# mount). Safe by construction: only external/removable disks are offered, the
# disk backing the laptop's own root filesystem is never a candidate, and a
# typed confirmation is required before anything is written.
#
# Env knobs:
#   RASPUTIN_SEED_B64    (required) base64 of the rasputin-seed.env contents
#   RASPUTIN_ROOT_CA_FILE  use a local copy of the Rasputin root CA instead of
#                        fetching it. It must still match the fingerprint baked
#                        into this script.
#   RASPUTIN_ARCH        target CPU arch: amd64 (default) or arm64. Selects which
#                        per-arch OS image the control plane hands back (amd64 =
#                        N100/Intel, arm64 = CM5/Raspberry Pi). The Add-node
#                        wizard sets this from the architecture you pick. OS
#                        nodes only — ignored for a firewall seed (x86-only, and
#                        its image endpoint takes no arch).
#   RASPUTIN_CP_URL      override control-plane base URL (default: derived from
#                        the seed's NATS host, else http://rasputin.local)
#   RASPUTIN_DISK        target device (e.g. /dev/disk4 or /dev/sdb); skips the
#                        interactive picker (still asks for confirmation unless
#                        RASPUTIN_ASSUME_YES=1)
#   RASPUTIN_ASSUME_YES  =1 to skip the typed confirmation (non-interactive)
#   RASPUTIN_DRY_RUN     =1 to print the plan and stop before any write
#   RASPUTIN_ALLOW_INTERNAL =1 to also offer internal disks (dangerous)
#
set -euo pipefail

RED=''; GRN=''; YEL=''; BLD=''; RST=''
if [ -t 2 ]; then RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; BLD=$'\033[1m'; RST=$'\033[0m'; fi
say()  { printf '%s\n' "$*" >&2; }
info() { printf '%s==>%s %s\n' "$GRN" "$RST" "$*" >&2; }
warn() { printf '%s!!%s  %s\n' "$YEL" "$RST" "$*" >&2; }
die()  { printf '%sERROR:%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }
ask()  { # ask <prompt-var> ; reads from the terminal even under `curl | bash`
	local __p="$1" __v
	if [ -r /dev/tty ]; then printf '%s' "$__p" >&2; IFS= read -r __v </dev/tty || __v=""; else __v=""; fi
	printf '%s' "$__v"
}
have() { command -v "$1" >/dev/null 2>&1; }

# ==============================================================================
# BEGIN shared release verifier
# ------------------------------------------------------------------------------
# This block is the ONE laptop-side verifier, kept BYTE-IDENTICAL in two places:
#
#   rasputin-site               static/bootstrap.sh          (canonical copy)
#   rasputin-control-plane      api/internal/api/flash.sh    (vendored copy)
#
# The markers are how the two are compared: rasputin-control-plane's
# TestFlashScriptVerifierMatchesCanonical extracts everything between them and
# checks it against a pinned hash, so an edit to one copy fails that repo's
# tests until the other is updated. Change the canonical copy, then copy the
# whole block across, markers included.
#
# The two scripts are otherwise different programs — bootstrap.sh flashes a
# FIRST control plane from a public release, flash.sh joins a node to a running
# cluster and is handed the manifest by that cluster — and only this part is
# shared, because only this part is a security decision.
#
# WHAT IT ESTABLISHES (geekdojo/geekdojo-brain#528)
#   Before this, a first flash trusted the release manifest on HTTPS plus GitHub
#   repository write: `manifest.json` arrived over TLS, the image's SHA-256 was
#   read out of it, and the manifest's own signature — published beside it —
#   was never fetched. Every checksum below is only as trustworthy as the
#   document it was read from, so the chain started at "whatever GitHub served".
#
#   Now it starts at a fingerprint baked into this file:
#
#     1. the root CA is downloaded and its SHA-256 fingerprint must equal
#        RASPUTIN_ROOT_CA_SHA256 below — so the anchor comes from the script's
#        own bytes, not from the fetch;
#     2. `manifest.json.sig` must verify against that root;
#     3. the SIGNER must carry the release purpose OID — this is the check that
#        binds the signature to firmware, rather than to any leaf the same root
#        happens to have issued;
#     4. only then is a SHA-256 read out of the manifest and the image checked
#        against it (the existing check, further down).
#
#   THIS DOES NOT make a compromised control plane safe: it closes tampering
#   with the published release assets, which is the threat a laptop faces.
#
# TOOLING
#   `openssl` only — a laptop has no Rasputin binary. macOS ships LibreSSL
#   3.3.6, Linux ships OpenSSL 3.x; the commands below were measured on both
#   (geekdojo/geekdojo-brain#474). Two consequences worth not re-deriving:
#     - `x509 -ext` does not exist on LibreSSL, so the EKU is read from
#       `x509 -text`;
#     - `-purpose any` on the CMS verify, because the default purpose is
#       S/MIME: it passes today only because the release leaf happens to carry
#       emailProtection, which is incidental. The purpose gate is the OID check,
#       which is what the control plane and the node agent also enforce.
# ==============================================================================

# The Rasputin root CA, by fingerprint. This is the anchor: a root that does not
# hash to this is refused no matter where it came from. Published alongside the
# PEM at https://rasputin.geekdojo.com/docs/agents/.
RASPUTIN_ROOT_CA_URL="https://rasputin.geekdojo.com/rasputin-root-ca.pem"
RASPUTIN_ROOT_CA_SHA256="677e570613873e08a32cf5f4527610338d575ac4e9675ccd91c443febd27c1b9"

# The release purpose. A leaf carrying it may sign OS and firmware artifacts; a
# leaf without it may not, whatever else it chains to. Matched as a WHOLE TOKEN
# below — the raw string is a prefix of any future …1.1.1x OID, so a substring
# test would accept a purpose that has not been minted yet.
RASPUTIN_RELEASE_OID="1.3.6.1.4.1.66587.1.1.1"

# sha256_of <file> — print a file's SHA-256, on whichever tool the box has.
sha256_of() {
	if have shasum; then shasum -a 256 "$1" | awk '{print $1}'
	elif have sha256sum; then sha256sum "$1" | awk '{print $1}'
	else return 1
	fi
}

# rasputin_openssl — the openssl to use, or empty if there is none.
rasputin_openssl() { command -v openssl 2>/dev/null; }

# cert_fingerprint <pem> — the SHA-256 fingerprint of the first certificate in a
# PEM file, as bare lowercase hex.
#
# The fingerprint of the CERTIFICATE (its DER), not of the file. A PEM can gain
# a comment, a trailing newline or CRLF endings and still be the same
# certificate, so hashing the file would refuse a root that is in fact ours. It
# is also the form published for a human to compare against
# (`openssl x509 -noout -fingerprint -sha256`), so the value below is the value
# on the docs page rather than a second, differently-computed one.
cert_fingerprint() {
	local ssl
	ssl="$(rasputin_openssl || true)"
	[ -n "$ssl" ] || return 1
	"$ssl" x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null \
		| sed 's/^.*=//; s/://g' | tr 'A-Z' 'a-z'
}

# rasputin_trusted_root <workdir> — put a FINGERPRINT-CHECKED root CA at
# <workdir>/root-ca.pem, or die. Set RASPUTIN_ROOT_CA_FILE to use a local copy
# instead of downloading; it is checked against the same fingerprint.
rasputin_trusted_root() {
	local work="$1" dest="$1/root-ca.pem" got
	if [ -n "${RASPUTIN_ROOT_CA_FILE:-}" ]; then
		[ -r "$RASPUTIN_ROOT_CA_FILE" ] || die "can't read RASPUTIN_ROOT_CA_FILE: $RASPUTIN_ROOT_CA_FILE"
		cp "$RASPUTIN_ROOT_CA_FILE" "$dest" || die "couldn't copy $RASPUTIN_ROOT_CA_FILE"
	else
		curl -fsSL --max-time 30 -o "$dest" "$RASPUTIN_ROOT_CA_URL" \
			|| die "couldn't fetch the Rasputin root CA from $RASPUTIN_ROOT_CA_URL — check your network."
	fi
	got="$(cert_fingerprint "$dest" || true)"
	[ -n "$got" ] \
		|| die "couldn't read a certificate out of the root CA at $dest — openssl is required (macOS ships it; on Linux install the 'openssl' package). Refusing to continue."
	[ "$got" = "$RASPUTIN_ROOT_CA_SHA256" ] || die \
"the Rasputin root CA does not match the fingerprint built into this script.
  expected  $RASPUTIN_ROOT_CA_SHA256
  got       $got
Nothing was written. Either this script is out of date, or what you downloaded
is not the Rasputin root CA. Re-download the script from
https://rasputin.geekdojo.com/bootstrap.sh and try again."
	printf '%s' "$dest"
}

# rasputin_verify_manifest <manifest> <sig> <root-ca> <workdir> <stale-advice>
#
# Verify the detached CMS signature over the manifest, then require the release
# purpose OID on the signer. Dies on any failure; prints nothing on success but
# a one-line confirmation. <stale-advice> is the sentence to print when the
# signature is fine but the signing certificate has EXPIRED — a caller that is
# adding a node to a running cluster and one that is flashing a first node need
# different advice for the same condition.
rasputin_verify_manifest() {
	local manifest="$1" sig="$2" root="$3" work="$4" stale_advice="$5"
	local ssl signer eku

	# `|| true`: under `set -e` a failing command substitution would exit before
	# the message below, and "openssl is missing" deserves a sentence.
	ssl="$(rasputin_openssl || true)"
	[ -n "$ssl" ] || die "openssl is required to verify the release signature (macOS ships it; on Linux install the 'openssl' package). Refusing to flash an unverified image."

	[ -s "$manifest" ] || die "the release manifest is empty or missing: $manifest"
	[ -s "$sig" ] || die \
"this release has no signature for its manifest (manifest.json.sig).
Releases published before 2026-09 are not signed, and this script will not flash
an unverified image. Use the current release — drop RASPUTIN_RELEASE to take the
latest stable."

	signer="$work/signer.pem"
	if ! "$ssl" cms -verify -purpose any -binary -inform DER \
		-in "$sig" -content "$manifest" -CAfile "$root" \
		-signer "$signer" -out /dev/null 2>"$work/verify.err"; then

		# Work out WHICH failure this is before reporting it. The signature can
		# be perfectly good and still not verify, because the signing
		# certificate has a lifetime — and "certificate has expired" on a
		# release you did not choose is not a tampering report, it is a stale
		# release. Extract the signer without chain validation purely to tell
		# the two apart. (geekdojo/geekdojo-brain#576)
		if "$ssl" cms -verify -noverify -binary -inform DER \
			-in "$sig" -content "$manifest" -signer "$signer" -out /dev/null 2>/dev/null \
			&& [ -s "$signer" ] \
			&& ! "$ssl" x509 -in "$signer" -noout -checkend 0 >/dev/null 2>&1; then
			die \
"this release's signing certificate expired on $("$ssl" x509 -in "$signer" -noout -enddate 2>/dev/null | sed 's/^notAfter=//').
The signature itself is intact — the release is simply too old to install.
$stale_advice
Nothing was written."
		fi

		die \
"the release manifest's signature did NOT verify against the Rasputin root CA.
Nothing was written. Do not flash this image. openssl said:
$(sed 's/^/  /' "$work/verify.err" 2>/dev/null | tail -3)"
	fi

	[ -s "$signer" ] || die "the signature verified but openssl produced no signer certificate — refusing to continue."

	# The purpose check. `x509 -text` (not -ext: LibreSSL has no -ext), the EKU
	# value on the line after the heading, and a WHOLE-TOKEN match so
	# 1.3.6.1.4.1.66587.1.1.1x cannot pass as 1.3.6.1.4.1.66587.1.1.1.
	#
	# `|| true` is load-bearing: a certificate with NO extendedKeyUsage at all
	# makes grep exit 1, and under `set -e` a failing command substitution in an
	# ASSIGNMENT kills the script — silently, with status 1 and not one word
	# about why. The oldest published release leaf is exactly that shape, so the
	# least authorized signer there is produced the least informative refusal.
	# An empty $eku simply fails the match below, which is the right answer
	# said out loud.
	eku="$("$ssl" x509 -in "$signer" -noout -text 2>/dev/null \
		| grep -A1 'X509v3 Extended Key Usage' | tr -d '\r' || true)"
	printf '%s\n' "$eku" | grep -Eq "(^|[ ,])$(printf '%s' "$RASPUTIN_RELEASE_OID" | sed 's/\./\\./g')([ ,]|\$)" \
		|| die \
"the release manifest is signed by a certificate that is NOT authorized to sign
Rasputin OS or firmware images (it does not carry $RASPUTIN_RELEASE_OID).
Nothing was written. Do not flash this image.
  signer: $("$ssl" x509 -in "$signer" -noout -subject 2>/dev/null)"

	info "Release signature verified (signed by $("$ssl" x509 -in "$signer" -noout -subject 2>/dev/null | sed 's/^subject= *//'))."
}
# ==============================================================================
# END shared release verifier
# ==============================================================================

OS="$(uname -s)"
case "$OS" in
	Darwin|Linux) ;;
	*) die "unsupported OS: $OS (this flasher runs on macOS or Linux)" ;;
esac

[ "$(id -u)" = "0" ] || die "must run as root — paste the command including 'sudo' as shown in the wizard."

# --- decode + parse the seed --------------------------------------------------
[ -n "${RASPUTIN_SEED_B64:-}" ] || die "RASPUTIN_SEED_B64 is not set — copy the full one-line command from the control plane's Add-node dialog."
SEED="$(printf '%s' "$RASPUTIN_SEED_B64" | base64 -d 2>/dev/null || printf '%s' "$RASPUTIN_SEED_B64" | base64 -D 2>/dev/null || true)"
printf '%s' "$SEED" | grep -q '^RASPUTIN_NODE_ROLE=' || die "the seed didn't decode cleanly — re-copy the command from the wizard."

seed_val() { printf '%s\n' "$SEED" | sed -n "s/^$1=//p" | head -1; }
NODE_ID="$(seed_val RASPUTIN_NODE_ID)"
NODE_ROLE="$(seed_val RASPUTIN_NODE_ROLE)"
NATS_URL="$(seed_val RASPUTIN_NATS_URL)"

# Control-plane base URL: explicit override, else derive from the seed's NATS
# host (nats://rasputin.local:4222 -> https://rasputin.local), else default.
# HTTPS: the operator installed the mesh CA at first-run setup (it's what makes
# the web UI + passkeys work), so curl validates the control plane's cert — and
# fetching a script we pipe to `bash` over a verified channel keeps a LAN MITM
# from swapping it. A cert error here means the CA isn't trusted on this machine
# yet (install it from the control plane's trust page) — not something to -k past.
CP_URL="${RASPUTIN_CP_URL:-}"
if [ -z "$CP_URL" ]; then
	host="$(printf '%s' "$NATS_URL" | sed -e 's#^[a-z]*://##' -e 's#:.*$##')"
	[ -n "$host" ] || host="rasputin.local"
	CP_URL="https://$host"
fi
CP_URL="${CP_URL%/}"

# --- role-derived image + seed parameters ------------------------------------
# The seed's RASPUTIN_NODE_ROLE is the single source of truth for what this
# node becomes, so it also selects the two things that genuinely differ between
# the OS-node image and the firewall image: which control-plane endpoint hands
# back the image descriptor, and the volume LABEL of the seed FAT the image
# exposes. Everything downstream is identical for both — that one-code-path is
# the whole point (no "if firewall, do X differently"). The decompressor is
# derived from the image's own filename at flash time, not from the role.
case "$NODE_ROLE" in
	firewall)
		SEED_LABEL="RASPUTIN-FW"
		IMG_DESC_URL="$CP_URL/api/cluster/firewall-image"
		IMG_KIND="Rasputin Firewall"
		IMG_ARCH_LABEL="x86-64"
		;;
	*)
		# OS nodes (compute/storage/controlplane): a per-arch image, seed FAT
		# labeled RASPUTIN-OS. Arch applies only on this path — the firewall is
		# x86-only and its endpoint takes no arch.
		ARCH="${RASPUTIN_ARCH:-amd64}"
		case "$ARCH" in amd64|arm64) ;; *) die "RASPUTIN_ARCH must be amd64 or arm64 (got '$ARCH')." ;; esac
		SEED_LABEL="RASPUTIN-OS"
		IMG_DESC_URL="$CP_URL/api/cluster/node-image?arch=$ARCH"
		IMG_KIND="Rasputin OS"
		IMG_ARCH_LABEL="$ARCH"
		;;
esac

# --- fetch the image descriptor the cluster expects --------------------------
have curl || die "curl is required."
info "Asking ${CP_URL} which ${IMG_KIND} (${IMG_ARCH_LABEL}) image this cluster runs…"
DESC="$(curl -fsSL --max-time 20 "$IMG_DESC_URL" 2>/dev/null || true)"
[ -n "$DESC" ] || die "couldn't get the ${IMG_KIND} image from the control plane at $CP_URL — either this laptop isn't on the cluster's network (override with RASPUTIN_CP_URL=…), or this cluster's release has no matching image yet."
json_val() { printf '%s' "$DESC" | sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" | head -1; }
IMG_VERSION="$(json_val version)"
IMG_URL="$(json_val url)"
IMG_SHA="$(json_val sha256)"
IMG_NAME="$(json_val image)"
MANIFEST_B64="$(json_val manifestB64)"
MANIFEST_SIG_B64="$(json_val manifestSigB64)"
[ -n "$IMG_URL" ] && [ -n "$IMG_SHA" ] || die "the control plane didn't return a usable image descriptor (got: $DESC)"

# --- verify the release manifest, and take the checksum out of IT -------------
#
# Until this, the sha256 above was simply believed: the control plane said it,
# and the only thing standing behind it was the publisher's word as relayed by
# whoever served the release assets. It is the value that decides whether a
# downloaded image gets written to a disk, so relaying it is not enough
# (geekdojo/geekdojo-brain#527).
#
# The control plane now hands over the release manifest AND its detached
# signature. This verifies the signature against a root CA pinned by the
# fingerprint below, requires the signer to be authorized for firmware, and then
# reads the checksum out of the manifest it just verified — refusing if that
# disagrees with what the descriptor claimed.
#
# WHAT THIS DOES AND DOES NOT COVER. It closes tampering with the published
# release assets. It does NOT make a compromised control plane safe: this script
# is itself served by that control plane, so a control plane that lies could
# also serve a script that does not check. That threat is accepted (threat model
# §5b, F50) and is why the control plane is reached over HTTPS validated against
# the cluster's own CA.
#
# An OLDER control plane sends no manifest at all, and so does a current one for
# a release that predates manifest signing. Then this falls back to the bare
# sha256, exactly as this script has always behaved — the same integrity story
# as before, not a weaker one, and it is stated out loud rather than passed over
# in silence.
TMP="$(mktemp -d "${TMPDIR:-/tmp}/rasputin-flash.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

b64_decode() { base64 -d 2>/dev/null || base64 -D 2>/dev/null; }

if [ -n "$MANIFEST_B64" ] && [ -n "$MANIFEST_SIG_B64" ]; then
	printf '%s' "$MANIFEST_B64"     | b64_decode > "$TMP/manifest.json"     || die "the control plane's release manifest didn't decode."
	printf '%s' "$MANIFEST_SIG_B64" | b64_decode > "$TMP/manifest.json.sig" || die "the control plane's manifest signature didn't decode."

	info "Verifying the release signature…"
	ROOT_CA="$(rasputin_trusted_root "$TMP")" || exit 1
	rasputin_verify_manifest "$TMP/manifest.json" "$TMP/manifest.json.sig" "$ROOT_CA" "$TMP" \
		"Update the cluster before adding a node — a current release is signed by a current certificate."

	# The checksum now comes from the VERIFIED manifest, not from the
	# descriptor. Flatten it, split objects onto lines, take the one naming this
	# image, and prefer `imageSha256` (the OS manifest's flashable-image digest;
	# its `sha256` covers the RAUC bundle) falling back to `sha256` (the
	# firewall manifest, whose image digest is that field). The keys are
	# quote-anchored so "image" cannot match "imageSha256".
	[ -n "$IMG_NAME" ] || IMG_NAME="${IMG_URL##*/}"
	MFLAT="$(tr -d ' \n\t\r' < "$TMP/manifest.json")"
	MART="$(printf '%s' "$MFLAT" | tr '}' '\n' | grep -F "\"$IMG_NAME\"" | head -1 || true)"
	[ -n "$MART" ] || die "the signed release manifest does not mention ${IMG_NAME}. Nothing was written."
	mpluck() { printf '%s' "$MART" | sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" | head -1; }
	MSHA="$(mpluck imageSha256)"
	[ -n "$MSHA" ] || MSHA="$(mpluck sha256)"
	[ -n "$MSHA" ] || die "the signed release manifest carries no checksum for ${IMG_NAME}. Nothing was written."

	MVER="$(printf '%s' "$MFLAT" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p' | head -1)"
	[ "$MVER" = "$IMG_VERSION" ] || die "the control plane offered ${IMG_KIND} ${IMG_VERSION} but handed over a signed manifest for ${MVER}. Nothing was written."

	if [ "$MSHA" != "$IMG_SHA" ]; then
		die "the control plane's checksum for ${IMG_NAME} does not match the signed release manifest.
  control plane  $IMG_SHA
  signed         $MSHA
Nothing was written. Do not flash this image."
	fi
	IMG_SHA="$MSHA"
else
	warn "This release has no signed manifest, so the image is verified by checksum alone (as every release before manifest signing was). The checksum came from the control plane over HTTPS."
fi

info "Node ${BLD}${NODE_ID}${RST} (${NODE_ROLE}) → ${IMG_KIND} ${BLD}${IMG_VERSION}${RST} (${IMG_ARCH_LABEL})"

# --- pick the target disk -----------------------------------------------------
# list_disks prints one "<device>\t<size>\t<model>" line per candidate.
root_disk_darwin() { diskutil info -plist / 2>/dev/null | tr -d '\t' | awk 'f{gsub(/<[^>]*>/,"");print;exit} /ParentWholeDisk/{f=1}'; }
list_disks() {
	if [ "$OS" = "Darwin" ]; then
		local scope="external physical"; [ "${RASPUTIN_ALLOW_INTERNAL:-}" = "1" ] && scope="physical"
		local d
		for d in $(diskutil list $scope 2>/dev/null | awk '/^\/dev\/disk/{print $1}'); do
			local size name
			size="$(diskutil info "$d" 2>/dev/null | awk -F': *' '/Disk Size/{print $2; exit}')"
			name="$(diskutil info "$d" 2>/dev/null | awk -F': *' '/Device \/ Media Name/{print $2; exit}')"
			printf '%s\t%s\t%s\n' "$d" "${size:-?}" "${name:-disk}"
		done
	else
		local rootsrc rootdisk
		rootsrc="$(findmnt -no SOURCE / 2>/dev/null || true)"
		rootdisk="$(lsblk -no PKNAME "$rootsrc" 2>/dev/null | head -1 || true)"
		lsblk -dpno NAME,SIZE,MODEL,TRAN,RM,TYPE 2>/dev/null | while read -r name size model tran rm type rest; do
			[ "$type" = "disk" ] || continue
			[ "/dev/${rootdisk}" = "$name" ] && continue          # never the laptop's own root disk
			if [ "${RASPUTIN_ALLOW_INTERNAL:-}" != "1" ]; then
				[ "$rm" = "1" ] || [ "$tran" = "usb" ] || continue  # removable / USB only
			fi
			printf '%s\t%s\t%s\n' "$name" "${size:-?}" "${model:-disk}"
		done
	fi
}

DISK="${RASPUTIN_DISK:-}"
if [ -z "$DISK" ]; then
	mapfile_disks="$(list_disks || true)"
	if [ -z "$mapfile_disks" ]; then
		die "no external/removable disk found. Plug in the node's SSD (a USB enclosure works), then re-run. (To target an internal disk, set RASPUTIN_ALLOW_INTERNAL=1 — careful.)"
	fi
	say ""; say "${BLD}Plugged-in disks:${RST}"
	i=0; devs=""
	while IFS=$'\t' read -r dev size model; do
		i=$((i+1)); devs="$devs $dev"
		printf '  %s) %-14s %8s  %s\n' "$i" "$dev" "$size" "$model" >&2
	done <<EOF
$mapfile_disks
EOF
	say ""
	sel="$(ask "Which disk number to flash (1-$i, or q to quit)? ")"
	[ "$sel" = "q" ] && die "cancelled."
	case "$sel" in ''|*[!0-9]*) die "not a number: '$sel'";; esac
	[ "$sel" -ge 1 ] && [ "$sel" -le "$i" ] || die "out of range: $sel"
	DISK="$(printf '%s' "$devs" | tr ' ' '\n' | sed -n "$((sel+1))p")"
fi
[ -n "$DISK" ] && [ -b "$DISK" ] || die "invalid disk: '$DISK'"

# Refuse the root disk on Linux even if passed explicitly.
if [ "$OS" = "Linux" ]; then
	rootsrc="$(findmnt -no SOURCE / 2>/dev/null || true)"
	rootdisk="$(lsblk -no PKNAME "$rootsrc" 2>/dev/null | head -1 || true)"
	[ "/dev/${rootdisk}" = "$DISK" ] && die "refusing to flash $DISK — it backs this computer's root filesystem."
fi

# --- confirm ------------------------------------------------------------------
DISK_DESC="$(list_disks | awk -F'\t' -v d="$DISK" '$1==d{print $2"  "$3}')"
say ""
warn "About to ${BLD}ERASE ALL DATA${RST}${YEL} on ${BLD}${DISK}${RST}${YEL}  ${DISK_DESC}${RST}"
say   "        and flash ${IMG_KIND} ${IMG_VERSION}, seeded as ${NODE_ID} (${NODE_ROLE})."
if [ "${RASPUTIN_DRY_RUN:-}" = "1" ]; then info "DRY RUN — stopping before any write. Disk=$DISK Image=$IMG_URL"; exit 0; fi
if [ "${RASPUTIN_ASSUME_YES:-}" != "1" ]; then
	short="$(basename "$DISK")"
	ans="$(ask "Type ${BLD}${short}${RST} to confirm (anything else aborts): ")"
	[ "$ans" = "$short" ] || die "aborted — '$ans' did not match '$short'. Nothing was written."
fi

# --- download + verify --------------------------------------------------------
# $IMG_SHA came out of the signed manifest above when the release has one, so
# this check chains the image to the publisher's root rather than to whatever
# the descriptor asserted. TMP and its trap are set up with that verification.
IMG="$TMP/rasputin-image.img"   # compression-agnostic name; decompressor picked below
info "Downloading $IMG_URL"
curl -fL --progress-bar -o "$IMG" "$IMG_URL" || die "image download failed."
info "Verifying checksum…"
got="$(sha256_of "$IMG")" || die "neither shasum nor sha256sum is available."
[ "$got" = "$IMG_SHA" ] || die "checksum MISMATCH — refusing to flash a corrupt download.\n  expected $IMG_SHA\n  got      $got"
info "Checksum OK."

# --- flash --------------------------------------------------------------------
# Pick the decompressor from the image's own filename — the OS image ships
# .img.xz, the firewall image ships .img.gz. Deriving it from the URL (rather
# than the role) means a future compression change needs no edit here.
case "$IMG_URL" in
	*.xz) DECOMP="xz" ;;
	*.gz) DECOMP="gzip" ;;
	*)    die "don't know how to decompress $IMG_URL (expected an .img.xz or .img.gz image)." ;;
esac
have "$DECOMP" || die "$DECOMP is required to decompress the image (macOS: 'brew install $DECOMP'; Linux: install it via your package manager)."
info "Flashing ${DISK} (this takes a few minutes; do not unplug)…"
if [ "$OS" = "Darwin" ]; then
	diskutil unmountDisk "$DISK" >/dev/null 2>&1 || true
	RDISK="/dev/r${DISK#/dev/}"   # raw device (e.g. /dev/disk4 -> /dev/rdisk4) is much faster on macOS
	"$DECOMP" -dc "$IMG" | dd of="$RDISK" bs=4m || die "write to $RDISK failed (see the error above — is the disk in use?)."
else
	for p in $(lsblk -lnpo NAME "$DISK" 2>/dev/null | tail -n +2); do umount "$p" 2>/dev/null || true; done
	if "$DECOMP" -dc "$IMG" | dd of="$DISK" bs=4M oflag=sync status=progress 2>/dev/null; then :; else
		"$DECOMP" -dc "$IMG" | dd of="$DISK" bs=4M 2>/dev/null || die "dd failed."
	fi
fi
sync
info "Image written. Settling partitions…"
if [ "$OS" = "Darwin" ]; then diskutil unmountDisk "$DISK" >/dev/null 2>&1 || true; else
	have partprobe && partprobe "$DISK" 2>/dev/null || true
	have udevadm && udevadm settle 2>/dev/null || true
	sleep 2
fi

# --- locate the seed FAT on the flashed disk — BY VOLUME LABEL, never by number
# The seed volume is the FAT labeled $SEED_LABEL (RASPUTIN-OS for an OS node,
# RASPUTIN-FW for a firewall). Its partition NUMBER differs by image (rpi: p1
# "selector"; n100: p2 — p1 is the hidden ESP; firewall: the basic-data FAT
# after the RASPUTINEFI ESP), and every image mounts the seed by label, so
# number-guessing strands the node: a seed written to the ESP verifies clean
# but firstboot only ever sees the real seed volume's baked blank template
# (bit the bootstrap.sh bench runs, 2026-07-14).
seed_part_for() { # <disk> -> partition device carrying the $SEED_LABEL FAT
	if [ "$OS" = "Darwin" ]; then
		local id vn
		for id in $(diskutil list "$1" 2>/dev/null | awk '{print $NF}' | grep "^${1#/dev/}s[0-9]*$"); do
			vn="$(diskutil info "/dev/$id" 2>/dev/null | awk -F': *' '/Volume Name/{print $2; exit}')"
			[ "$vn" = "$SEED_LABEL" ] && { printf '/dev/%s\n' "$id"; return 0; }
		done
		return 1
	else
		lsblk -lnpo NAME,LABEL "$1" 2>/dev/null | awk -v lbl="$SEED_LABEL" '$2==lbl{print $1; exit}' | grep . || return 1
	fi
}
PART=""
for attempt in 1 2 3 4 5; do
	PART="$(seed_part_for "$DISK" || true)"
	[ -n "$PART" ] && break
	sleep 1   # partition scan can lag the flash by a moment
done
[ -n "$PART" ] || die "no $SEED_LABEL volume found on $DISK after flashing — can't place the seed. (Unexpected image layout? Re-run, and if it persists check the control plane's release.)"
info "Seed volume: ${PART} (${SEED_LABEL})"

# --- write the seed onto the seed FAT, then READ IT BACK ----------------------
SEED_FILE="$TMP/rasputin-seed.env"; printf '%s' "$SEED" > "$SEED_FILE"
READBACK="$TMP/readback.env"
write_and_verify_seed() {
	if [ "$OS" = "Darwin" ]; then
		# macOS: ALWAYS write through the kernel FS (mount-dance), never mcopy
		# against the raw device. macOS auto-mounts the freshly-flashed FAT
		# asynchronously seconds after dd; a raw-device write that races that
		# mount verifies clean on read-back and is then UN-WRITTEN at eject,
		# when the kernel flushes its stale cached FAT metadata over it.
		# Writing via diskutil mount keeps every byte cache-coherent; the
		# UNMOUNT + FRESH-MOUNT read-back still defeats the write cache.
		local mp="$TMP/mnt"; mkdir -p "$mp"
		diskutil unmount "$PART" >/dev/null 2>&1 || true   # clear any automount first
		diskutil mount -mountPoint "$mp" "$PART" >/dev/null 2>&1 || return 1
		cp "$SEED_FILE" "$mp/rasputin-seed.env" || return 1; sync
		diskutil unmount "$mp" >/dev/null 2>&1 || return 1
		diskutil mount -mountPoint "$mp" "$PART" >/dev/null 2>&1 || return 1
		cp "$mp/rasputin-seed.env" "$READBACK" 2>/dev/null || true
		diskutil unmount "$mp" >/dev/null 2>&1 || true
	elif have mcopy; then
		# Linux + mtools: block-level write (no FS cache between us and the
		# medium). Headless Linux doesn't automount, so the macOS race above
		# doesn't apply; a desktop automounter would reintroduce it, so make
		# sure nothing has grabbed the partition first.
		umount "$PART" 2>/dev/null || true
		mcopy -o -i "$PART" "$SEED_FILE" ::rasputin-seed.env || return 1
		rm -f "$READBACK"
		mcopy -n -i "$PART" ::rasputin-seed.env "$READBACK" || return 1
	else
		# Linux without mtools: same mount-dance — write, sync, UNMOUNT, then
		# MOUNT FRESH to read back from the medium.
		local mp="$TMP/mnt"; mkdir -p "$mp"
		mount "$PART" "$mp" || return 1
		cp "$SEED_FILE" "$mp/rasputin-seed.env" || return 1; sync
		umount "$mp" || return 1
		mount "$PART" "$mp" || return 1
		cp "$mp/rasputin-seed.env" "$READBACK" 2>/dev/null || true
		umount "$mp" || true
	fi
	return 0
}
info "Writing enrollment seed to the boot partition…"
write_and_verify_seed || die "could not write the seed to $PART."
[ -s "$READBACK" ] && cmp -s "$SEED_FILE" "$READBACK" \
	|| die "seed read-back FAILED — the seed is not reliably on the disk. Re-run before seating the node (do NOT boot it as-is — it would come up un-enrolled)."
info "Seed verified on disk (read-back matches)."

# --- done ---------------------------------------------------------------------
if [ "$OS" = "Darwin" ]; then diskutil eject "$DISK" >/dev/null 2>&1 || true; else
	sync; have udisksctl && udisksctl power-off -b "$DISK" >/dev/null 2>&1 || true
fi
say ""
info "${GRN}${BLD}Done.${RST} Flashed ${IMG_KIND} ${IMG_VERSION} and seeded ${NODE_ID} (${NODE_ROLE})."
say   "      Seat the drive in the node, power it on — it'll appear as ${BLD}${NODE_ID}${RST} in the control plane within a minute."
