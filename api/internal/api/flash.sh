#!/usr/bin/env bash
#
# rasputin flash.sh — one-command node flasher.
#
# Served by the control plane at GET /flash.sh. The Add-node wizard hands the
# operator a single line to paste on their laptop:
#
#   curl -fsSL https://rasputin.local/flash.sh | sudo RASPUTIN_SEED_B64='…' bash
#
# It downloads the OS image that matches the cluster, verifies its checksum,
# flashes a plugged-in SSD/USB, writes the node's enrollment seed onto the boot
# partition, and — critically — READS THE SEED BACK at the block level and fails
# loudly if it didn't land. A silent seed write that never reached the medium is
# exactly what stranded the first bench add-node (2026-06-22); the read-back is
# the point of this script, not a nicety.
#
# Secret handling: the only secret is the seed (it carries the one-time, node-
# bound join token). It is passed in via RASPUTIN_SEED_B64 (base64) and never
# placed in a URL or fetched from the server — this script itself contains no
# secrets. Image version/URL/sha are non-secret and fetched from the control
# plane's /api/cluster/node-image.
#
# Cross-platform: macOS (diskutil + mtools/diskutil) and Linux (lsblk + mtools/
# mount). Safe by construction: only external/removable disks are offered, the
# disk backing the laptop's own root filesystem is never a candidate, and a
# typed confirmation is required before anything is written.
#
# Env knobs:
#   RASPUTIN_SEED_B64    (required) base64 of the rasputin-seed.env contents
#   RASPUTIN_ARCH        target CPU arch: amd64 (default) or arm64. Selects which
#                        per-arch OS image the control plane hands back (amd64 =
#                        N100/Intel, arm64 = CM5/Raspberry Pi). The Add-node
#                        wizard sets this from the architecture you pick.
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

# --- fetch the image descriptor the cluster expects --------------------------
# Target arch (amd64 default). The control plane resolves it to the matching
# per-arch image (amd64 = N100/Intel, arm64 = CM5/Raspberry Pi).
ARCH="${RASPUTIN_ARCH:-amd64}"
case "$ARCH" in amd64|arm64) ;; *) die "RASPUTIN_ARCH must be amd64 or arm64 (got '$ARCH')." ;; esac
have curl || die "curl is required."
info "Asking ${CP_URL} which ${ARCH} image this cluster runs…"
DESC="$(curl -fsSL --max-time 20 "$CP_URL/api/cluster/node-image?arch=$ARCH" 2>/dev/null || true)"
[ -n "$DESC" ] || die "couldn't get the $ARCH image from the control plane at $CP_URL — either this laptop isn't on the cluster's network (override with RASPUTIN_CP_URL=…), or this cluster's release has no $ARCH image yet."
json_val() { printf '%s' "$DESC" | sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" | head -1; }
IMG_VERSION="$(json_val version)"
IMG_URL="$(json_val url)"
IMG_SHA="$(json_val sha256)"
[ -n "$IMG_URL" ] && [ -n "$IMG_SHA" ] || die "the control plane didn't return a usable image descriptor (got: $DESC)"

info "Node ${BLD}${NODE_ID}${RST} (${NODE_ROLE}) → Rasputin OS ${BLD}${IMG_VERSION}${RST} (${ARCH})"

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
say   "        and flash Rasputin OS ${IMG_VERSION}, seeded as ${NODE_ID} (${NODE_ROLE})."
if [ "${RASPUTIN_DRY_RUN:-}" = "1" ]; then info "DRY RUN — stopping before any write. Disk=$DISK Image=$IMG_URL"; exit 0; fi
if [ "${RASPUTIN_ASSUME_YES:-}" != "1" ]; then
	short="$(basename "$DISK")"
	ans="$(ask "Type ${BLD}${short}${RST} to confirm (anything else aborts): ")"
	[ "$ans" = "$short" ] || die "aborted — '$ans' did not match '$short'. Nothing was written."
fi

# --- download + verify --------------------------------------------------------
TMP="$(mktemp -d "${TMPDIR:-/tmp}/rasputin-flash.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
IMG="$TMP/node.img.xz"
info "Downloading $IMG_URL"
curl -fL --progress-bar -o "$IMG" "$IMG_URL" || die "image download failed."
info "Verifying checksum…"
if have shasum; then got="$(shasum -a 256 "$IMG" | awk '{print $1}')"; else got="$(sha256sum "$IMG" | awk '{print $1}')"; fi
[ "$got" = "$IMG_SHA" ] || die "checksum MISMATCH — refusing to flash a corrupt download.\n  expected $IMG_SHA\n  got      $got"
info "Checksum OK."

# --- flash --------------------------------------------------------------------
have xz || die "xz is required to decompress the image (macOS: 'brew install xz'; Linux: install xz-utils)."
info "Flashing ${DISK} (this takes a few minutes; do not unplug)…"
if [ "$OS" = "Darwin" ]; then
	diskutil unmountDisk "$DISK" >/dev/null 2>&1 || true
	RDISK="/dev/r${DISK#/dev/}"   # raw device (e.g. /dev/disk4 -> /dev/rdisk4) is much faster on macOS
	xz -dc "$IMG" | dd of="$RDISK" bs=4m || die "write to $RDISK failed (see the error above — is the disk in use?)."
else
	for p in $(lsblk -lnpo NAME "$DISK" 2>/dev/null | tail -n +2); do umount "$p" 2>/dev/null || true; done
	if xz -dc "$IMG" | dd of="$DISK" bs=4M oflag=sync status=progress 2>/dev/null; then :; else
		xz -dc "$IMG" | dd of="$DISK" bs=4M 2>/dev/null || die "dd failed."
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
# The seed volume is the FAT labeled RASPUTIN-OS. Its partition NUMBER differs
# by board (rpi: p1 "selector"; n100: p2 — p1 is the hidden ESP), and the OS
# mounts it by label, so number-guessing strands the node: a seed written to
# the ESP verifies clean but firstboot only ever sees the real seed volume's
# baked blank template (bit the bootstrap.sh bench runs, 2026-07-14).
seed_part_for() { # <disk> -> partition device carrying the RASPUTIN-OS FAT
	if [ "$OS" = "Darwin" ]; then
		local id vn
		for id in $(diskutil list "$1" 2>/dev/null | awk '{print $NF}' | grep "^${1#/dev/}s[0-9]*$"); do
			vn="$(diskutil info "/dev/$id" 2>/dev/null | awk -F': *' '/Volume Name/{print $2; exit}')"
			[ "$vn" = "RASPUTIN-OS" ] && { printf '/dev/%s\n' "$id"; return 0; }
		done
		return 1
	else
		lsblk -lnpo NAME,LABEL "$1" 2>/dev/null | awk '$2=="RASPUTIN-OS"{print $1; exit}' | grep . || return 1
	fi
}
PART=""
for attempt in 1 2 3 4 5; do
	PART="$(seed_part_for "$DISK" || true)"
	[ -n "$PART" ] && break
	sleep 1   # partition scan can lag the flash by a moment
done
[ -n "$PART" ] || die "no RASPUTIN-OS volume found on $DISK after flashing — can't place the seed. (Unexpected image layout? Re-run, and if it persists check the control plane's release.)"
info "Seed volume: ${PART} (RASPUTIN-OS)"

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
info "${GRN}${BLD}Done.${RST} Flashed Rasputin OS ${IMG_VERSION} and seeded ${NODE_ID} (${NODE_ROLE})."
say   "      Seat the SSD in the node, power it on — it'll appear as ${BLD}${NODE_ID}${RST} in the control plane within a minute."
