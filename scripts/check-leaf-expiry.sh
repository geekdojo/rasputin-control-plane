#!/usr/bin/env bash
# check-leaf-expiry.sh — how long until a publisher signing leaf takes the fleet down.
#
# Verification happens at time.Now(), not at the signature's signingTime
# (artifactsig/verify.go, matching RAUC). So when a leaf expires, every artifact
# it ever signed stops being installable AT ONCE, on a date nothing announces —
# and the app catalog does something quieter and worse: catalogsync re-verifies
# its cached bundle on every boot, so each cluster silently reverts to the floor
# baked into its image.
#
# WHY IT READS PUBLISHED SIGNATURES RATHER THAN THE CI SECRET. The leaf is
# embedded in every detached CMS signature we publish, so this needs no secret
# and can run with a read-only token. The better reason is accuracy: it measures
# the leaf that ACTUALLY signs what people install. A secret rotated without a
# release cut would otherwise read as done while every artifact in the field was
# still signed by the old leaf — which is precisely the state this alarms on.
#
# Thresholds come from the decision in release-pipeline.md §9.2: old releases are
# NOT re-signed, so a new leaf must be signing production releases at least 90
# days before the old one expires, leaving a back catalogue a user can still
# install and roll back within. Alarming AT 90 would already be too late — the
# rotation itself has to fit before it.
#
#   WARN_DAYS   rotate now: room to mint, release, bench-validate, and still have
#               new-leaf artifacts in production by the 90-day floor.
#   CRIT_DAYS   the floor itself. Past here the rollback window is being eaten.
#
# Usage:  scripts/check-leaf-expiry.sh            # human-readable report
#         scripts/check-leaf-expiry.sh --json     # machine-readable, for CI
#         JSON_OUT=f.json scripts/check-leaf-expiry.sh    # both, from ONE run
#
# JSON_OUT exists so CI does not have to invoke this twice to get both forms.
# Two runs are two sets of downloads that can disagree if a release publishes
# between them — a small window, but the report and the numbers driving the
# alarm would then describe different states, which is the sort of thing nobody
# ever debugs because nobody believes it.
#
# Exit:   0 = every leaf outside WARN_DAYS · 1 = at least one inside · 2 = broken
set -euo pipefail

WARN_DAYS=${WARN_DAYS:-120}
CRIT_DAYS=${CRIT_DAYS:-90}
JSON=0
[[ ${1:-} == "--json" ]] && JSON=1
JSON_OUT=${JSON_OUT:-}

# repo | what the leaf signs | glob picking ONE detached signature from the newest release
TARGETS=(
  "geekdojo/rasputin-os|OS images (RAUC bundles)|manifest.json.sig"
  "geekdojo/rasputin-openwrt-firewall|firewall images|*.rootfs.sig"
  "geekdojo/rasputin-app-catalog|app-catalog bundles|catalog.json.sig"
)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

now_epoch=$(date -u +%s)
worst=999999
rows=()
failures=0

for entry in "${TARGETS[@]}"; do
    IFS='|' read -r repo what glob <<<"$entry"

    tag=$(gh release list --repo "$repo" --limit 1 --json tagName -q '.[0].tagName' 2>/dev/null || true)
    if [[ -z "$tag" ]]; then
        echo "::warning::no releases found in $repo — cannot check the leaf signing $what" >&2
        failures=$((failures + 1))
        continue
    fi

    d="$tmp/$(basename "$repo")"
    mkdir -p "$d"
    if ! gh release download "$tag" --repo "$repo" --pattern "$glob" --dir "$d" --clobber >/dev/null 2>&1; then
        echo "::warning::$repo $tag has no asset matching $glob — cannot read its signing leaf" >&2
        failures=$((failures + 1))
        continue
    fi
    sig=$(find "$d" -type f -name '*.sig' | head -1)

    # A CMS signature embeds leaf + intermediate. Pick the LEAF by ELIMINATING
    # the CAs, not by looking for CA:FALSE — our leaves carry no basicConstraints
    # extension at all (pki-init.sh sets only keyUsage + extendedKeyUsage), so
    # CA:FALSE never appears and testing for it finds nothing. Matching on the
    # subject string would be worse still: it breaks the first time a leaf is
    # renamed, which is exactly what a rotation does.
    #
    # Split with awk, not csplit: BSD csplit has no -z and no -b, so the obvious
    # csplit one-liner works on the Linux runner and fails on a Mac. Reaching for
    # a portable primitive beats discovering the difference from a red build.
    certs="$d/certs.pem"
    openssl pkcs7 -inform DER -in "$sig" -print_certs -out "$certs" 2>/dev/null
    leaf=""
    awk -v dir="$d" '
        /-----BEGIN CERTIFICATE-----/ { n++ }
        n { print > sprintf("%s/c%02d.pem", dir, n) }
    ' "$certs"
    for c in "$d"/c*.pem; do
        [[ -f $c ]] || continue
        if ! openssl x509 -in "$c" -noout -text 2>/dev/null | grep -q "CA:TRUE"; then
            leaf="$c"; break
        fi
    done
    if [[ -z "$leaf" ]]; then
        echo "::warning::no end-entity certificate found in $repo $tag's signature" >&2
        failures=$((failures + 1))
        continue
    fi

    subject=$(openssl x509 -in "$leaf" -noout -subject | sed 's/^subject= *//')
    not_after=$(openssl x509 -in "$leaf" -noout -enddate | cut -d= -f2)
    # GNU and BSD date disagree on everything except -u; try both.
    exp_epoch=$(date -u -d "$not_after" +%s 2>/dev/null \
        || date -u -j -f "%b %d %T %Y %Z" "$not_after" +%s 2>/dev/null)
    days=$(( (exp_epoch - now_epoch) / 86400 ))
    [[ $days -lt $worst ]] && worst=$days

    status=ok
    [[ $days -le $WARN_DAYS ]] && status=warn
    [[ $days -le $CRIT_DAYS ]] && status=critical
    rows+=("$repo|$what|$subject|$not_after|$days|$status|$tag")
done

if [[ $failures -gt 0 && ${#rows[@]} -eq 0 ]]; then
    echo "error: could not read a signing leaf from any target — refusing to report 'all clear'" >&2
    exit 2
fi

emit_json() {
    printf '{"warnDays":%d,"critDays":%d,"soonestDays":%d,"leaves":[' "$WARN_DAYS" "$CRIT_DAYS" "$worst"
    local sep=""
    for r in "${rows[@]}"; do
        IFS='|' read -r repo what subject not_after days status tag <<<"$r"
        printf '%s{"repo":"%s","signs":"%s","subject":"%s","notAfter":"%s","daysLeft":%d,"status":"%s","fromRelease":"%s"}' \
            "$sep" "$repo" "$what" "$subject" "$not_after" "$days" "$status" "$tag"
        sep=","
    done
    printf ']}\n'
}

[[ -n $JSON_OUT ]] && emit_json > "$JSON_OUT"

if [[ $JSON -eq 1 ]]; then
    emit_json
else
    printf '%-34s %-28s %-22s %6s  %s\n' REPO SIGNS EXPIRES DAYS STATUS
    for r in "${rows[@]}"; do
        IFS='|' read -r repo what subject not_after days status tag <<<"$r"
        printf '%-34s %-28s %-22s %6d  %s\n' "$repo" "$what" "$not_after" "$days" "$status"
    done
    echo
    echo "soonest expiry: $worst days (warn at $WARN_DAYS, critical at $CRIT_DAYS)"
fi

[[ $worst -le $WARN_DAYS ]] && exit 1
exit 0
