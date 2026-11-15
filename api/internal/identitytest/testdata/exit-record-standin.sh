#!/bin/sh
# exit-record-standin.sh: a MINIMAL STAND-IN for the identity service unit's
# ExecStopPost= exit-record hook, which rasputin-os ships (Identity 2.5,
# geekdojo/geekdojo-brain#973). It is NOT that hook, and it is never shipped:
# the real-systemd tests in this directory (TC-979-02, geekdojo/geekdojo-brain#979)
# use it so the records they read carry systemd's own values.
#
# It writes exactly the contract's record and `last` (the plan's "Contract for
# #973" §3) from the environment systemd gives ExecStopPost=:
#
#   <dir>/<INVOCATION_ID>  outcome=$SERVICE_RESULT, invocation_id,
#                          exit_code=$EXIT_CODE, exit_status=$EXIT_STATUS
#   <dir>/last             the invocation ID, written after the record
#
# Each is written to a .tmp file and renamed, so a reader never sees half of
# one. It does not implement the 256-record cap, which is the real hook's.
#
# Usage (as ExecStopPost=): exit-record-standin.sh <dir>
set -eu
dir="$1"
umask 077
mkdir -p "$dir"
id="$INVOCATION_ID"
printf 'outcome=%s\ninvocation_id=%s\nexit_code=%s\nexit_status=%s\n' \
	"${SERVICE_RESULT:-}" "$id" "${EXIT_CODE:-}" "${EXIT_STATUS:-}" >"$dir/$id.tmp"
mv "$dir/$id.tmp" "$dir/$id"
printf '%s\n' "$id" >"$dir/last.tmp"
mv "$dir/last.tmp" "$dir/last"
