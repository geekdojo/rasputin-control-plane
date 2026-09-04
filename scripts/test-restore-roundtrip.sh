#!/usr/bin/env bash
# test-restore-roundtrip.sh — the backup → wipe → restore round-trip, run on
# demand. design/storage.md §4.4: "No tile ships classified `critical` until
# a restore round-trip has been demonstrated. A backup nobody has restored is
# not a backup." Issue geekdojo/geekdojo-brain#300 is that gate; #291 is the
# restore it exercises.
#
# What runs (api/internal/storage/restore_roundtrip_test.go):
#
#   1. a real backup.run — the real saga, a real SQLite database holding real
#      users, passkey credentials and bus tokens, the real assembler and the
#      real seal — lands a generation on a temp target through fake agents;
#   2. a FRESH data dir stands in for a re-flashed controlplane;
#   3. the recovery-code wrapping is opened in Go from a fixture the browser
#      code produced (testdata/recovery-code-vector.json) — the cross-language
#      custody path, executed rather than assumed;
#   4. PrepareRestore + ApplyPendingRestore put the identity set into the
#      fresh dir before any store opens;
#   5. the restored rasputin.db opens, matches the manifest's digest, and
#      matches the pre-wipe database row for row on users, credentials and
#      bus tokens; a pre-wipe bus token still validates; the mesh CA and the
#      Headscale state are byte-identical.
#
#   6. the app-data half (#291 phase 2): the same run captured an app's
#      `critical` volume for real (a real tar, sealed on its node, uploaded
#      through the real transport); the live volume is CORRUPTED; the app's
#      data is restored from the generation with the recovered key through
#      the real backup.restore_app saga, the real restore-stream endpoint
#      (the api unseals) and the real fsat unpack; the bytes match, the app
#      was stopped and restarted around the swap, the record names the
#      volume, and neither the key nor the credential reached a log line,
#      ledger row or report.
#
# Runs anywhere `go test` runs — no bench, no hardware, no root. CI runs it
# with the rest of ./api/...; this script is for running it alone, verbosely,
# after touching anything on the backup or restore path.

set -euo pipefail
cd "$(dirname "$0")/.."

export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.4}"
exec go test -count=1 -race -v -run 'TestRestoreRoundTrip' ./api/internal/storage/ "$@"
