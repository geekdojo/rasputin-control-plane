#!/usr/bin/env bash
#
# test-auth-register.sh — tests for scripts/auth-register.sh.
#
# Run:  ./scripts/test-auth-register.sh
#
# A gate nobody has fed a bad input to is a gate nobody knows the shape of. So
# every case below is a register this gate MUST refuse, plus the two it must
# not: the real register, and a revisit trigger that merely reads like a date
# because it names an upstream version.
#
# The last case is the one that matters most. It writes a real Go declaration
# into the tree, anchors a row to it, watches the gate pass, edits that
# declaration, and watches the gate fail — which is the whole contract of the
# register. A fingerprint that did not move when the code moved would leave
# every row reading as review long after the code stopped matching it.
#
# No network. python3 only, same as the gate.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
GATE="${GATE:-$here/auth-register.sh}"

tmp="$(mktemp -d)"
# A directory inside the repo, because anchors are repo-relative paths and the
# gate resolves them from the repo root. Removed on exit, including on failure.
intree="$root/.auth-register-test-tmp"
trap 'rm -rf -- "$tmp" "$intree"' EXIT
mkdir -p "$intree"

HEADER=$'fingerprint\tid\tkind\tcell\tmethod\texception\tconstraint\tstatus\trevisit\tanchor\tcite\tline'

# row FP ID KIND CELL METHOD EXCEPTION CONSTRAINT STATUS REVISIT ANCHOR CITE
row() {
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n' \
		"$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}" "${11}"
}

# A row that is valid in every respect, so each case below differs from a
# passing register in exactly one way.
good_exception() {
	row "" E99 exception "a cell" "the canonical method" "the second method" \
		"the constraint that forces it" true-now \
		"the fact that retires this row" \
		"go:artifactsig/verify.go#VerifyForPurpose" ""
}

# write_register FILE < rows
write_register() {
	{
		printf '%s\n' "$HEADER"
		cat
	} >"$1"
}

# refresh FILE — fill in fingerprints the way a person would before committing.
refresh() { AUTH_REGISTER="$1" "$GATE" --refresh >/dev/null || true; }

failures=0

# check NAME WANT_STATUS WANT_OUTPUT FILE
check() {
	local name="$1" want_status="$2" want_output="$3" file="$4"
	local status=0 output
	output="$(AUTH_REGISTER="$file" "$GATE" --gate 2>&1)" || status=$?
	if [ "$status" != "$want_status" ]; then
		printf 'FAIL %s: exit %s, want %s\n%s\n' "$name" "$status" "$want_status" "$output"
		failures=$((failures + 1))
	elif [ -n "$want_output" ] && ! grep -qF -- "$want_output" <<<"$output"; then
		printf 'FAIL %s: output lacks %q\n%s\n' "$name" "$want_output" "$output"
		failures=$((failures + 1))
	else
		printf 'ok   %s\n' "$name"
	fi
}

# ── the register we actually ship ───────────────────────────────────────────

check "the committed register passes its own gate" 0 "cells" "$root/.github/auth-register.tsv"

# A committed register whose fingerprints were never filled in is the failure
# mode of committing --refresh output without running it, so prove the gate
# catches it rather than trusting the file on disk.
{
	AUTH_REGISTER="$root/.github/auth-register.tsv" "$GATE" --report >"$tmp/posture.txt" 2>&1
} || true
if ! grep -q "canonical" "$tmp/posture.txt"; then
	printf 'FAIL the committed register prints no posture line\n'
	failures=$((failures + 1))
else
	printf 'ok   the committed register prints a posture line\n'
fi

# ── a baseline that must pass, so every refusal below is attributable ───────

good_exception | write_register "$tmp/good.tsv"
refresh "$tmp/good.tsv"
check "a well-formed exception row passes" 0 "exception 1" "$tmp/good.tsv"

# ── a date is never a revisit trigger ───────────────────────────────────────

for trigger in "revisit on 2027-01-01" "revisit in 6 months" "re-check in March 2027" \
	"revisit next Q3" "reviewed quarterly" "settle this by 2028"; do
	row "" E99 exception "a cell" "the canonical method" "the second method" \
		"the constraint that forces it" true-now "$trigger" \
		"go:artifactsig/verify.go#VerifyForPurpose" "" | write_register "$tmp/date.tsv"
	refresh "$tmp/date.tsv"
	check "a revisit trigger of '$trigger' is refused" 1 "A date is never a trigger" "$tmp/date.tsv"
done

# The detector must not fire on a version pin. A pinned upstream version is
# exactly the kind of checkable fact this column is for, so a detector that
# rejected one would push people to write worse triggers to get past it.
for trigger in "the OS ships Buildroot 2026.08" "the image ships OpenWrt 25.12.5" \
	"the pinned collector reaches v1.4.2"; do
	row "" E99 exception "a cell" "the canonical method" "the second method" \
		"the constraint that forces it" true-now "$trigger" \
		"go:artifactsig/verify.go#VerifyForPurpose" "" | write_register "$tmp/ver.tsv"
	refresh "$tmp/ver.tsv"
	check "a version pin in '$trigger' is not mistaken for a date" 0 "" "$tmp/ver.tsv"
done

# ── anchors ─────────────────────────────────────────────────────────────────

row "" E99 exception "a cell" "m" "e" "c" true-now "a fact" \
	"go:artifactsig/verify.go#ThisSymbolDoesNotExist" "" | write_register "$tmp/nosym.tsv"
check "an anchor naming a symbol that does not exist is refused" 1 \
	"no Go declaration of" "$tmp/nosym.tsv"

row "" E99 exception "a cell" "m" "e" "c" true-now "a fact" \
	"go:artifactsig/does-not-exist.go#Verify" "" | write_register "$tmp/nofile.tsv"
check "an anchor naming a file that does not exist is refused" 1 \
	"does not exist" "$tmp/nofile.tsv"

printf 'package x\n\nfunc A() {}\nfunc A2() {}\n' >"$intree/dup.go"
row "" E99 exception "a cell" "m" "e" "c" true-now "a fact" \
	"text:.auth-register-test-tmp/dup.go#func A" "" | write_register "$tmp/dup.tsv"
check "a text anchor that matches more than once is refused" 1 \
	"an anchor must be unique" "$tmp/dup.tsv"

row "" E99 exception "a cell" "m" "e" "c" true-now "a fact" \
	"go:artifactsig/verify.go" "" | write_register "$tmp/noform.tsv"
check "an anchor with no '#target' is refused" 1 "has no '#<target>' part" "$tmp/noform.tsv"

# A method anchor (Type.Method) must resolve — the register leans on them.
row "" E99 exception "a cell" "m" "e" "c" true-now "a fact" \
	"go:api/internal/auth/store.go#Store.FirstRun" "" | write_register "$tmp/meth.tsv"
refresh "$tmp/meth.tsv"
check "a Type.Method anchor resolves" 0 "" "$tmp/meth.tsv"

# ── drift: the contract the whole register rests on ─────────────────────────

cat >"$intree/subject.go" <<'GO'
package subject

// Gate is the declaration a register row anchors to in this test.
func Gate(mode string) bool { return mode == "enforce" }
GO
row "" E99 exception "a cell" "m" "e" "c" true-now "a fact" \
	"go:.auth-register-test-tmp/subject.go#Gate" "" | write_register "$tmp/drift.tsv"
refresh "$tmp/drift.tsv"
check "a row anchored to unchanged code passes" 0 "" "$tmp/drift.tsv"

# Reindenting and rewording the comment beside it must NOT churn the row: a
# register that fails on cosmetic edits is one people stop refreshing.
cat >"$intree/subject.go" <<'GO'
package subject

// Gate is the declaration a register row anchors to. Reworded deliberately.
func    Gate(mode string) bool { return mode == "enforce" }
GO
check "reindenting and rewording a comment does not move the fingerprint" 0 "" "$tmp/drift.tsv"

# Changing what the declaration SAYS must fail, and must say why.
cat >"$intree/subject.go" <<'GO'
package subject

// Gate is the declaration a register row anchors to in this test.
func Gate(mode string, allowPlaintext bool) bool { return allowPlaintext }
GO
check "editing the anchored declaration fails the gate" 1 \
	"whose anchored code has changed" "$tmp/drift.tsv"

# And a refresh is what clears it — after a human has re-read the row.
refresh "$tmp/drift.tsv"
check "a refresh clears the drift once the row has been re-read" 0 "" "$tmp/drift.tsv"

# A hand-edited fingerprint is the same failure, reached a different way.
good_exception | write_register "$tmp/badfp.tsv"
refresh "$tmp/badfp.tsv"
sed -i.bak 's/^[0-9a-f]\{16\}/0000000000000000/' "$tmp/badfp.tsv"
check "a fingerprint that does not match the anchored code is refused" 1 \
	"whose anchored code has changed" "$tmp/badfp.tsv"

# ── evidence must be reachable ──────────────────────────────────────────────

row "" E99 exception "a cell" "m" "e" "c" decision "a fact" \
	"go:artifactsig/verify.go#VerifyForPurpose" "" | write_register "$tmp/nocite.tsv"
refresh "$tmp/nocite.tsv"
check "a recorded decision with no cite is refused" 1 \
	"decision nobody can look up" "$tmp/nocite.tsv"

row "" E99 exception "a cell" "m" "e" "c" unverified "a fact" \
	"go:artifactsig/verify.go#VerifyForPurpose" "" | write_register "$tmp/unver.tsv"
refresh "$tmp/unver.tsv"
check "an unverified premise with no scheduled probe is refused" 1 \
	"File the probe and cite it here" "$tmp/unver.tsv"

row "" E99 exception "a cell" "m" "e" "c" unverified "a fact" \
	"go:artifactsig/verify.go#VerifyForPurpose" "geekdojo/geekdojo-brain#1" \
	| write_register "$tmp/unver2.tsv"
refresh "$tmp/unver2.tsv"
check "an unverified premise with a scheduled probe passes and is reported" 0 \
	"rest on a premise nobody has checked" "$tmp/unver2.tsv"

row "" E99 exception "a cell" "m" "e" "c" true-now "a fact" "none:" "" \
	| write_register "$tmp/noanchor.tsv"
refresh "$tmp/noanchor.tsv"
check "an unanchored row with no cite is refused" 1 \
	"must at least say where its evidence is" "$tmp/noanchor.tsv"

# ── shape ───────────────────────────────────────────────────────────────────

row "" E99 exception "a cell" "m" "e" "" true-now "a fact" \
	"go:artifactsig/verify.go#VerifyForPurpose" "" | write_register "$tmp/nocon.tsv"
refresh "$tmp/nocon.tsv"
check "an exception row with no constraint is refused" 1 \
	"names the constraint that forces it" "$tmp/nocon.tsv"

row "" E99 exception "a cell" "m" "e" "c" true-now "" \
	"go:artifactsig/verify.go#VerifyForPurpose" "" | write_register "$tmp/norev.tsv"
refresh "$tmp/norev.tsv"
check "an exception row with no revisit fact is refused" 1 \
	"the fact that retires it" "$tmp/norev.tsv"

row "" C99 canonical "a cell" "m" "a second method" "" true-now "" \
	"go:artifactsig/verify.go#VerifyForPurpose" "" | write_register "$tmp/canexc.tsv"
refresh "$tmp/canexc.tsv"
check "a canonical row carrying an exception is refused" 1 \
	"a canonical row carries no" "$tmp/canexc.tsv"

{
	good_exception
	good_exception
} | write_register "$tmp/dupid.tsv"
refresh "$tmp/dupid.tsv"
check "a duplicate id is refused" 1 "duplicate id" "$tmp/dupid.tsv"

row "" E99 exception "a cell" "m" "e" "c" probably-fine "a fact" \
	"go:artifactsig/verify.go#VerifyForPurpose" "" | write_register "$tmp/badstatus.tsv"
check "an unknown status is refused" 1 "unknown status" "$tmp/badstatus.tsv"

row "" E99 wishlist "a cell" "m" "e" "c" true-now "a fact" \
	"go:artifactsig/verify.go#VerifyForPurpose" "" | write_register "$tmp/badkind.tsv"
check "an unknown kind is refused" 1 "unknown kind" "$tmp/badkind.tsv"

{
	printf '%s\n' "$HEADER"
	printf 'abc\tE99\texception\ta cell\n'
} >"$tmp/short.tsv"
check "a row with the wrong number of fields is refused" 2 "expected 12" "$tmp/short.tsv"

{
	printf 'id\tkind\n'
	good_exception
} >"$tmp/badheader.tsv"
check "a register with no header row is refused" 2 "no header row" "$tmp/badheader.tsv"

# A header with the right shape but the wrong column names: the row bodies would
# parse, and every field would land in the wrong column.
{
	printf '%s\n' "${HEADER/cell/scope}"
	good_exception
} >"$tmp/renamedheader.tsv"
check "a header with a renamed column is refused" 2 "header is" "$tmp/renamedheader.tsv"

printf '%s\n' "$HEADER" >"$tmp/empty.tsv"
check "an empty register still prints a posture line" 0 "0 rows" "$tmp/empty.tsv"

# ── result ──────────────────────────────────────────────────────────────────

if [ "$failures" -ne 0 ]; then
	printf '\nauth-register: %d check(s) failed\n' "$failures"
	exit 1
fi
printf '\nauth-register: all checks passed\n'
