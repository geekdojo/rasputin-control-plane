package console

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// A stand-in for the firewall image's /usr/lib/rasputin/set-root-hash
// (geekdojo/rasputin-openwrt-firewall#64), reduced to the parts of its
// contract the agent depends on: the hash arrives on stdin, RASPUTIN_SHADOW_FILE
// names the file, only root's second field is rewritten, a plaintext is
// refused, and nothing echoes the value. The agent must drive THIS, not its
// own writer, wherever an image ships one.
const fakeHelper = `#!/bin/sh
set -eu
SHADOW="${RASPUTIN_SHADOW_FILE:-/etc/shadow}"
if [ "$#" -ge 1 ]; then HASH="$1"; else HASH="$(cat)"; fi
[ -n "$HASH" ] || { echo "set-root-hash: ERROR: no hash given" >&2; exit 1; }
case "$HASH" in
  *:*)            echo "set-root-hash: ERROR: hash contains ':'" >&2; exit 1 ;;
  '*'|'!')        : ;;
  '$'?*'$'*)      : ;;
  *)              echo "set-root-hash: ERROR: value is not a crypt hash" >&2; exit 1 ;;
esac
tmp="$SHADOW.t$$"
awk -v h="$HASH" -F: 'BEGIN{OFS=":"} $1=="root"{$2=h} {print}' "$SHADOW" > "$tmp"
chmod 600 "$tmp"
mv -f "$tmp" "$SHADOW"
echo "HELPER RAN" >> "$SHADOW.log"
exit 0
`

func writeHelper(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "set-root-hash")
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func helperRan(path string) bool {
	_, err := os.Stat(path + ".log")
	return err == nil
}

// The image's helper is what writes, when the image ships one.
func TestApplyPrefersTheImageHelper(t *testing.T) {
	shadow := writeShadow(t, "root::0:0:99999:7:::\ndaemon:*:0:0:99999:7:::\n")
	helper := writeHelper(t, fakeHelper, 0o755)

	changed, via, err := apply(context.Background(), shadow, helper, testHash)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("changed=false on a node that held no password")
	}
	if !strings.Contains(string(via), "set-root-hash") {
		t.Fatalf("via = %q, want the image helper", via)
	}
	if !helperRan(shadow) {
		t.Fatal("the agent wrote the file itself instead of calling the image's helper")
	}
	if got := rootLine(t, shadow)[1]; got != testHash {
		t.Fatalf("root password field is %q", got)
	}
	raw, _ := os.ReadFile(shadow)
	if !strings.Contains(string(raw), "daemon:*:0:0:99999:7:::") {
		t.Errorf("another account's entry changed:\n%s", raw)
	}
}

// A converged node is a no-op, and the helper is not even called: a re-run
// of the push job must not rewrite a shadow file it has nothing to say
// about. The helper has no "already?" answer, so the agent makes that call.
func TestApplyIsANoOpWhenTheNodeAlreadyHoldsIt(t *testing.T) {
	shadow := writeShadow(t, "root:"+testHash+":19000:0:99999:7:::\n")
	helper := writeHelper(t, fakeHelper, 0o755)

	changed, _, err := apply(context.Background(), shadow, helper, testHash)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("changed=true for a node that already held this hash")
	}
	if helperRan(shadow) {
		t.Fatal("the helper was called for an unchanged hash")
	}
}

// An image that has not shipped the helper yet is tolerated, not failed —
// the case rasputin-openwrt-firewall#64 hands to this story. The agent's own
// writer produces the same file.
func TestApplyFallsBackWhenTheImageShipsNoHelper(t *testing.T) {
	for name, helper := range map[string]string{
		"absent":         filepath.Join(t.TempDir(), "not-here"),
		"not executable": writeHelper(t, fakeHelper, 0o644),
		"a directory":    t.TempDir(),
	} {
		t.Run(name, func(t *testing.T) {
			shadow := writeShadow(t, "root::0:0:99999:7:::\n")
			changed, via, err := apply(context.Background(), shadow, helper, testHash)
			if err != nil {
				t.Fatal(err)
			}
			if !changed {
				t.Fatal("changed=false")
			}
			if !strings.Contains(string(via), "agent's own") {
				t.Fatalf("via = %q, want the agent's own writer", via)
			}
			if got := rootLine(t, shadow)[1]; got != testHash {
				t.Fatalf("root password field is %q", got)
			}
		})
	}
}

// A helper that refuses fails the node, with its own words — it is not
// second-guessed by falling back to the agent's writer. The image refused
// for a reason the agent does not know.
func TestApplyFailsWhenTheHelperRefuses(t *testing.T) {
	const refusing = "#!/bin/sh\necho 'set-root-hash: ERROR: /etc is read-only' >&2\nexit 1\n"
	shadow := writeShadow(t, "root::0:0:99999:7:::\n")
	helper := writeHelper(t, refusing, 0o755)

	_, _, err := apply(context.Background(), shadow, helper, testHash)
	if err == nil {
		t.Fatal("a refusing helper was treated as success")
	}
	if !strings.Contains(err.Error(), "read-only") {
		t.Errorf("the helper's reason was lost: %v", err)
	}
	if got := rootLine(t, shadow)[1]; got != "" {
		t.Fatalf("the agent wrote the file after the helper refused: %q", got)
	}
}

// The hash goes to the helper on STDIN, never on argv: an argument is
// readable in /proc/<pid>/cmdline by every process on the box while the
// helper runs, and the hash is secret material.
func TestApplyPassesTheHashOnStdinNotArgv(t *testing.T) {
	const recorder = `#!/bin/sh
set -eu
SHADOW="${RASPUTIN_SHADOW_FILE:-/etc/shadow}"
printf 'argc=%s\n' "$#" > "$SHADOW.args"
for a in "$@"; do printf 'arg=%s\n' "$a" >> "$SHADOW.args"; done
HASH="$(cat)"
awk -v h="$HASH" -F: 'BEGIN{OFS=":"} $1=="root"{$2=h} {print}' "$SHADOW" > "$SHADOW.t"
mv -f "$SHADOW.t" "$SHADOW"
exit 0
`
	shadow := writeShadow(t, "root::0:0:99999:7:::\n")
	helper := writeHelper(t, recorder, 0o755)
	if _, _, err := apply(context.Background(), shadow, helper, testHash); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(shadow + ".args")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "argc=0") {
		t.Fatalf("the helper was given arguments: %s", args)
	}
	if strings.Contains(string(args), "$6$") {
		t.Fatalf("the hash reached argv: %s", args)
	}
	if got := rootLine(t, shadow)[1]; got != testHash {
		t.Fatalf("the helper did not receive the hash on stdin: %q", got)
	}
}

// The agent refuses a value that is not a crypt hash before anything is
// exec'd — a plaintext must never reach a helper's stdin, whatever that
// helper would have done with it.
func TestHandlerRefusesBeforeCallingTheHelper(t *testing.T) {
	shadow := writeShadow(t, "root::0:0:99999:7:::\n")
	helper := writeHelper(t, fakeHelper, 0o755)
	h := NewHandler("n1", shadow, helper)

	ack := h.apply(proto.ConsoleRootHashCmd{Hash: "hunter2-in-the-clear"})
	if ack.OK {
		t.Fatal("a plaintext was accepted")
	}
	if helperRan(shadow) {
		t.Fatal("a plaintext was handed to the image's helper")
	}
	if !strings.Contains(ack.Detail, "refusing") {
		t.Errorf("detail = %q", ack.Detail)
	}
	if strings.Contains(ack.Detail, "hunter2") {
		t.Errorf("the ack echoed the value: %q", ack.Detail)
	}
}

// The ack says which path applied it, so a bench run can tell an image that
// owns the write from one that is still leaning on the agent.
func TestHandlerAckNamesTheApplyPath(t *testing.T) {
	shadow := writeShadow(t, "root::0:0:99999:7:::\n")
	helper := writeHelper(t, fakeHelper, 0o755)
	h := NewHandler("n1", shadow, helper)

	ack := h.apply(proto.ConsoleRootHashCmd{Hash: testHash, HashID: proto.ConsoleRootHashID(testHash)})
	if !ack.OK || !ack.Changed {
		t.Fatalf("ack = %+v", ack)
	}
	if !strings.Contains(ack.Detail, "set-root-hash") {
		t.Errorf("detail = %q, want it to name the helper", ack.Detail)
	}
	// And a second delivery is the converged no-op.
	ack = h.apply(proto.ConsoleRootHashCmd{Hash: testHash, HashID: proto.ConsoleRootHashID(testHash)})
	if !ack.OK || ack.Changed {
		t.Fatalf("second delivery: %+v", ack)
	}
}
