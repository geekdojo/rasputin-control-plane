package bmc

import (
	"strings"
	"testing"
)

// What comes back after a power verb is never a reason to fail: the BMC
// returns nothing there, and nobody has captured what else the rack might
// send. The one thing worth pointing out in the journal is a line shaped like
// a command echo that names another bus address.
func TestBitScopeReplyNote(t *testing.T) {
	target := bitscopeTarget{nodeID: "n", pos: "A-1", addr: 0x01}
	for _, tc := range []struct {
		name, reply string
		wantNote    string
	}{
		{"silence, the normal reply", "", ""},
		{"whitespace only", "\r\n ", ""},
		{"its own echo", "01|/", ""},
		{"its own echo, bracketed", "[01]|/", ""},
		{"bytes with no echo line", "ok", ""},
		{"an echo whose address does not parse", "zz|/", ""},
		{"another address", "02|/", "names bus address 02"},
		{"another address after its own", "01|/\n17|/", "names bus address 17"},
	} {
		got := bitscopeReplyNote(target, tc.reply)
		if tc.wantNote == "" && got != "" {
			t.Errorf("%s: reply %q: note = %q, want none", tc.name, tc.reply, got)
		}
		if tc.wantNote != "" && !strings.Contains(got, tc.wantNote) {
			t.Errorf("%s: reply %q: note = %q, want it to contain %q", tc.name, tc.reply, got, tc.wantNote)
		}
	}
}
