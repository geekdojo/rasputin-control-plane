package bmc

import "testing"

// What the echo check must NOT do: refuse a reply it does not recognise.
// Nobody has captured a power verb's full reply, so anything that is not
// silence and not a foreign echo is accepted and left to the status read.
func TestCheckBitScopeEcho(t *testing.T) {
	target := bitscopeTarget{nodeID: "n", pos: "A-1", addr: 0x01}
	for _, tc := range []struct {
		name, reply string
		wantErr     bool
	}{
		{"silence", "", true},
		{"whitespace only", "\r\n ", true},
		{"its own echo", "01|/", false},
		{"its own echo, bracketed", "[01]|/", false},
		{"echo then more", "01|/\r\nsomething", false},
		{"no echo line at all", "ok", false},
		{"an echo whose address does not parse", "zz|/", false},
		{"another address", "02|/", true},
		{"another address after its own", "01|/\n17|/", true},
	} {
		err := checkBitScopeEcho(target, bitscopeVerbOn, tc.reply)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: reply %q: err = %v, wantErr %v", tc.name, tc.reply, err, tc.wantErr)
		}
	}
}
