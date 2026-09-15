package releases

import "testing"

func TestParseChannel(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"stable", ChannelStable, true},
		{"dev", ChannelDev, true},
		{"", "", false},
		{"Dev", "", false},
		{"nightly", "", false},
		{"dev\n", "", false},
		{"x\ny", "", false},
	} {
		got, ok := ParseChannel(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ParseChannel(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
