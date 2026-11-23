package bus

import (
	"testing"

	"github.com/nats-io/nats-server/v2/server"
)

// TC-988-30: the RASPUTIN_NATS_PORT mapping is unchanged from v2026.09.5,
// and "-1" is the one new value.
func TestParsePort(t *testing.T) {
	if DefaultPort != 4222 {
		t.Fatalf("DefaultPort = %d, want 4222", DefaultPort)
	}
	if AnyPort != -1 {
		t.Fatalf("AnyPort = %d, want -1", AnyPort)
	}
	if AnyPort != server.RANDOM_PORT {
		t.Fatalf("AnyPort = %d, want server.RANDOM_PORT (%d)", AnyPort, server.RANDOM_PORT)
	}
	for _, tc := range []struct {
		in   string
		want int
	}{
		{"", DefaultPort},
		{"0", DefaultPort},
		{"-2", DefaultPort},
		{"x", DefaultPort},
		{"5000", 5000},
		{"-1", AnyPort},
	} {
		if got := ParsePort(tc.in); got != tc.want {
			t.Errorf("ParsePort(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
