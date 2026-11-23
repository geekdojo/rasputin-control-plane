package signinname

import (
	"math"
	"testing"
)

// F-995-11: an ifindex the kernel's int32 cannot carry, or one naming no
// interface, is refused before any conversion; every valid one passes intact.
func TestIfindex32(t *testing.T) {
	for _, tc := range []struct {
		in   int
		want int32
		ok   bool
	}{
		{in: 1, want: 1, ok: true},
		{in: 7, want: 7, ok: true},
		{in: math.MaxInt32, want: math.MaxInt32, ok: true},
		{in: 0},
		{in: -1},
		{in: math.MinInt32},
		{in: math.MaxInt32 + 1},
	} {
		got, err := ifindex32(tc.in)
		if tc.ok {
			if err != nil || got != tc.want {
				t.Errorf("ifindex32(%d) = %d, %v; want %d, nil", tc.in, got, err, tc.want)
			}
			continue
		}
		if err == nil {
			t.Errorf("ifindex32(%d) = %d, nil; want an error", tc.in, got)
		}
	}
}
