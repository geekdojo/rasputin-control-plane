package ids

import "testing"

func TestCanaryDouble(t *testing.T) {
	if got := canaryDouble(3); got != 6 {
		t.Fatalf("canaryDouble(3) = %d, want 6", got)
	}
}
