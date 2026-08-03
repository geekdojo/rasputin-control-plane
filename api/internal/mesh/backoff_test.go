package mesh

import (
	"testing"
	"time"
)

// The bench case this replaced (2026-08-03): a freshly flashed node's FIRST
// enroll lands mid-`growpart`-reboot and fails, the node self-corrects in ~30
// seconds, and the old flat 30-minute cooldown then kept it out of the mesh
// for 33.7 minutes — long enough that an operator concludes the cluster is
// broken. The first retry must be quick.
func TestEnrollRetryBackoff_FirstRetryIsQuick(t *testing.T) {
	if got := enrollRetryBackoff(1); got != 30*time.Second {
		t.Errorf("first retry = %v, want 30s — a transient first-boot failure must not cost minutes", got)
	}
}

func TestEnrollRetryBackoff_DoublesThenCaps(t *testing.T) {
	for _, tc := range []struct {
		failures int
		want     time.Duration
	}{
		{1, 30 * time.Second},
		{2, time.Minute},
		{3, 2 * time.Minute},
		{4, 4 * time.Minute},
		{5, 8 * time.Minute},
		{6, 16 * time.Minute},
		{7, 30 * time.Minute}, // 32m clamped to the cap
		{8, 30 * time.Minute},
		{50, 30 * time.Minute},
	} {
		if got := enrollRetryBackoff(tc.failures); got != tc.want {
			t.Errorf("enrollRetryBackoff(%d) = %v, want %v", tc.failures, got, tc.want)
		}
	}
}

// The ceiling is the whole reason a flat cooldown existed: a persistently
// broken agent must not produce a failed job every reconcile tick. Backoff
// converges on exactly the old value, so that protection does not regress.
func TestEnrollRetryBackoff_NeverExceedsTheOldFlatCooldown(t *testing.T) {
	for n := 1; n < 200; n++ {
		if got := enrollRetryBackoff(n); got > 30*time.Minute {
			t.Fatalf("enrollRetryBackoff(%d) = %v, exceeds the 30m ceiling", n, got)
		}
	}
}

// A node with no failure streak is eligible immediately — a zero here is what
// lets a never-failed node enroll on the first reconcile tick.
func TestEnrollRetryBackoff_NoFailuresMeansNoWait(t *testing.T) {
	for _, n := range []int{0, -1} {
		if got := enrollRetryBackoff(n); got != 0 {
			t.Errorf("enrollRetryBackoff(%d) = %v, want 0", n, got)
		}
	}
}
