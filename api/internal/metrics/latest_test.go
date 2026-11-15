package metrics

import (
	"context"
	"testing"
	"time"
)

// TC-1011-09: LatestValue is the updater's read of a control plane's reported
// memory. It returns the newest sample of the named metric for the named node,
// never another node's or another metric's, and ok=false with no error for a
// node that has reported nothing.
func TestStore_LatestValue(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	t0 := time.Now().UTC().Truncate(time.Millisecond)
	// cp's newest sample is in the middle of insertion order, so the answer
	// cannot be "the last row written".
	insertSample(t, s, "cp", t0, map[string]float64{"mem_total_bytes": 100, "mem_used_bytes": 1})
	insertSample(t, s, "cp", t0.Add(2*time.Second), map[string]float64{"mem_total_bytes": 300, "mem_used_bytes": 2})
	insertSample(t, s, "cp", t0.Add(time.Second), map[string]float64{"mem_total_bytes": 200, "mem_used_bytes": 3})
	// w1's sample is newer than all of cp's and larger.
	insertSample(t, s, "w1", t0.Add(time.Hour), map[string]float64{"mem_total_bytes": 999})

	v, ok, err := s.LatestValue(ctx, "cp", "mem_total_bytes")
	if err != nil || !ok || v != 300 {
		t.Errorf("LatestValue(cp, mem_total_bytes) = (%v, %v, %v), want (300, true, nil)", v, ok, err)
	}
	v, ok, err = s.LatestValue(ctx, "cp", "mem_used_bytes")
	if err != nil || !ok || v != 2 {
		t.Errorf("LatestValue(cp, mem_used_bytes) = (%v, %v, %v), want (2, true, nil)", v, ok, err)
	}
	v, ok, err = s.LatestValue(ctx, "absent", "mem_total_bytes")
	if err != nil || ok || v != 0 {
		t.Errorf("LatestValue(absent) = (%v, %v, %v), want (0, false, nil)", v, ok, err)
	}
	v, ok, err = s.LatestValue(ctx, "w1", "mem_used_bytes")
	if err != nil || ok || v != 0 {
		t.Errorf("LatestValue(w1, mem_used_bytes) = (%v, %v, %v), want (0, false, nil): another metric's rows leaked", v, ok, err)
	}
}

// A closed store's read error is returned, not read as "no sample", so the
// updater refuses as unreadable rather than as not reported.
func TestStore_LatestValue_ReturnsTheReadError(t *testing.T) {
	s := newStore(t)
	_ = s.Close()
	if _, ok, err := s.LatestValue(context.Background(), "cp", "mem_total_bytes"); err == nil || ok {
		t.Errorf("LatestValue on a closed store = (ok=%v, err=%v), want an error", ok, err)
	}
}
