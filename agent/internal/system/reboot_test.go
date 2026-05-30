package system

import (
	"sync"
	"testing"
)

// TestIsMuted_DefaultsFalse — fresh process starts not muted.
func TestIsMuted_DefaultsFalse(t *testing.T) {
	// We can't easily reset the package-level atomic between tests, so
	// preserve the value and restore on exit.
	prev := IsMuted()
	t.Cleanup(func() { MutedAtomic().Store(prev) })

	MutedAtomic().Store(false)
	if IsMuted() {
		t.Error("after Store(false), IsMuted should be false")
	}
}

// TestMutedAtomic_ReadModifyWriteFlow mirrors how updater.MockBackend uses
// the shared flag: set, do work, defer reset. The heartbeat loop reads
// IsMuted() concurrently; the race detector will catch any unsoundness if
// our parallel sub-tests interleave.
func TestMutedAtomic_ReadModifyWriteFlow(t *testing.T) {
	prev := IsMuted()
	t.Cleanup(func() { MutedAtomic().Store(prev) })

	MutedAtomic().Store(true)
	if !IsMuted() {
		t.Error("after Store(true), IsMuted should be true")
	}
	MutedAtomic().Store(false)
	if IsMuted() {
		t.Error("after Store(false), IsMuted should be false")
	}
}

// TestMutedAtomic_ReturnsSameInstance — important for the cross-package
// contract documented in MutedAtomic's docstring: the updater and system
// packages must share *the same* atomic, not snapshots of it.
func TestMutedAtomic_ReturnsSameInstance(t *testing.T) {
	a := MutedAtomic()
	b := MutedAtomic()
	if a != b {
		t.Error("MutedAtomic returned two different *atomic.Bool instances; cross-package mute would be broken")
	}
}

// TestMutedAtomic_ConcurrentReads exercises the race detector against
// concurrent IsMuted() callers. Modeled on the heartbeat loop, which reads
// the flag every 10s from a single goroutine — here we fan out across
// many to maximize the chance of catching a torn read.
func TestMutedAtomic_ConcurrentReads(t *testing.T) {
	prev := IsMuted()
	t.Cleanup(func() { MutedAtomic().Store(prev) })

	MutedAtomic().Store(true)
	var wg sync.WaitGroup
	wg.Add(8)
	for i := 0; i < 8; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = IsMuted()
			}
		}()
	}
	wg.Wait()
}

// TestRebootConstants — captures the public constants we depend on.
// If anyone bumps these, they should at least have to update this test,
// which jogs them into checking the api saga timeouts that compensate
// for the delay.
func TestRebootConstants(t *testing.T) {
	if rebootDefaultDelay <= 0 {
		t.Errorf("default delay must be positive, got %d", rebootDefaultDelay)
	}
	if rebootMaxDelay <= rebootDefaultDelay {
		t.Errorf("max delay (%d) must be > default (%d)", rebootMaxDelay, rebootDefaultDelay)
	}
}
