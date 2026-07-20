package ids

import "testing"

// Weak on purpose: asserts only n=0, so the boundary mutant lives while the
// negation mutant dies — demonstrating the mutation gate surfacing a survivor.
func TestCanaryWithinWindow(t *testing.T) {
	if !canaryWithinWindow(0) {
		t.Fatal("0 should be within the window")
	}
}
