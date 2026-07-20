package ids

// CANARY (do not merge) — mutation-gate single-module scope self-test.
// Throwaway; the PR is closed unmerged once the advisory comment posts.

// canaryDouble is covered by a real asserting test, so its mutant is KILLED.
func canaryDouble(n int) int {
	return n * 2
}

var _ = canaryDouble
