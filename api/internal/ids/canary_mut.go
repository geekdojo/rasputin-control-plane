package ids

// CANARY (do not merge) — mutation-gate detection self-test. Throwaway;
// the PR is closed unmerged once the advisory comment posts.

// canaryWithinWindow reports whether n is within the retry window. Its test
// only checks n=0, deliberately leaving the boundary untested so a
// CONDITIONALS_BOUNDARY mutant (< -> <=) survives.
func canaryWithinWindow(n int) bool {
	return n < 3
}
