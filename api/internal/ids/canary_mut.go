package ids

// CANARY (do not merge) — mutation-gate detection self-test. Throwaway;
// the PR is closed unmerged once the advisory comment posts.
//
// canaryBackoff has NO test exercising it, so its arithmetic mutants are
// reported NOT COVERED — a survivor the gate surfaces in its advisory
// comment (a mutant no test can catch because no test runs the line).
func canaryBackoff(n int) int {
	return n*2 + 1
}

// Referenced so the compiler doesn't consider canaryBackoff dead, without
// any test asserting its result.
var _ = canaryBackoff
