//go:build race

package bustls_test

// raceEnabled: this test binary runs with the race detector, so the binaries
// it builds get it too.
const raceEnabled = true
