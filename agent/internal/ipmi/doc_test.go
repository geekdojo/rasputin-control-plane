// Package ipmi has no implementation yet — it's a doc-only placeholder
// reserving the import path for the future I²C / Redfish / IPMI client.
// This test file exists so `go test ./agent/internal/ipmi/...` reports
// `ok` instead of `[no test files]`, which would otherwise show up as a
// gap in CI's coverage matrix.
package ipmi

import "testing"

func TestPackagePlaceholder(t *testing.T) {
	// Intentionally empty. The package currently exports nothing.
	// When the real backend lands, replace this with real tests.
}
