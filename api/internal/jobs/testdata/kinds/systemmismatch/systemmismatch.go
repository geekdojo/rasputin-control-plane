// Package systemmismatch is a fixture for kinds_complete_test.go: a System
// workflow whose kind the table classes control, not system-only.
package systemmismatch

import "github.com/geekdojo/rasputin-control-plane/api/internal/jobs"

// Workflow is the mismatched workflow.
func Workflow() jobs.Workflow { return jobs.Workflow{Kind: "bmc.power", System: true} }
