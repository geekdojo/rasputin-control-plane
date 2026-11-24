// Package unmapped is a fixture for kinds_complete_test.go: a workflow whose
// constant kind the kind table does not hold.
package unmapped

import "github.com/geekdojo/rasputin-control-plane/api/internal/jobs"

const kind = "test.not_in_the_table"

// Workflow is the unmapped workflow.
func Workflow() jobs.Workflow { return jobs.Workflow{Kind: kind} }
