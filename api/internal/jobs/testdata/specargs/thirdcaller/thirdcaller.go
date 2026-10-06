// Package thirdcaller is a fixture for specargs_test.go: two declarations
// that reach SubmitRawSpec and are not among its two pinned callers.
package thirdcaller

import (
	"context"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// Call is a third caller.
func Call(ctx context.Context, r *jobs.Runner) { _, _ = r.SubmitRawSpec(ctx, "k", nil, "c") }

// MethodValue takes the raw entry point as a method value, which reaches it
// as surely as a call.
func MethodValue(ctx context.Context, r *jobs.Runner) {
	f := r.SubmitRawSpec
	_, _ = f(ctx, "k", nil, "c")
}
