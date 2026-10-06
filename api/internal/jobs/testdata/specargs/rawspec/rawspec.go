// Package rawspec is a fixture for specargs_test.go: five runner calls with a
// raw spec, each of which the checker must name, and two it must pass.
package rawspec

import (
	"context"
	"encoding/json"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bmc"
	"github.com/geekdojo/rasputin-control-plane/api/internal/console"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

type spec struct {
	NodeID string `json:"nodeId"`
}

// Raw passes each raw form; the line numbers are pinned by the test.
func Raw(ctx context.Context, r *jobs.Runner, sub bmc.SubmitFn, push console.Submitter, k, c string) {
	b, _ := json.Marshal(spec{NodeID: "n1"})
	// json.Marshal's bytes to Submit:
	_, _ = r.Submit(ctx, k, b, c)
	raw := json.RawMessage(`{}`)
	// a json.RawMessage to SubmitPrepared:
	_, _ = r.SubmitPrepared(ctx, k, raw, c, nil)
	ptr := &raw
	// a *json.RawMessage to SubmitChild:
	_, _ = r.SubmitChild(ctx, k, ptr, c, "parent")
	bs := []byte(`{}`)
	// []byte to a bmc.SubmitFn:
	_ = sub(ctx, k, bs, c)
	rm := json.RawMessage(`{}`)
	// a json.RawMessage to a console.Submitter:
	_ = push(ctx, k, rm, c)
}

// Typed passes a struct and nil, which the checker must accept.
func Typed(ctx context.Context, r *jobs.Runner, k, c string) {
	_, _ = r.Submit(ctx, k, spec{NodeID: "n1"}, c)
	_, _ = r.Submit(ctx, k, nil, c)
}
