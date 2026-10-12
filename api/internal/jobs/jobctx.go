package jobs

import "context"

// jobIDKey is the context key ContextWithJobID stores a job's id under.
type jobIDKey struct{}

// ContextWithJobID returns ctx carrying the id of the job a step runs for, so
// a collaborator the step calls can put that id on its own log records as the
// correlation id that joins them to the job (geekdojo/geekdojo-brain#760,
// F-760-03).
func ContextWithJobID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, jobIDKey{}, id)
}

// JobIDFromContext returns the job id ContextWithJobID stored in ctx, or ""
// when ctx carries none.
func JobIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(jobIDKey{}).(string)
	return id
}
