package storestate

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
)

// Counts is how many requests the api's audited store calls sent to the
// store since the process started, and how many of them failed
// (geekdojo/geekdojo-brain#939). Both only ever grow.
type Counts struct {
	Requests uint64
	Errors   uint64
}

// Counter is an Observer that counts the outcomes it is told about, for the
// store-health metrics (geekdojo/geekdojo-brain#939). It reads nothing and
// decides nothing: the Monitor stays the one reading of readiness, and the
// composition root tees the two (Tee). Safe for concurrent use; the zero
// value is ready.
//
// Its rules follow the Monitor's own reading of an outcome (ObserveAudited):
//
//   - ctx is done: nothing is counted, because the store was not given the
//     time to answer;
//   - ErrInvalidValue or ErrDisabled: nothing is counted, because no request
//     reached a store;
//   - nil, not found or a check-and-set mismatch: one request, no error, as
//     the store answered;
//   - anything else (denied, sealed, unreachable or timed out, a protocol
//     error): one request and one error.
type Counter struct {
	requests atomic.Uint64
	errors   atomic.Uint64
}

// ObserveAudited counts one audited call's outcome.
func (c *Counter) ObserveAudited(ctx context.Context, err error) {
	if ctx.Err() != nil {
		return
	}
	switch {
	case errors.Is(err, secretstore.ErrInvalidValue), errors.Is(err, secretstore.ErrDisabled):
		return
	case err == nil, errors.Is(err, secretstore.ErrNotFound), errors.Is(err, secretstore.ErrCASMismatch):
		c.requests.Add(1)
	default:
		c.requests.Add(1)
		c.errors.Add(1)
	}
}

// Counts returns the counts so far.
func (c *Counter) Counts() Counts {
	return Counts{Requests: c.requests.Load(), Errors: c.errors.Load()}
}

// Tee returns an Observer that tells every one of observers each outcome,
// in order. The composition root uses it to give both the Monitor and the
// Counter every audited call.
func Tee(observers ...Observer) Observer {
	return tee(observers)
}

type tee []Observer

func (t tee) ObserveAudited(ctx context.Context, err error) {
	for _, o := range t {
		o.ObserveAudited(ctx, err)
	}
}
