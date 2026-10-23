package secretstore

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// healthSeq answers each Health call with the next answer, then the last.
type healthSeq struct {
	mu   sync.Mutex
	errs []error
	n    int
}

func (h *healthSeq) Health(context.Context) (Health, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	i := min(h.n, len(h.errs)-1)
	h.n++
	if h.errs[i] != nil {
		return Health{}, h.errs[i]
	}
	return Health{Initialized: true}, nil
}

// WaitReady, the one ready-wait (#765, K24): it returns on the first 200
// after a store that answered sealed, and with its bound's error naming the
// last answer when no 200 comes.
func TestWaitReady(t *testing.T) {
	sealed := &Error{Op: "health", Kind: ErrSealed}
	h := &healthSeq{errs: []error{sealed, sealed, nil}}
	if err := WaitReady(context.Background(), h, 5*time.Second); err != nil {
		t.Fatalf("WaitReady = %v, want nil once the store answers 200", err)
	}
	if h.n != 3 {
		t.Errorf("Health asked %d times, want 3", h.n)
	}
	err := WaitReady(context.Background(), &healthSeq{errs: []error{sealed}}, 250*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "last: sealed") {
		t.Fatalf("WaitReady on a sealed store = %v, want its bound naming sealed", err)
	}
}
