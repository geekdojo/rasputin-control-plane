// Package logkittest is a recording slog handler for tests that assert on the
// structured records a component writes through its injected logger: the
// level, the message and the fields, rather than a rendered line.
package logkittest

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
)

// Recorder keeps every record written through the loggers New returns. Safe
// for concurrent use: a handler goroutine writes while the test reads.
type Recorder struct {
	mu   sync.Mutex
	recs []slog.Record
}

// New returns a logger that records at every level, and its recorder.
func New() (*slog.Logger, *Recorder) {
	r := &Recorder{}
	return slog.New(&handler{rec: r}), r
}

// Records returns a copy of everything recorded so far, in order.
func (r *Recorder) Records() []slog.Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]slog.Record(nil), r.recs...)
}

// Matching returns the records at level whose message contains sub.
func (r *Recorder) Matching(level slog.Level, sub string) []slog.Record {
	var out []slog.Record
	for _, rec := range r.Records() {
		if rec.Level == level && strings.Contains(rec.Message, sub) {
			out = append(out, rec)
		}
	}
	return out
}

// AtLevel returns every record at level.
func (r *Recorder) AtLevel(level slog.Level) []slog.Record {
	return r.Matching(level, "")
}

// Text renders every record — level, message and every field — so a test can
// search all of it for a string that must never appear, such as a credential.
func (r *Recorder) Text() string {
	var b strings.Builder
	for _, rec := range r.Records() {
		fmt.Fprintf(&b, "%s %s", rec.Level, rec.Message)
		rec.Attrs(func(a slog.Attr) bool {
			fmt.Fprintf(&b, " %s=%v", a.Key, a.Value.Resolve().Any())
			return true
		})
		b.WriteString("\n")
	}
	return b.String()
}

// Attr returns the string form of rec's field key, and whether it is present.
func Attr(rec slog.Record, key string) (string, bool) {
	var (
		val   string
		found bool
	)
	rec.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			val, found = a.Value.Resolve().String(), true
			return false
		}
		return true
	})
	return val, found
}

// handler is the slog.Handler behind New. Attributes from WithAttrs are
// prepended to every record, so a logger built With fields records them too.
type handler struct {
	rec   *Recorder
	attrs []slog.Attr
}

func (h *handler) Enabled(context.Context, slog.Level) bool { return true }

func (h *handler) Handle(_ context.Context, r slog.Record) error {
	c := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	c.AddAttrs(h.attrs...)
	r.Attrs(func(a slog.Attr) bool {
		c.AddAttrs(a)
		return true
	})
	h.rec.mu.Lock()
	defer h.rec.mu.Unlock()
	h.rec.recs = append(h.rec.recs, c)
	return nil
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &handler{rec: h.rec, attrs: append(append([]slog.Attr(nil), h.attrs...), attrs...)}
}

// WithGroup is not used by the components under test; groups are flattened.
func (h *handler) WithGroup(string) slog.Handler { return h }
