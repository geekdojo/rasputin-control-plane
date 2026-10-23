package osoutcome

import (
	"context"
	"os"
	"sync"
	"testing"
)

// observed records each Observe call.
type observed struct {
	mu   sync.Mutex
	recs []Record
}

func (o *observed) observe(_ context.Context, rec Record) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.recs = append(o.recs, rec)
}

func (o *observed) got() []Record {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]Record(nil), o.recs...)
}

// TC-765-29: a source declaring Observe has it called once per parsed record,
// at start and after a store restart, and never for an absent, unreadable or
// malformed record.
func TestReader_ObserveIsCalledOncePerParsedRecord(t *testing.T) {
	const initSrc = 1
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, h *harness)
		want  int
	}{
		{"absent", func(*testing.T, *harness) {}, 0},
		{"unreadable", func(t *testing.T, h *harness) {
			if err := os.Mkdir(h.srcs[initSrc].Path, 0o700); err != nil {
				t.Fatal(err)
			}
		}, 0},
		{"malformed", func(t *testing.T, h *harness) {
			h.write(t, initSrc, initRec("initialised", testBoot, "Done.")+"extra=1\n")
		}, 0},
		{"parsed", func(t *testing.T, h *harness) {
			h.write(t, initSrc, initRec("initialised", testBoot, "Done."))
		}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			o := &observed{}
			h.srcs[initSrc].Observe = o.observe
			tc.setup(t, h)
			r := h.reader(t)
			r.ReadAtStart(t.Context())
			if got := o.got(); len(got) != tc.want {
				t.Fatalf("at start: Observe called %d time(s), want %d", len(got), tc.want)
			}
			r.AfterStoreRestart(t.Context())
			got := o.got()
			if len(got) != 2*tc.want {
				t.Fatalf("after the restart: Observe called %d time(s), want %d", len(got), 2*tc.want)
			}
			for _, rec := range got {
				if rec.Outcome != "initialised" || rec.BootID != testBoot {
					t.Errorf("observed %+v, want the parsed initialised record for %s", rec, testBoot)
				}
			}
		})
	}
}
