package jobs

import (
	"context"
	"log/slog"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// LogStep writes msg to the step log at the mapped level and msg with the
// job's id and attrs to the logger; a StepCtx with no Log writes the logger
// alone.
func TestLogStep(t *testing.T) {
	for _, tc := range []struct {
		level slog.Level
		want  string
	}{
		{slog.LevelDebug, "info"}, {slog.LevelInfo, "info"}, {slog.LevelWarn, "warn"}, {slog.LevelError, "error"}, {slog.LevelError + 4, "error"},
	} {
		log, rec := logkittest.New()
		var got []string
		sc := &StepCtx{Ctx: context.Background(), JobID: "job-1", Log: func(level, msg string) { got = append(got, level+":"+msg) }}
		LogStep(log, sc, tc.level, "safe text", "err", "detail")
		if len(got) != 1 || got[0] != tc.want+":safe text" {
			t.Errorf("level %v: step log %q, want %q", tc.level, got, tc.want+":safe text")
		}
		r := rec.Records()
		if len(r) != 1 || r[0].Level != tc.level || r[0].Message != "safe text" {
			t.Fatalf("level %v: records %+v", tc.level, r)
		}
		for key, want := range map[string]string{"job_id": "job-1", "err": "detail"} {
			if v, _ := logkittest.Attr(r[0], key); v != want {
				t.Errorf("%s = %q, want %q", key, v, want)
			}
		}
	}
	log, rec := logkittest.New()
	LogStep(log, &StepCtx{Ctx: context.Background(), JobID: "job-2"}, slog.LevelInfo, "no step log")
	if len(rec.Records()) != 1 {
		t.Errorf("records = %d, want 1 with no step log", len(rec.Records()))
	}
}
