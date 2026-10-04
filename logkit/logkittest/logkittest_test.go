package logkittest

import (
	"log/slog"
	"strings"
	"testing"
)

// The recorder keeps level, message and fields, including fields bound with
// With, and renders all of it for a search.
func TestRecorder(t *testing.T) {
	logger, rec := New()
	logger.With("job_id", "j1").Warn("refused", "code", "scope")
	logger.Info("landed", "bytes", 42)

	warns := rec.AtLevel(slog.LevelWarn)
	if len(warns) != 1 || warns[0].Message != "refused" {
		t.Fatalf("WARN records: %+v", warns)
	}
	if v, ok := Attr(warns[0], "job_id"); !ok || v != "j1" {
		t.Errorf("job_id = %q (present %v), want the field bound With", v, ok)
	}
	if v, ok := Attr(warns[0], "code"); !ok || v != "scope" {
		t.Errorf("code = %q (present %v)", v, ok)
	}
	if _, ok := Attr(warns[0], "absent"); ok {
		t.Error("an absent field was found")
	}
	if got := rec.Matching(slog.LevelInfo, "land"); len(got) != 1 {
		t.Errorf("Matching(INFO, land) = %d records, want 1", len(got))
	}
	if got := rec.Matching(slog.LevelInfo, "refused"); len(got) != 0 {
		t.Errorf("Matching matched across levels: %d", len(got))
	}
	text := rec.Text()
	for _, want := range []string{"WARN refused", "job_id=j1", "code=scope", "INFO landed", "bytes=42"} {
		if !strings.Contains(text, want) {
			t.Errorf("Text lacks %q:\n%s", want, text)
		}
	}
	if len(rec.Records()) != 2 {
		t.Errorf("Records = %d, want 2", len(rec.Records()))
	}
	if logger.WithGroup("g").Handler() == nil {
		t.Error("WithGroup returned no handler")
	}
}
