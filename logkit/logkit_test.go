package logkit

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// TC-517-52: the logger both mains use renders LevelFatal as FATAL.
func TestNew_RendersFatal(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).Log(context.Background(), LevelFatal, "cannot continue", "node_id", "c1")
	out := buf.String()
	if !strings.Contains(out, "level=FATAL") {
		t.Fatalf("a LevelFatal record rendered as %q, want level=FATAL", out)
	}
	if strings.Contains(out, "ERROR+4") {
		t.Fatalf("a LevelFatal record still carries slog's default name: %q", out)
	}
}

// TC-517-52: a value carrying CRLF cannot forge a second record.
func TestNew_EscapesControlCharacters(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).Log(context.Background(), LevelFatal, "bad value",
		"value", "x\r\nlevel=INFO msg=forged")
	out := buf.String()
	if n := strings.Count(out, "\n"); n != 1 {
		t.Fatalf("one record wrote %d lines: %q", n, out)
	}
	if strings.Contains(out, "\r") {
		t.Fatalf("a raw CR reached the output: %q", out)
	}
	if !strings.Contains(out, `\r\n`) {
		t.Fatalf("the CRLF was not escaped: %q", out)
	}
}

// Below Info is dropped: the level is Info, as in Human System's newLogger.
func TestNew_InfoAndAbove(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.Debug("hidden")
	l.Info("shown")
	if strings.Contains(buf.String(), "hidden") || !strings.Contains(buf.String(), "shown") {
		t.Fatalf("level filtering wrong: %q", buf.String())
	}
	if !l.Enabled(context.Background(), slog.LevelWarn) {
		t.Fatal("WARN disabled")
	}
}
