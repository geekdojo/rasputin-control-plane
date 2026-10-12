package storeaudit

import (
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

var sentenceText = regexp.MustCompile(`^[A-Z].*[.]$`)

func newFreeSpace(t *testing.T, free uint64, err error) (*FreeSpace, *logkittest.Recorder) {
	t.Helper()
	log, rec := logkittest.New()
	f, nerr := NewFreeSpace("/var/lib/rasputin", func(dir string) (uint64, error) {
		if dir != "/var/lib/rasputin" {
			t.Errorf("read dir = %q", dir)
		}
		return free, err
	}, log)
	if nerr != nil {
		t.Fatal(nerr)
	}
	return f, rec
}

// TC-799-22: warn below 5 GiB, crit below 1 GiB, nothing at or above 5 GiB.
// Every alert has the stable id and the node source, and its title and detail
// are sentences.
func TestFreeSpace_Thresholds(t *testing.T) {
	const gib = uint64(1) << 30
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		free uint64
		want proto.AlertSeverity // "" is no alert
	}{
		{5*gib - 1, proto.AlertWarn},
		{5 * gib, ""},
		{gib - 1, proto.AlertCrit},
		{gib, proto.AlertWarn},
		{0, proto.AlertCrit},
	} {
		f, rec := newFreeSpace(t, tc.free, nil)
		got := f.Alerts(now)
		if tc.want == "" {
			if len(got) != 0 {
				t.Errorf("free %d: %d alerts, want none", tc.free, len(got))
			}
			continue
		}
		if len(got) != 1 {
			t.Fatalf("free %d: %d alerts, want 1", tc.free, len(got))
		}
		a := got[0]
		if a.Severity != tc.want || a.ID != "disk-free:data-partition" ||
			a.Source != proto.AlertSourceNode || !a.Since.Equal(now) {
			t.Errorf("free %d: alert = %+v", tc.free, a)
		}
		if !sentenceText.MatchString(a.Title) || !sentenceText.MatchString(a.Detail) {
			t.Errorf("free %d: title %q / detail %q are not sentences", tc.free, a.Title, a.Detail)
		}
		if len(rec.Records()) != 0 {
			t.Errorf("free %d: logged %s", tc.free, rec.Text())
		}
	}
}

// TC-799-23: a failed read is one warn alert with no path or error text, and
// one WARN log carrying both.
func TestFreeSpace_ReadError(t *testing.T) {
	f, rec := newFreeSpace(t, 0, errors.New("statfs /var/lib/rasputin: input/output error"))
	got := f.Alerts(time.Now())
	if len(got) != 1 {
		t.Fatalf("%d alerts, want 1", len(got))
	}
	a := got[0]
	if a.ID != FreeSpaceAlertID || a.Severity != proto.AlertWarn || a.Source != proto.AlertSourceNode {
		t.Errorf("alert = %+v", a)
	}
	for _, s := range []string{a.Title, a.Detail} {
		if !sentenceText.MatchString(s) || strings.Contains(s, "/") || strings.Contains(s, "input/output") {
			t.Errorf("%q is not a sentence free of the path and the error", s)
		}
	}
	warns := rec.AtLevel(slog.LevelWarn)
	if len(warns) != 1 {
		t.Fatalf("records:\n%s\nwant one WARN", rec.Text())
	}
	if got := attr(t, warns[0], "file"); got != "/var/lib/rasputin" {
		t.Errorf("WARN file = %q", got)
	}
	if got := attr(t, warns[0], "err"); !strings.Contains(got, "input/output error") {
		t.Errorf("WARN err = %q", got)
	}
}
