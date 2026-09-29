package bustls

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-517-21: an unavailable bus is a crit alert naming the file that failed —
// the key or the certificate — and an available one raises none.
func TestState_Alert(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	key, _, err := EnsureKey(filepath.Join(dir, "bus"))
	if err != nil {
		t.Fatal(err)
	}
	if a := Available(key).Alert(now); a != nil {
		t.Fatalf("Available(key).Alert = %+v, want nil", a)
	}
	for _, file := range []string{
		filepath.Join(dir, "bus", KeyFileName),
		filepath.Join(dir, "bus", CertFileName),
	} {
		a := Unavailable(file, errors.New("boom")).Alert(now)
		if a == nil {
			t.Fatalf("Unavailable(%s).Alert = nil", file)
		}
		if AlertID != "bus-tls-unavailable" || a.ID != AlertID || a.Severity != proto.AlertCrit || a.Title != "Node bus is down" {
			t.Errorf("alert = %+v, want id bus-tls-unavailable, crit, title %q", a, "Node bus is down")
		}
		if !strings.Contains(a.Detail, file) {
			t.Errorf("detail %q does not name %s", a.Detail, file)
		}
		other := CertFileName
		if strings.HasSuffix(file, CertFileName) {
			other = KeyFileName
		}
		if strings.Contains(a.Detail, other) {
			t.Errorf("detail %q names %s, which did not fail", a.Detail, other)
		}
		if !a.Since.Equal(now) {
			t.Errorf("since = %s, want %s", a.Since, now)
		}
	}
}

// TC-517-54: the zero State and Available(nil) fail closed: no pin, a crit
// alert, a fault, and no panic.
func TestState_ZeroValueFailsClosed(t *testing.T) {
	for name, s := range map[string]State{"zero": {}, "Available(nil)": Available(nil)} {
		t.Run(name, func(t *testing.T) {
			if pin, ok := s.Pin(); ok || pin != "" {
				t.Fatalf("Pin() = (%q, %v), want (\"\", false)", pin, ok)
			}
			if _, err := s.Fault(); err == nil {
				t.Fatal("Fault() = nil error for a State with no key")
			}
			a := s.Alert(time.Now())
			if a == nil || a.Severity != proto.AlertCrit || a.ID != AlertID {
				t.Fatalf("Alert() = %+v, want a crit %s", a, AlertID)
			}
		})
	}
}

func TestState_AvailableAndUnavailable(t *testing.T) {
	key, _, err := EnsureKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := Available(key)
	if pin, ok := s.Pin(); !ok || pin != key.Pin() {
		t.Fatalf("Pin() = (%q, %v), want (%q, true)", pin, ok, key.Pin())
	}
	if file, err := s.Fault(); file != "" || err != nil {
		t.Fatalf("Fault() = (%q, %v), want none", file, err)
	}
	cause := errors.New("unreadable")
	u := Unavailable("/d/bus/bus.key", cause)
	if file, err := u.Fault(); file != "/d/bus/bus.key" || !errors.Is(err, cause) {
		t.Fatalf("Fault() = (%q, %v), want the file and the cause", file, err)
	}
	if _, err := Unavailable("/d/bus/bus.crt", nil).Fault(); err == nil {
		t.Fatal("Unavailable with a nil error reports no fault")
	}
}
