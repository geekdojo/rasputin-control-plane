package functest

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// recorder is a TB that records each call instead of acting on it.
type recorder struct {
	helpers int
	fatals  []string
	skips   []string
}

func (r *recorder) Helper() { r.helpers++ }

func (r *recorder) Fatalf(format string, args ...any) {
	r.fatals = append(r.fatals, fmt.Sprintf(format, args...))
}

func (r *recorder) Skipf(format string, args ...any) {
	r.skips = append(r.skips, fmt.Sprintf(format, args...))
}

const (
	appsecretEnv = "RASPUTIN_APPSECRET_FUNCTIONAL"
	grafanaEnv   = "RASPUTIN_GRAFANA_FUNCTIONAL"
)

var errNoDocker = errors.New(`exec: "docker": executable file not found in $PATH`)

// unsetenv clears env for the rest of t, restoring it afterwards (t.Setenv
// registers the restore; the Unsetenv then removes the variable outright).
func unsetenv(t *testing.T, env string) {
	t.Helper()
	t.Setenv(env, "")
	if err := os.Unsetenv(env); err != nil {
		t.Fatal(err)
	}
}

// TC-695-01: with the variable set to "required", SkipOrFail fails once with a
// message naming the variable and the formatted reason, and never skips.
func TestSkipOrFail_RequiredFails(t *testing.T) {
	t.Setenv(appsecretEnv, Required)
	r := &recorder{}

	SkipOrFail(r, appsecretEnv, "docker not on PATH: %v", errNoDocker)

	if r.helpers == 0 {
		t.Error("Helper was not called")
	}
	if len(r.skips) != 0 {
		t.Errorf("Skipf called %d times, want 0: %q", len(r.skips), r.skips)
	}
	if len(r.fatals) != 1 {
		t.Fatalf("Fatalf called %d times, want 1: %q", len(r.fatals), r.fatals)
	}
	want := "RASPUTIN_APPSECRET_FUNCTIONAL=required but docker not on PATH: " + errNoDocker.Error()
	if r.fatals[0] != want {
		t.Errorf("Fatalf message = %q, want %q", r.fatals[0], want)
	}
}

// TC-695-02: any value other than exactly "required", and an unset variable,
// skips once with the bare reason and never fails.
func TestSkipOrFail_NotRequiredSkips(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		unset bool
	}{
		{name: "unset", unset: true},
		{name: "empty", value: ""},
		{name: "one", value: "1"},
		{name: "upper", value: "REQUIRED"},
		{name: "trailing space", value: "required "},
		{name: "leading space", value: " required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.unset {
				unsetenv(t, appsecretEnv)
			} else {
				t.Setenv(appsecretEnv, tc.value)
			}
			r := &recorder{}

			SkipOrFail(r, appsecretEnv, "docker not on PATH: %v", errNoDocker)

			if r.helpers == 0 {
				t.Error("Helper was not called")
			}
			if len(r.fatals) != 0 {
				t.Errorf("Fatalf called %d times, want 0: %q", len(r.fatals), r.fatals)
			}
			if len(r.skips) != 1 {
				t.Fatalf("Skipf called %d times, want 1: %q", len(r.skips), r.skips)
			}
			want := "docker not on PATH: " + errNoDocker.Error()
			if r.skips[0] != want {
				t.Errorf("Skipf message = %q, want %q", r.skips[0], want)
			}
			if strings.Contains(r.skips[0], appsecretEnv+"=") {
				t.Errorf("Skipf message %q carries the required prefix", r.skips[0])
			}
		})
	}
}

// TC-695-03: SkipOrFail reads only the variable it is given. Another test's
// switch set to "required" does not make this one fail, and the swapped case
// fails as in TC-695-01.
func TestSkipOrFail_ReadsOnlyItsOwnVariable(t *testing.T) {
	t.Run("other variable required", func(t *testing.T) {
		t.Setenv(grafanaEnv, Required)
		unsetenv(t, appsecretEnv)
		r := &recorder{}

		SkipOrFail(r, appsecretEnv, "docker not on PATH: %v", errNoDocker)

		if len(r.fatals) != 0 {
			t.Errorf("Fatalf called %d times, want 0: %q", len(r.fatals), r.fatals)
		}
		if len(r.skips) != 1 {
			t.Errorf("Skipf called %d times, want 1: %q", len(r.skips), r.skips)
		}
	})
	t.Run("own variable required", func(t *testing.T) {
		t.Setenv(appsecretEnv, Required)
		unsetenv(t, grafanaEnv)
		r := &recorder{}

		SkipOrFail(r, appsecretEnv, "docker not on PATH: %v", errNoDocker)

		if len(r.skips) != 0 {
			t.Errorf("Skipf called %d times, want 0: %q", len(r.skips), r.skips)
		}
		if len(r.fatals) != 1 {
			t.Fatalf("Fatalf called %d times, want 1: %q", len(r.fatals), r.fatals)
		}
		if !strings.HasPrefix(r.fatals[0], appsecretEnv+"=required but ") {
			t.Errorf("Fatalf message %q does not name %s", r.fatals[0], appsecretEnv)
		}
	})
}

// TC-695-04 is the coverage measurement over this package:
//
//	go test -coverprofile=c.out ./api/internal/functest && go tool cover -func=c.out
//
// The tests above exercise both branches of SkipOrFail.
