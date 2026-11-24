package main

import (
	"log/slog"
	"strings"
	"testing"
)

// Each path gets its own file name, and / is root.
func TestShotName(t *testing.T) {
	for in, want := range map[string]string{"/": "root.png", "/apps": "apps.png", "/settings/users?x=1": "settings_users_x_1.png"} {
		if got := shotName(in); got != want {
			t.Errorf("shotName(%q) = %q, want %q", in, got, want)
		}
	}
}

// A run with no path, or before the stack is up, says what is missing and
// starts no browser.
func TestRun_RefusesWithoutPathsOrStack(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	if err := run(log, t.TempDir(), t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "at least one") {
		t.Errorf("no paths: %v", err)
	}
	if err := run(log, t.TempDir(), t.TempDir(), []string{"/"}); err == nil || !strings.Contains(err.Error(), "identity-on-mac.sh up") {
		t.Errorf("no stack: %v", err)
	}
}
