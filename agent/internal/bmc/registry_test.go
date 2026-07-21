package bmc

import (
	"strings"
	"testing"
)

func TestNew_OffKindsAreNotConstructible(t *testing.T) {
	// Hard off: "" and "none" mean no backend at all — the caller skips
	// construction; asking the registry for one is a wiring bug.
	for _, kind := range []string{"", BackendNone} {
		if _, err := New(kind, Config{StateDir: t.TempDir()}); err == nil {
			t.Errorf("New(%q): expected error", kind)
		}
	}
}

func TestNew_Mock(t *testing.T) {
	b, err := New("mock", Config{StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("New(mock): %v", err)
	}
	if _, ok := b.(*MockBackend); !ok {
		t.Errorf("New(mock) returned %T, want *MockBackend", b)
	}
}

func TestNew_UnknownKindErrors(t *testing.T) {
	_, err := New("bogus", Config{StateDir: t.TempDir()})
	if err == nil {
		t.Fatal("New(bogus): expected error, got nil")
	}
	if !strings.Contains(err.Error(), "bogus") || !strings.Contains(err.Error(), "mock") {
		t.Errorf("error should name the bad kind and the valid ones: %v", err)
	}
}

func TestNames_ContainsRegisteredKinds(t *testing.T) {
	names := Names()
	want := map[string]bool{"mock": false, "bitscope": false}
	for _, n := range names {
		if _, ok := want[n]; ok {
			want[n] = true
		}
	}
	for kind, seen := range want {
		if !seen {
			t.Errorf("Names() = %v, missing %q", names, kind)
		}
	}
}
