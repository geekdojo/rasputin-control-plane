package bmc

import (
	"strings"
	"testing"
)

func TestNew_EmptyKindSelectsDefault(t *testing.T) {
	b, err := New("", Config{StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("New(\"\"): %v", err)
	}
	if b.Name() != DefaultBackend {
		t.Errorf("Name: %q, want %q", b.Name(), DefaultBackend)
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

func TestNames_ContainsDefault(t *testing.T) {
	names := Names()
	for _, n := range names {
		if n == DefaultBackend {
			return
		}
	}
	t.Errorf("Names() = %v, missing %q", names, DefaultBackend)
}
