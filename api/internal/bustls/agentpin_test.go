package bustls

import (
	"os"
	"path/filepath"
	"testing"
)

// The controlplane's own agent gets the live pin written beside its token, on
// every start, at a mode it can read (geekdojo/geekdojo-brain#510).
func TestWriteAgentPinFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bus")
	key, _, err := EnsureKey(dir)
	if err != nil {
		t.Fatal(err)
	}

	path, err := WriteAgentPinFile(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if got := filepath.Base(path); got != "agent.pin" {
		t.Fatalf("wrote %q, want agent.pin", got)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != key.Pin()+"\n" {
		t.Fatalf("file = %q, want %q", b, key.Pin()+"\n")
	}
	// The pin is public — it is printed by GET /api/bus/tls and rendered into
	// every seed — and the agent may run as another uid on a dev box, so the
	// FILE is 0644. The directory around it stays 0700.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("pin file mode = %v, want 0644", fi.Mode().Perm())
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("bus dir mode = %v, want 0700", di.Mode().Perm())
	}

	// Written again on every start, so a restored or regenerated key reaches
	// the local agent with nobody editing a file.
	other := filepath.Join(t.TempDir(), "bus")
	key2, _, err := EnsureKey(other)
	if err != nil {
		t.Fatal(err)
	}
	if key2.Pin() == key.Pin() {
		t.Fatal("two generated keys share a pin")
	}
	if _, err := WriteAgentPinFile(dir, key2); err != nil {
		t.Fatal(err)
	}
	if b, err = os.ReadFile(path); err != nil {
		t.Fatal(err)
	}
	if string(b) != key2.Pin()+"\n" {
		t.Fatalf("file = %q after a re-write, want %q", b, key2.Pin()+"\n")
	}

	// No key means no pin, and a refusal rather than an empty file that an
	// agent would read as a configured-but-unusable pin.
	if _, err := WriteAgentPinFile(dir, nil); err == nil {
		t.Fatal("WriteAgentPinFile(nil) = nil, want an error")
	}
}
