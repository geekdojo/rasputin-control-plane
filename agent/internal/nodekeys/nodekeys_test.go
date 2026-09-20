package nodekeys

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Generated once, then loaded: a second Ensure must return the SAME keys.
// A node that re-minted its identity on every agent restart would raise the
// control plane's key-change alert on every restart, which would make the
// alert worthless.
func TestEnsure_GeneratesOnceAndLoadsAfter(t *testing.T) {
	dir := t.TempDir()
	first, generated, err := Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := proto.NodeKeyPurposes()
	if !reflect.DeepEqual(generated, want) {
		t.Fatalf("generated = %v, want %v", generated, want)
	}
	for _, p := range want {
		if first.Signer(p) == nil {
			t.Fatalf("no signer for %s", p)
		}
		if first.Hashes()[p] == "" {
			t.Fatalf("no hash for %s", p)
		}
	}
	if first.Hashes()[proto.NodeKeyAgent] == first.Hashes()[proto.NodeKeyCollector] {
		t.Fatal("the agent and collector share one key")
	}

	second, generated, err := Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(generated) != 0 {
		t.Errorf("a second Ensure generated %v", generated)
	}
	if !first.Hashes().Equal(second.Hashes()) {
		t.Errorf("hashes changed across Ensure: %v then %v", first.Hashes(), second.Hashes())
	}
}

// The hash reported is the hash of the key on disk. Anything else and the
// control plane records an identity the node cannot present.
func TestEnsure_HashMatchesTheKeyOnDisk(t *testing.T) {
	dir := t.TempDir()
	keys, _, err := Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range proto.NodeKeyPurposes() {
		blob, err := os.ReadFile(KeyPath(dir, p))
		if err != nil {
			t.Fatal(err)
		}
		signer, err := parse(blob)
		if err != nil {
			t.Fatal(err)
		}
		want, err := proto.NodeKeySPKIHash(signer.Public())
		if err != nil {
			t.Fatal(err)
		}
		if got := keys.Hashes()[p]; got != want {
			t.Errorf("%s: reported %q, key on disk hashes to %q", p, got, want)
		}
	}
}

// 0600 in a 0700 directory, and a wider mode left by a restore or a copy is
// tightened rather than accepted.
func TestEnsure_Modes(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	di, err := os.Stat(Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if got := di.Mode().Perm(); got != 0o700 {
		t.Errorf("key dir mode %o, want 700", got)
	}
	for _, p := range proto.NodeKeyPurposes() {
		fi, err := os.Stat(KeyPath(dir, p))
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != 0o600 {
			t.Errorf("%s key mode %o, want 600", p, got)
		}
	}

	loose := KeyPath(dir, proto.NodeKeyAgent)
	if err := os.Chmod(loose, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(loose)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("a 0644 key was left at %o, want tightened to 600", got)
	}
	di, err = os.Stat(Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if got := di.Mode().Perm(); got != 0o700 {
		t.Errorf("a 0755 key dir was left at %o, want tightened to 700", got)
	}
}

// A key file that does not parse is an ERROR, never a reason to generate a
// new one: replacing a key the control plane recorded would take the node off
// HTTPS, and minting a new identity silently is exactly what the key-change
// alert exists to stop happening unnoticed.
func TestEnsure_RefusesAnUnreadableKeyRatherThanReplacingIt(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	path := KeyPath(dir, proto.NodeKeyCollector)
	before, err := os.ReadFile(KeyPath(dir, proto.NodeKeyAgent))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Ensure(dir); err == nil {
		t.Fatal("Ensure accepted an unusable key file")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "not a key\n" {
		t.Errorf("the unusable file was rewritten: %q, %v", got, err)
	}
	after, err := os.ReadFile(KeyPath(dir, proto.NodeKeyAgent))
	if err != nil || string(after) != string(before) {
		t.Errorf("the other key was disturbed by the failure")
	}
}

func TestEnsure_RequiresAStateDir(t *testing.T) {
	if _, _, err := Ensure(""); err == nil {
		t.Fatal("Ensure accepted an empty state dir")
	}
}

// A nil key set reports nothing rather than panicking, so a caller that never
// got keys does not have to guard every use.
func TestNilKeysReportNothing(t *testing.T) {
	var k *Keys
	if k.Hashes() != nil || k.Signer(proto.NodeKeyAgent) != nil || k.Path(proto.NodeKeyAgent) != "" {
		t.Error("a nil key set answered something")
	}
}

func TestPathsAreUnderTheStateDir(t *testing.T) {
	dir := t.TempDir()
	keys, _, err := Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "keys", "collector.key")
	if got := keys.Path(proto.NodeKeyCollector); got != want {
		t.Errorf("Path = %q, want %q", got, want)
	}
}
