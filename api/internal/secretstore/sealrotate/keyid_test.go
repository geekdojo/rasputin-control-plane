package sealrotate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TC-830-02: only rasputin- plus a 36-character lowercase uuid parses, and a
// refusal quotes the input and nothing else.
func TestParseKeyID(t *testing.T) {
	const uuid = "0f1e2d3c-4b5a-4968-8776-655443322110"
	if got, err := ParseKeyID("rasputin-" + uuid); err != nil || got.String() != "rasputin-"+uuid {
		t.Fatalf("ParseKeyID(valid) = %q, %v", got, err)
	}
	for _, in := range []string{
		"rasputin-" + strings.ToUpper(uuid),
		"rasputin-" + uuid[:35],
		"rasputin-" + uuid + "0",
		uuid,
		"rasputin-../x",
		"rasputin-0f1e2d3c-4b5a-4968-8776/655443322110",
		"",
	} {
		_, err := ParseKeyID(in)
		if err == nil {
			t.Errorf("ParseKeyID(%q) parsed", in)
			continue
		}
		if want := fmt.Sprintf("sealrotate: key id %q is not rasputin-<uuid>", in); err.Error() != want {
			t.Errorf("ParseKeyID(%q) error = %q, want %q", in, err, want)
		}
	}
}

// KernelKeyID reads the uuid file once per call, as #803 does.
func TestKernelKeyID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "uuid")
	if err := os.WriteFile(path, []byte("0f1e2d3c-4b5a-4968-8776-655443322110\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if id, err := KernelKeyID(path)(); err != nil || id != "rasputin-0f1e2d3c-4b5a-4968-8776-655443322110" {
		t.Fatalf("KernelKeyID = %q, %v", id, err)
	}
	if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := KernelKeyID(path)(); err == nil {
		t.Error("an empty uuid made an id")
	}
	if _, err := KernelKeyID(filepath.Join(dir, "absent"))(); err == nil {
		t.Error("a missing uuid file made an id")
	}
	if err := os.WriteFile(path, []byte("NOT-A-UUID"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := KernelKeyID(path)(); err == nil {
		t.Error("a malformed uuid made an id")
	}
}
