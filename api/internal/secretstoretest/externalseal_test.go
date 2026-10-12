package secretstoretest

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

// The ExternalSeal render (geekdojo/geekdojo-brain#830): no seal stanza in the
// main config, and a fragment in rasputin-seal-key.sh's exact shape under a
// rasputin-<uuid> key id.
func TestExternalSealRender(t *testing.T) {
	p := serverPaths{StoreCA: "/t/ca.pem", ServerCert: "/t/c.pem", ServerKey: "/t/k.pem", SealKey: "/t/seal/seal-key", Storage: "/t/data", ExternalSeal: true}
	hcl := renderServerHCL(p, 18299)
	if strings.Contains(hcl, "seal") {
		t.Errorf("the ExternalSeal main config holds a seal stanza:\n%s", hcl)
	}
	const id = "rasputin-0f1e2d3c-4b5a-4968-8776-655443322110"
	want := "seal \"static\" {\n  current_key_id = \"" + id + "\"\n  current_key    = \"file:///t/seal/seal-key\"\n}\n"
	if got := string(renderSealFragment(id, p.SealKey)); got != want {
		t.Errorf("fragment =\n%s\nwant\n%s", got, want)
	}

	h := &Harness{cfg: Config{Rand: bytes.NewReader(bytes.Repeat([]byte{0xff}, 16))}}
	got, err := h.keyID()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^rasputin-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(got) {
		t.Errorf("key id %q is not rasputin-<v4 uuid>", got)
	}
	h = &Harness{cfg: Config{Rand: bytes.NewReader(nil)}}
	if _, err := h.keyID(); err == nil {
		t.Error("an empty Rand made a key id")
	}
}

// StartNoWait refuses a store that still runs, as Restart does.
func TestStartNoWait_RefusesARunningStore(t *testing.T) {
	s := &Store{exited: make(chan struct{})}
	if err := s.StartNoWait(t.Context()); err == nil || !strings.Contains(err.Error(), "still running") {
		t.Errorf("StartNoWait on a running store = %v", err)
	}
	if !s.Running() {
		t.Error("Running = false for a store whose process has not exited")
	}
	close(s.exited)
	if s.Running() {
		t.Error("Running = true after the process exited")
	}
}
