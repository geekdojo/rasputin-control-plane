package proto

import "testing"

// The api fingerprints the PEM it holds in memory; the agent fingerprints the
// file it wrote, which installMeshCA terminates with one newline. The two must
// agree, or every node would read as stale forever.
func TestMeshCAFingerprintIgnoresSurroundingWhitespace(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
	want := MeshCAFingerprint([]byte(pem))
	if want == "" || len(want) != 64 {
		t.Fatalf("fingerprint = %q, want 64 hex chars", want)
	}
	for _, variant := range []string{pem + "\n", "\n" + pem + "\n\n", pem + "  \n"} {
		if got := MeshCAFingerprint([]byte(variant)); got != want {
			t.Errorf("fingerprint(%q) = %s, want %s", variant, got, want)
		}
	}
	if got := MeshCAFingerprint([]byte(pem + "x")); got == want {
		t.Error("a different PEM must fingerprint differently")
	}
}

// Nothing fingerprints to nothing — and nothing must never compare equal to a
// node's report, or an api with no CA configured would re-deliver an empty
// one to every node reporting "none".
func TestMeshCAFingerprintEmptyIsEmpty(t *testing.T) {
	for _, in := range [][]byte{nil, {}, []byte("  \n\t")} {
		if got := MeshCAFingerprint(in); got != "" {
			t.Errorf("fingerprint(%q) = %q, want empty", in, got)
		}
	}
	if MeshCAFingerprint(nil) == MeshCAFingerprintNone {
		t.Error("empty must not equal the none sentinel")
	}
}

func TestShortFingerprint(t *testing.T) {
	if got := ShortFingerprint("0123456789abcdef"); got != "0123456789ab" {
		t.Errorf("short = %q", got)
	}
	if got := ShortFingerprint("abc"); got != "abc" {
		t.Errorf("short short = %q", got)
	}
}
