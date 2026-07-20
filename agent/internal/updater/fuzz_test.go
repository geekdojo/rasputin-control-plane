package updater

import "testing"

// FuzzParseGrubenv fuzzes the grubenv block parser. grubenv is read from the
// ESP at boot to decide the A/B slot; a corrupt/truncated/adversarial block
// must parse without panicking. Step 5, Go-native fuzzing of untrusted-input
// parsers.
func FuzzParseGrubenv(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("# GRUB Environment Block\n"))
	f.Add([]byte("# GRUB Environment Block\nrasputin_slot=b\nrasputin_try=1\n"))
	f.Add([]byte("# GRUB Environment Block\n=noKeyName\nkeyonly\n#####"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = parseGrubenv(b)
	})
}
