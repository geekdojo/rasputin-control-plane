package bytesize

import "testing"

// TC-1011-18: the shared formatter gives the strings storage's humanBytes gave
// before it moved here, so every storage message and the updater's
// memory-floor sentences render sizes the same way.
func TestFormat_KeepsStoragesOutputs(t *testing.T) {
	const (
		kib = uint64(1) << 10
		mib = uint64(1) << 20
		gib = uint64(1) << 30
		pib = uint64(1) << 50
	)
	for _, c := range []struct {
		in   uint64
		want string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{kib, "1.0 KiB"},
		{928 * mib, "928.0 MiB"},
		{3994 * mib, "3.9 GiB"},
		{3584 * mib, "3.5 GiB"},
		{pib, "1.0 PiB"},
		// The unit stops at PiB: a larger count is still PiB, never an
		// index past the end of the unit letters.
		{2048 * pib, "2048.0 PiB"},
	} {
		if got := Format(c.in); got != c.want {
			t.Errorf("Format(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}
