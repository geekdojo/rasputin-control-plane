package quiesce

import (
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// refusalFor and restoreRefusalFor map an error onto the wire refusal code the
// api and UI branch on. Two properties are load-bearing and were untested:
//
//   - a nil error (a successful verb) MUST map to "" — no refusal — not to the
//     catch-all backend-error code;
//   - a recognised error MUST map to its own specific code.
//
// A mutation of the leading `err == nil` guard to `err != nil` breaks both at
// once: it would send every success through the default arm (a spurious
// refusal) AND short-circuit every real error to "" (a refusal silently
// dropped). Asserting a nil and a recognised error each map correctly pins it.
func TestRefusalFor_NilIsNoRefusal(t *testing.T) {
	if got := refusalFor(nil); got != "" {
		t.Errorf("refusalFor(nil) = %q, want %q (a success is not a refusal)", got, "")
	}
	if got := refusalFor(ErrUnsupported); got != proto.BackupRefusalQuiesceUnsupported {
		t.Errorf("refusalFor(ErrUnsupported) = %q, want %q", got, proto.BackupRefusalQuiesceUnsupported)
	}

	if got := restoreRefusalFor(nil); got != "" {
		t.Errorf("restoreRefusalFor(nil) = %q, want %q (a success is not a refusal)", got, "")
	}
	if got := restoreRefusalFor(ErrClassNotRestored); got != proto.BackupRefusalClassNotRestored {
		t.Errorf("restoreRefusalFor(ErrClassNotRestored) = %q, want %q", got, proto.BackupRefusalClassNotRestored)
	}
}
