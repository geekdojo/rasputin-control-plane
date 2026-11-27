//go:build !linux

package breakglass

import "testing"

// Off Linux the peer's uid can't be read, so every peer is refused.
func TestPeerUID_RefusesOffLinux(t *testing.T) {
	if _, err := PeerUID(nil); err == nil {
		t.Fatal("PeerUID read a uid off Linux")
	}
}
