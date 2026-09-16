package proto

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// The cluster bus is TLS, and a node trusts the controlplane's end of it by a
// PIN: the SHA-256 of the bus key's public half, nothing else
// (geekdojo/geekdojo-brain#448, docs/bus-tls-contract.md).
//
// Why a pin and not a CA chain, in one line each — the issue has the long
// form: a CA change (wipe, restore onto a reflashed box, rotation) would lock
// the fleet out with no channel left to deliver new trust; certificate
// validity would make bus membership depend on node clocks, and a Pi boots
// before NTP with no battery-backed clock; and matched sets are generated
// offline, before any mesh CA exists. So the check looks at the key and
// ignores the certificate around it: no chain, no hostname, no dates.
//
// The encoding is HPKP's pin-sha256 (RFC 7469 §2.4): standard base64 of the
// SHA-256 of the DER SubjectPublicKeyInfo. It is the same value
// `curl --pinnedpubkey sha256//…` takes, and an operator can recompute it
// from the key file on the controlplane with stock openssl:
//
//	base64 -d < /var/lib/rasputin/bus/bus.key | openssl pkey -inform der -pubout -outform der \
//	  | openssl dgst -sha256 -binary | base64
//
// The prefix names the hash so a future algorithm is a new prefix, not a
// reinterpretation of an old value.

// BusPinPrefix introduces a bus pin. The one algorithm there is.
const BusPinPrefix = "sha256/"

// MetadataBusTLS is the registration-metadata key under which an agent reports
// whether the connection it is registering over is TLS with the pin verified.
// true only then; false for a plaintext connection. Absent from a pre-TLS
// agent's registration, and consumers must treat absence as "not TLS" — the
// switch to TLS-required waits for every node to say true, and a node that
// cannot say anything has not.
const MetadataBusTLS = "busTls"

// BusPinVerb is the agent command that delivers the pin to an already-enrolled
// node: rasputin.node.<id>.cmd.bus.pin.
const BusPinVerb = "bus.pin"

// BusPinCmd carries the pin. It travels over the bus the node is connected to
// right now, which during migration is plaintext — accepted by Bryce for the
// migration window (#448, decided design step 4).
type BusPinCmd struct {
	Pin string `json:"pin"`
}

// BusPinAck is the agent's answer.
//
// OK means the node now holds exactly this pin, persisted, and is about to
// reconnect over TLS (Reconnecting) or already is connected over it. A node
// that holds a DIFFERENT pin refuses (OK=false): replacing a pin is key
// rotation, which the server cannot serve (it holds one key), so accepting
// would strand the node.
type BusPinAck struct {
	NodeID string `json:"nodeId"`
	OK     bool   `json:"ok"`
	// Pin is the pin the node holds after handling the command ("" if none).
	Pin string `json:"pin,omitempty"`
	// Reconnecting is true when the node persisted a new pin and is dropping
	// its current connection to come back over TLS.
	Reconnecting bool   `json:"reconnecting,omitempty"`
	Detail       string `json:"detail,omitempty"`
}

// BusPinForSPKI returns the pin for a DER SubjectPublicKeyInfo.
func BusPinForSPKI(spkiDER []byte) string {
	sum := sha256.Sum256(spkiDER)
	return BusPinPrefix + base64.StdEncoding.EncodeToString(sum[:])
}

// BusPinForPublicKey returns the pin for a public key (*ecdsa.PublicKey,
// ed25519.PublicKey, *rsa.PublicKey).
func BusPinForPublicKey(pub any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("bus pin: marshal public key: %w", err)
	}
	return BusPinForSPKI(der), nil
}

// ErrBusPinFormat is wrapped by every ParseBusPin failure.
var ErrBusPinFormat = errors.New(`bus pin must be "sha256/" followed by the standard base64 of a 32-byte SHA-256 (44 characters)`)

// ParseBusPin validates a pin and returns its digest. Surrounding whitespace
// is trimmed (env files and UCI values carry it); anything else that is not
// the exact canonical form is refused rather than repaired — a pin is compared
// byte for byte, and one "fixed" into a different digest would be a node that
// can never connect with nothing saying why.
func ParseBusPin(s string) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	s = strings.TrimSpace(s)
	rest, ok := strings.CutPrefix(s, BusPinPrefix)
	if !ok {
		return out, fmt.Errorf("%w (got %q)", ErrBusPinFormat, s)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(rest)
	if err != nil || len(raw) != sha256.Size {
		return out, fmt.Errorf("%w (got %q)", ErrBusPinFormat, s)
	}
	copy(out[:], raw)
	return out, nil
}

// BusPinMatchesSPKI reports whether a DER SubjectPublicKeyInfo hashes to the
// digest ParseBusPin returned. Constant-time, out of habit rather than need —
// the pin is public.
func BusPinMatchesSPKI(want [sha256.Size]byte, spkiDER []byte) bool {
	got := sha256.Sum256(spkiDER)
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}
