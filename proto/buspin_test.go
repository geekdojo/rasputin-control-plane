package proto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"
)

// A fixed vector: the pin of an empty SPKI is the base64 of SHA-256(""),
// which anyone can reproduce with `printf ” | openssl dgst -sha256 -binary |
// base64`. Pins the encoding (standard base64, padded, "sha256/" prefix)
// independently of this package's own round trip.
func TestBusPinForSPKI_KnownVector(t *testing.T) {
	const want = "sha256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
	if got := BusPinForSPKI(nil); got != want {
		t.Fatalf("BusPinForSPKI(empty) = %q, want %q", got, want)
	}
}

func TestParseBusPin_RoundTripAndMatch(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	pin, err := BusPinForPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	if pin != BusPinForSPKI(spki) {
		t.Fatalf("BusPinForPublicKey and BusPinForSPKI disagree: %s vs %s", pin, BusPinForSPKI(spki))
	}
	digest, err := ParseBusPin(" " + pin + "\n")
	if err != nil {
		t.Fatalf("ParseBusPin(%q): %v", pin, err)
	}
	if digest != sha256.Sum256(spki) {
		t.Fatal("parsed digest is not the SPKI's SHA-256")
	}
	if !BusPinMatchesSPKI(digest, spki) {
		t.Fatal("BusPinMatchesSPKI rejected the key it was made from")
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherSPKI, err := x509.MarshalPKIXPublicKey(other.Public())
	if err != nil {
		t.Fatal(err)
	}
	if BusPinMatchesSPKI(digest, otherSPKI) {
		t.Fatal("BusPinMatchesSPKI accepted a different key")
	}
}

// Anything but the exact canonical form is refused, never repaired.
func TestParseBusPin_RefusesNonCanonical(t *testing.T) {
	const good = "sha256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
	for _, bad := range []string{
		"",
		"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",                                 // no prefix
		"sha256//47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",                         // curl's double slash
		"SHA256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",                          // prefix case
		"sha256/47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU=",                          // URL alphabet
		"sha256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU",                           // unpadded
		"sha256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSu",                             // short
		"sha256/" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // hex
		"sha1/2jmj7l5rSw0yVb/vlWAYkK/YBwk=",
		good + "AA==",
	} {
		if _, err := ParseBusPin(bad); !errors.Is(err, ErrBusPinFormat) {
			t.Errorf("ParseBusPin(%q) = %v, want ErrBusPinFormat", bad, err)
		}
	}
	if _, err := ParseBusPin(good); err != nil {
		t.Fatalf("ParseBusPin(%q): %v", good, err)
	}
}
