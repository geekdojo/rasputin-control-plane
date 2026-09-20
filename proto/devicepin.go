package proto

import (
	"crypto/sha256"
	"crypto/x509"
)

// External devices — a chassis BMC today — are trusted by the SAME pin as the
// cluster bus: the SHA-256 of the DER SubjectPublicKeyInfo the peer presents,
// encoded as HPKP's pin-sha256 (RFC 7469 §2.4), with the "sha256/" prefix
// naming the algorithm. One encoding across Rasputin, so an operator reading a
// pin anywhere reads the same kind of value, and so a future algorithm is a new
// prefix rather than a reinterpretation of an old value.
//
// It pins the KEY, not the certificate. That is what makes it usable against a
// board whose certificate is self-signed and minted at the epoch — permanently
// expired, so no chain or validity check can ever pass — and it survives the
// board re-issuing a certificate for the same key.
//
// A cert-DER pin was considered instead, on the premise that the operator
// could compare the digest against one the board's own web UI displays. The
// probe of that premise (geekdojo/geekdojo-brain#473) found the Turing Pi BMC
// web UI shows no certificate fingerprint in any form, so there is nothing to
// compare against and the reason for the second pin form went with it.

// DevicePinPrefix introduces an external-device pin. Deliberately the same
// prefix, and the same value for the same key, as a bus pin.
const DevicePinPrefix = BusPinPrefix

// DevicePinForCert returns the pin for a presented certificate.
func DevicePinForCert(cert *x509.Certificate) string {
	return BusPinForSPKI(cert.RawSubjectPublicKeyInfo)
}

// DevicePinForSPKI returns the pin for a DER SubjectPublicKeyInfo.
func DevicePinForSPKI(spkiDER []byte) string { return BusPinForSPKI(spkiDER) }

// ParseDevicePin validates a pin and returns its digest. Surrounding
// whitespace is trimmed; anything else that is not the exact canonical form is
// refused rather than repaired, for the reason ParseBusPin gives.
func ParseDevicePin(s string) ([sha256.Size]byte, error) { return ParseBusPin(s) }

// DevicePinMatchesSPKI reports whether a DER SubjectPublicKeyInfo hashes to
// the digest ParseDevicePin returned.
func DevicePinMatchesSPKI(want [sha256.Size]byte, spkiDER []byte) bool {
	return BusPinMatchesSPKI(want, spkiDER)
}
