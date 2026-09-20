package console

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
)

// crypt(3) SHA-512, the hash the console root password travels as.
//
// Written here rather than pulled in as a dependency: it is ~80 lines of a
// frozen, fully specified algorithm (Ulrich Drepper, "Unix crypt using
// SHA-256 and SHA-512"), and the alternative is a new module in the api's
// supply chain for one function. Because it is hand-rolled spec code it is
// checked against real implementations rather than against itself —
// sha512crypt_test.go runs the specification's own published vectors, and
// the functional check cross-checks freshly minted hashes against BusyBox's
// `mkpasswd -m sha512` (the firewall image's crypt) and OpenSSL's
// `passwd -6`.
//
// Default rounds only. See proto.ConsoleRootHashCmd for why the fleet does
// not carry a "$6$rounds=N$" variant.

// cryptRounds is the default round count every crypt(3) SHA-512
// implementation uses when the hash carries no "rounds=" field.
const cryptRounds = 5000

// saltLen is the full 16 characters the format allows.
const saltLen = 16

// b64 is crypt(3)'s alphabet — NOT standard base64, and not
// interchangeable with it.
const b64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// permutation is the byte order the SHA-512 variant emits its digest in
// (the spec's b64_from_24bit call sequence). Each entry is one 24-bit
// group, most significant byte first; the last group is two bytes short and
// emits two characters rather than four.
var permutation = [21][3]int{
	{0, 21, 42}, {22, 43, 1}, {44, 2, 23}, {3, 24, 45}, {25, 46, 4},
	{47, 5, 26}, {6, 27, 48}, {28, 49, 7}, {50, 8, 29}, {9, 30, 51},
	{31, 52, 10}, {53, 11, 32}, {12, 33, 54}, {34, 55, 13}, {56, 14, 35},
	{15, 36, 57}, {37, 58, 16}, {59, 17, 38}, {18, 39, 60}, {40, 61, 19},
	{62, 20, 41},
}

// newSalt returns saltLen random characters from crypt's alphabet. The
// alphabet has 64 entries, so a byte masked to 6 bits indexes it without
// modulo bias.
func newSalt() (string, error) {
	raw := make([]byte, saltLen)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("console: salt: %w", err)
	}
	out := make([]byte, saltLen)
	for i, b := range raw {
		out[i] = b64[b&0x3f]
	}
	return string(out), nil
}

// sha512Crypt returns the "$6$<salt>$<digest>" hash of password under salt,
// at the default round count. salt must already be 1..16 characters of
// crypt's alphabet.
func sha512Crypt(password, salt []byte) string {
	// B = SHA512(password || salt || password)
	bh := sha512.New()
	bh.Write(password)
	bh.Write(salt)
	bh.Write(password)
	b := bh.Sum(nil)

	// A = SHA512(password || salt || B-to-the-length-of-the-password ||
	//            one bit of B-or-password per bit of len(password))
	ah := sha512.New()
	ah.Write(password)
	ah.Write(salt)
	for i := len(password); i > 0; i -= sha512.Size {
		if i > sha512.Size {
			ah.Write(b)
		} else {
			ah.Write(b[:i])
		}
	}
	for i := len(password); i > 0; i >>= 1 {
		if i&1 != 0 {
			ah.Write(b)
		} else {
			ah.Write(password)
		}
	}
	a := ah.Sum(nil)

	// DP = SHA512(password repeated len(password) times), cut to the
	// length of the password.
	dph := sha512.New()
	for range password {
		dph.Write(password)
	}
	p := repeatDigest(dph.Sum(nil), len(password))

	// DS = SHA512(salt repeated 16+A[0] times), cut to the length of the
	// salt. A[0] makes the count depend on the password.
	dsh := sha512.New()
	for i := 0; i < 16+int(a[0]); i++ {
		dsh.Write(salt)
	}
	s := repeatDigest(dsh.Sum(nil), len(salt))

	// The stretch. Each round mixes the previous digest with the password
	// and salt sequences in an order driven by the round number.
	c := a
	for r := 0; r < cryptRounds; r++ {
		h := sha512.New()
		if r%2 != 0 {
			h.Write(p)
		} else {
			h.Write(c)
		}
		if r%3 != 0 {
			h.Write(s)
		}
		if r%7 != 0 {
			h.Write(p)
		}
		if r%2 != 0 {
			h.Write(c)
		} else {
			h.Write(p)
		}
		c = h.Sum(nil)
	}

	return "$6$" + string(salt) + "$" + encode(c)
}

// repeatDigest returns n bytes of digest, repeating it as needed.
func repeatDigest(digest []byte, n int) []byte {
	out := make([]byte, 0, n)
	for len(out) < n {
		take := n - len(out)
		if take > len(digest) {
			take = len(digest)
		}
		out = append(out, digest[:take]...)
	}
	return out
}

// encode writes a 64-byte digest as crypt(3)'s 86-character base64, in the
// SHA-512 variant's byte order.
func encode(c []byte) string {
	out := make([]byte, 0, 86)
	emit := func(w uint32, n int) {
		for ; n > 0; n-- {
			out = append(out, b64[w&0x3f])
			w >>= 6
		}
	}
	for _, g := range permutation {
		emit(uint32(c[g[0]])<<16|uint32(c[g[1]])<<8|uint32(c[g[2]]), 4)
	}
	emit(uint32(c[63]), 2)
	return string(out)
}
