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
// CryptRounds is the stretch, and the api mints one value for the whole
// fleet: a cluster half on one round count and half on another is invisible
// until someone needs a console.
//
// 100,000, not crypt(3)'s 5,000 default. The default is what CodeQL's
// weak-password-hashing query is really objecting to, and it is right to:
// 5,000 rounds of SHA-512 is about 3 ms to try a candidate on a 2026 laptop,
// so an /etc/shadow that leaks is a wordlist away from a console login.
//
// The ceiling is what a node spends VERIFYING it, at the console, on the
// slowest hardware in a cluster. Measured 2026-09-19 on an x86 dev host:
// BusyBox 1.37 (the firewall image's crypt) takes ~0.09 s at 100,000 and
// ~0.42 s at 200,000; this package takes ~70 ms and ~187 ms. A Pi 4 is
// several times slower again, which puts 100,000 around a second there and
// 200,000 well past what anyone would sit through at a serial console.
//
// The "rounds=" form is portable, which is why this is not simply left at
// the default: BusyBox 1.37 and glibc produce BYTE-IDENTICAL output for
// "$6$rounds=100000$<salt>$..." (checked both ways, 2026-09-19), and the
// firewall image's set-root-hash accepts it. Both are pinned as vectors in
// sha512crypt_test.go, so a change on either side fails the build rather
// than a console.
//
// Raising it later is a password change, not a migration: the operator sets
// a new one and the push job delivers it. Nothing re-hashes in place,
// because nothing here ever holds the password again.
const CryptRounds = 100000

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

// sha512Crypt returns the hash of password under salt at CryptRounds.
// salt must already be 1..16 characters of crypt's alphabet.
func sha512Crypt(password, salt []byte) string {
	return sha512CryptRounds(password, salt, CryptRounds)
}

// sha512CryptRounds is the algorithm itself, at an explicit round count, so
// the published default-rounds vectors and the rounds= ones are both
// checkable against it.
func sha512CryptRounds(password, salt []byte, rounds int) string {
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

	// THE STRETCH, and the answer to CodeQL's go/weak-sensitive-data-hashing
	// on the sha512.New() calls in this function (.github/codeql-register.tsv).
	// The query flags SHA-512 as "not a computationally expensive hash
	// function" and is right about the primitive; it cannot see this loop,
	// which is the whole construction. crypt(3) SHA-512 is CryptRounds
	// iterations of it over a per-password salt.
	//
	// TRIP-WIRE: that verdict is void if this loop is removed or short-
	// circuited, or if CryptRounds is lowered — then it really would be a
	// bare digest over a password, and the register row must be reopened.
	c := a
	for r := 0; r < rounds; r++ {
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

	// The spec omits the field entirely at the default count, and every
	// implementation writes it that way — so the default form is emitted
	// as the default form, which is what makes the published vectors
	// comparable.
	prefix := "$6$"
	if rounds != 5000 {
		prefix = fmt.Sprintf("$6$rounds=%d$", rounds)
	}
	return prefix + string(salt) + "$" + encode(c)
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
