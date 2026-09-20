package console

import (
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Hand-rolled spec code is checked against other implementations, never
// against itself. The first two cases are the specification's own published
// vectors (Drepper, "Unix crypt using SHA-256 and SHA-512"); every case was
// independently reproduced with `openssl passwd -6 -salt <salt> <password>`
// (LibreSSL 3.3.6 on macOS) and the first with BusyBox 1.37's
// `mkpasswd -m sha512 -S saltstring`, which is the firewall image's crypt.
// The two agreed byte for byte.
var cryptVectors = []struct {
	salt, password, want string
}{
	{
		"saltstring", "Hello world!",
		"$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
	},
	{
		"toolongsaltstrin", "This is just a test",
		"$6$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0",
	},
	{
		// Spaces, and a password longer than one SHA-512 block — the case
		// the length-driven mixing steps get wrong when misread.
		"abcd0123ABCD./xy", "a very long password with spaces in it",
		"$6$abcd0123ABCD./xy$bRitHeSCsIbzGLutkdHvUYCfND6JlYEGhzL4keRiMM9WcxA9T6dsx54NjhNmFp4IOfClcNpic13kp8W3d4HC10",
	},
	{
		// One-character salt: the salt sequence is shorter than a digest.
		"z", "short salt",
		"$6$z$Bn5.8SyqNRiuUlcKF/QvIWJnxe/MMIuHATD.3YoNPfzKOKikp5g/zJIOk5BT/DJdrZ0CLb/.d.mS.JLs/Oq2k.",
	},
	{
		// Non-ASCII: the hash is over UTF-8 bytes, which is what the
		// images' crypt reads.
		"0123456789abcdef", "üñïçödé påsswörd",
		"$6$0123456789abcdef$g3yUZFYEDUpGk7I/.qgTH/M3Q3bdiBqO3xazVG859kgy9ANNMAO2IEES5HoyCwlVItjimdi6DNU.zPtlhXxNG/",
	},
}

func TestSHA512CryptMatchesReferenceVectors(t *testing.T) {
	for _, v := range cryptVectors {
		got := sha512CryptRounds([]byte(v.password), []byte(v.salt), 5000)
		if got != v.want {
			t.Errorf("salt %q password %q:\n got %q\nwant %q", v.salt, v.password, got, v.want)
		}
		if err := proto.ValidConsoleRootHash(got); err != nil {
			t.Errorf("salt %q: reference vector fails the wire check: %v", v.salt, err)
		}
	}
}

// The round count the api actually mints. These vectors were produced
// independently by BusyBox 1.37 (`mkpasswd -m sha512 -S "rounds=100000$<salt>"`),
// the firewall image's crypt, and by glibc (`mkpasswd -m sha512crypt -R
// 100000 -S <salt>`), the Buildroot OS's — byte-identical, both ways,
// 2026-09-19. They are what makes CryptRounds a portable choice rather than
// a hopeful one: if either implementation ever stops agreeing, this fails
// instead of a console does.
var cryptRoundsVectors = []struct {
	salt, password, want string
}{
	{
		"saltstring", "Hello world!",
		"$6$rounds=100000$saltstring$9s1nPRwOKo4FeNBCK5BUtBm4SG17hIi1AdBjtdwEAoIS.4ckJW8FPR8goM6zZZeHEFTq2BK/BQz3f/G/Yjbkg/",
	},
	{
		"0123456789abcdef", "a perfectly fine console password",
		"$6$rounds=100000$0123456789abcdef$iJ7fHUuAH7szYrYSsd9VSIo1lThtOcStIyubkK8vpm1ghu1.q5O4I1sN5Ci3sND5foG/iO89FuDGxs1JHvMFs/",
	},
}

func TestSHA512CryptAtTheRoundCountWeMint(t *testing.T) {
	if CryptRounds != 100000 {
		t.Fatalf("CryptRounds is %d; these vectors are for 100000 — regenerate them against BusyBox and glibc before changing it", CryptRounds)
	}
	for _, v := range cryptRoundsVectors {
		got := sha512CryptRounds([]byte(v.password), []byte(v.salt), CryptRounds)
		if got != v.want {
			t.Errorf("salt %q password %q:\n got %q\nwant %q", v.salt, v.password, got, v.want)
		}
		if err := proto.ValidConsoleRootHash(got); err != nil {
			t.Errorf("salt %q: fails the wire check: %v", v.salt, err)
		}
	}
	// And what HashPassword mints carries the round count, so a node is
	// never handed the 5,000-round default by accident.
	h, _, err := HashPassword("a perfectly fine console password")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$6$rounds=100000$") {
		t.Fatalf("minted hash is not at the fleet round count: %q", h[:24])
	}
}

// Every password length from 0 to two digest blocks exercises the two
// length-driven steps (the B-to-the-length-of-the-password loop and the
// bitwise one), which is where a misreading of the spec hides. At the
// default count, so a failure here is the algorithm and not the stretch.
func TestSHA512CryptLengthSweepIsSelfConsistent(t *testing.T) {
	const salt = "0123456789abcdef"
	seen := map[string]int{}
	for n := 0; n <= 130; n++ {
		pw := strings.Repeat("x", n)
		got := sha512CryptRounds([]byte(pw), []byte(salt), 5000)
		if len(got) != len("$6$"+salt+"$")+86 {
			t.Fatalf("len %d: hash is %d characters: %q", n, len(got), got)
		}
		if prev, dup := seen[got]; dup {
			t.Fatalf("passwords of length %d and %d hash the same", prev, n)
		}
		seen[got] = n
	}
}

func TestNewSaltIsFreshAndInAlphabet(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		s, err := newSalt()
		if err != nil {
			t.Fatal(err)
		}
		if len(s) != saltLen {
			t.Fatalf("salt %q: want %d characters", s, saltLen)
		}
		for _, r := range s {
			if !strings.ContainsRune(b64, r) {
				t.Fatalf("salt %q has %q, which is not in crypt's alphabet", s, r)
			}
		}
		if seen[s] {
			t.Fatalf("salt %q was minted twice in 64 draws", s)
		}
		seen[s] = true
	}
}

func TestHashPasswordMintsAWireValidHashWithAFreshSalt(t *testing.T) {
	const pw = "a perfectly fine console password"
	h1, id1, err := HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := proto.ValidConsoleRootHash(h1); err != nil {
		t.Fatalf("minted hash fails the wire check: %v", err)
	}
	if id1 != proto.ConsoleRootHashID(h1) {
		t.Fatalf("id %q does not name hash %q", id1, h1)
	}
	if strings.Contains(h1, pw) {
		t.Fatal("the hash contains the password")
	}
	h2, id2, err := HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if h2 == h1 || id2 == id1 {
		t.Fatal("two hashes of the same password are identical — the salt is not fresh")
	}
}

func TestValidatePassword(t *testing.T) {
	ok := []string{
		"a perfectly fine one",
		"twelve chars",
		"påsswörd with ünicode",
		strings.Repeat("x", MaxPasswordLen),
	}
	for _, pw := range ok {
		if err := ValidatePassword(pw); err != nil {
			t.Errorf("%q was refused: %v", pw, err)
		}
	}
	bad := map[string]string{
		"empty":        "",
		"eleven":       strings.Repeat("x", MinPasswordLen-1),
		"too long":     strings.Repeat("x", MaxPasswordLen+1),
		"newline":      "has a newline\nin it",
		"carriage ret": "has a return\rin it",
		"tab":          "has a tab\tin it",
		"nul":          "has a nul\x00in it",
		"all spaces":   strings.Repeat(" ", MinPasswordLen+2),
		"escape":       "has an escape\x1bin it",
	}
	for name, pw := range bad {
		if err := ValidatePassword(pw); err == nil {
			t.Errorf("%s: %q was accepted", name, pw)
		}
	}
	if _, _, err := HashPassword("short"); err == nil {
		t.Error("HashPassword accepted a too-short password")
	}
}
