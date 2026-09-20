package console

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// MinPasswordLen is the shortest console root password the api will hash.
//
// It is a break-glass credential, not the product's front door — the front
// door is a passkey — but it is the credential that answers a serial console
// and a BMC serial-over-LAN session, where there is no rate limit and no
// lockout. Twelve characters is the floor Bryce's other operator-chosen
// secrets use; nothing here caps it.
const MinPasswordLen = 12

// MaxPasswordLen bounds what one request can be asked to hash. crypt(3)
// SHA-512 has no length limit of its own, but the cost of the first digest
// grows with the square of the password length (the spec adds the password
// to a digest once per byte of it), so an unbounded value is a CPU cost an
// unauthenticated-looking request should not be able to choose.
const MaxPasswordLen = 256

// ErrPasswordTooShort, ErrPasswordTooLong and ErrPasswordCharacters are the
// three refusals SetPassword can return. Handlers map all three to 400.
var (
	ErrPasswordTooShort   = fmt.Errorf("console root password must be at least %d characters", MinPasswordLen)
	ErrPasswordTooLong    = fmt.Errorf("console root password must be at most %d characters", MaxPasswordLen)
	ErrPasswordCharacters = errors.New("console root password must be printable text on one line (no tabs, newlines or other control characters)")
	ErrPasswordNotUTF8    = errors.New("console root password is not valid UTF-8")
	// ErrNoPassword is what the push job fails with when no password has
	// been set yet: there is nothing to deliver, and an empty hash must
	// never be dispatched (it would lock or open every root account).
	ErrNoPassword = errors.New("no console root password has been set — set one in Settings before pushing")
)

// ValidatePassword reports why a password cannot be used, or nil.
//
// The character rule is about the console, not about strength: what the
// operator types here has to be typable again on a serial terminal that
// offers no clipboard, so a control character (an accidental tab or a
// pasted newline) is a password nobody can enter. Everything printable —
// including spaces inside the password and any non-ASCII text — is allowed;
// the hash is over the UTF-8 bytes, which is what both images' crypt reads.
func ValidatePassword(password string) error {
	if !utf8.ValidString(password) {
		return ErrPasswordNotUTF8
	}
	if n := utf8.RuneCountInString(password); n < MinPasswordLen {
		return ErrPasswordTooShort
	} else if n > MaxPasswordLen {
		return ErrPasswordTooLong
	}
	for _, r := range password {
		if r == ' ' {
			continue
		}
		if unicode.IsControl(r) || r == 0xFEFF {
			return ErrPasswordCharacters
		}
	}
	if strings.TrimSpace(password) == "" {
		return ErrPasswordCharacters
	}
	return nil
}

// HashPassword validates password and returns the crypt(3) SHA-512 hash
// under a fresh random salt, plus proto.ConsoleRootHashID of it.
//
// The plaintext goes no further than this call: nothing returned, logged or
// stored derives from it except the hash, and the hash itself is treated as
// secret from here on (see Store).
func HashPassword(password string) (hash, hashID string, err error) {
	if err := ValidatePassword(password); err != nil {
		return "", "", err
	}
	salt, err := newSalt()
	if err != nil {
		return "", "", err
	}
	hash = sha512Crypt([]byte(password), []byte(salt))
	// Belt and braces: the api refuses to store or dispatch a hash that
	// would not pass the wire check, so a bug in the encoder surfaces here
	// rather than on a node's shadow file.
	if err := proto.ValidConsoleRootHash(hash); err != nil {
		return "", "", fmt.Errorf("console: minted hash is malformed: %w", err)
	}
	return hash, proto.ConsoleRootHashID(hash), nil
}
