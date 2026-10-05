package sl01

import "github.com/geekdojo/rasputin-control-plane/secret"

type revealer interface{ Reveal() []byte }

type unrelated struct{}

func (unrelated) Reveal() []byte { return nil }

type other interface{ Reveal() string }

// spelled is satisfied by secret.Value: []uint8 is []byte to the type
// checker.
type spelled interface{ Reveal() []uint8 }

type holder struct{ secret.Value }

type Session struct{ key secret.Value }

func (s *Session) Open() []byte {
	return s.key.Reveal() // want `SL01 Session.Open: secret.Value.Reveal`
}

func Calls(v secret.Value, r revealer, u unrelated, o other, h holder, sp spelled) {
	_ = v.Reveal()                 // want "SL01"
	f := v.Reveal                  // want "SL01"
	_ = secret.Value.Reveal(v)     // want "SL01"
	_ = (*secret.Value).Reveal(&v) // want "SL01"
	_ = r.Reveal()                 // want "SL01"
	_ = h.Reveal()                 // want "SL01"
	_ = sp.Reveal()                // want "SL01"
	_ = u.Reveal()
	_ = o.Reveal()
	_ = f
	_ = v.Len()
	_ = v.String()
}

func Generic[T revealer](t T) []byte {
	return t.Reveal() // want "SL01"
}

// byteSet's type set holds only types whose underlying type is []byte, so a
// secret.Value can never be its T. The exact types.Implements path sees the
// type term; the method-set fallback for packages that cannot see Value does
// not, so this stays silent only when the package's own Value is found.
func ByteSet[T interface {
	~[]byte
	Reveal() []byte
}](t T) []byte {
	return t.Reveal()
}

var held secret.Value

// A Reveal in a package-level initializer is named for the variable.
var leaked = held.Reveal() // want `SL01 leaked: secret.Value.Reveal`
