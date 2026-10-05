package sl01

import "github.com/geekdojo/rasputin-control-plane/secret"

type revealer interface{ Reveal() []byte }

type unrelated struct{}

func (unrelated) Reveal() []byte { return nil }

type other interface{ Reveal() string }

type holder struct{ secret.Value }

type Session struct{ key secret.Value }

func (s *Session) Open() []byte {
	return s.key.Reveal() // want `SL01 Session.Open: secret.Value.Reveal`
}

func Calls(v secret.Value, r revealer, u unrelated, o other, h holder) {
	_ = v.Reveal()                 // want "SL01"
	f := v.Reveal                  // want "SL01"
	_ = secret.Value.Reveal(v)     // want "SL01"
	_ = (*secret.Value).Reveal(&v) // want "SL01"
	_ = r.Reveal()                 // want "SL01"
	_ = h.Reveal()                 // want "SL01"
	_ = u.Reveal()
	_ = o.Reveal()
	_ = f
	_ = v.Len()
	_ = v.String()
}

func Generic[T revealer](t T) []byte {
	return t.Reveal() // want "SL01"
}
