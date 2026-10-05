// Package noimport cannot see secret.Value, but one can still arrive through
// an interface it satisfies.
package noimport

import "log/slog"

type revealer interface{ Reveal() []byte }

type wider interface {
	Reveal() []byte
	Len() int
}

type notValue interface {
	Reveal() []byte
	Rotate()
}

// F-732-09: the fallback compares types, not spellings. []uint8 and an alias
// of []byte are identical to []byte, so Value satisfies these.
type uint8Revealer interface{ Reveal() []uint8 }

type B = []byte

type aliasRevealer interface{ Reveal() B }

// A defined type is not identical to []byte, so Value does not satisfy this.
type D []byte

type definedRevealer interface{ Reveal() D }

type stringRevealer interface{ Reveal() string }

// A named type from another package matches by its package and name: slog.Value
// is LogValue's result, a local type named Value is not.
type logValuer interface {
	Reveal() []byte
	LogValue() slog.Value
}

type Value struct{}

type localLogValuer interface {
	Reveal() []byte
	LogValue() Value
}

func Use(r revealer, w wider, n notValue) {
	_ = r.Reveal() // want "SL01"
	_ = w.Reveal() // want "SL01"
	_ = n.Reveal()
}

func UseSpellings(u uint8Revealer, a aliasRevealer, d definedRevealer, s stringRevealer) {
	_ = u.Reveal() // want "SL01"
	_ = a.Reveal() // want "SL01"
	_ = d.Reveal()
	_ = s.Reveal()
}

func UseNamed(l logValuer, ll localLogValuer) {
	_ = l.Reveal() // want "SL01"
	_ = ll.Reveal()
}
