// Package noimport cannot see secret.Value, but one can still arrive through
// an interface it satisfies.
package noimport

type revealer interface{ Reveal() []byte }

type wider interface {
	Reveal() []byte
	Len() int
}

type notValue interface {
	Reveal() []byte
	Rotate()
}

func Use(r revealer, w wider, n notValue) {
	_ = r.Reveal() // want "SL01"
	_ = w.Reveal() // want "SL01"
	_ = n.Reveal()
}
