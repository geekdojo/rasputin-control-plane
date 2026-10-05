// Package secret is a stub of the real package at its real import path.
// Reveal calls in here are exempt: this is where Reveal is defined.
package secret

type Value struct{ p *[]byte }

func New(b []byte) Value { c := append([]byte(nil), b...); return Value{p: &c} }

func (v Value) Reveal() []byte {
	if v.p == nil {
		return nil
	}
	return *v.p
}

func (v Value) Len() int { return len(v.Reveal()) }

func (v Value) Destroy() {}

func (v Value) String() string { return "[redacted]" }
