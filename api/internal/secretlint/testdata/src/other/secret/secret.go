// Package secret shares the real package's name but not its import path, so
// it is not exempt.
package secret

import real "github.com/geekdojo/rasputin-control-plane/secret"

func Leak(v real.Value) []byte {
	return v.Reveal() // want "SL01"
}
