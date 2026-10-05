// Package secret holds credential bytes in a type that cannot be rendered.
//
// It is an interim stand-in. The engineering standard (ARCH-COMMON) puts the
// secret type in the Geekdojo common library, and until the Go library exists
// (geekdojo/geekdojo-brain#668) this package is that type, written once so
// that the api, the agent and logkit cannot drift. When #668 publishes the Go
// library, this package is replaced by it.
//
// # What it guarantees
//
// A Value renders "[redacted]" through every ordinary rendering path: String,
// every fmt verb (%#v included), encoding/json and log/slog. The struct is
// opaque, so string(v) and []byte(v) do not compile, and the bytes sit behind
// a pointer, so formatting a struct that holds a Value in an UNEXPORTED field
// (which fmt cannot call methods on) prints an address, not the bytes.
//
// The bytes leave through Reveal and nowhere else. Every Reveal outside this
// package is a site the secretlint analyzer (api/internal/secretlint) reports,
// and CI fails on one that .github/secret-reveal-allow.tsv does not name
// (ADR-0009).
//
// # Ownership
//
// Every struct copy of a Value shares one payload, so Destroy on any copy
// zeroes the bytes for all of them. A holder that must outlive another's
// Destroy builds its own payload with New(v.Reveal()). A Value is not safe
// for a Destroy concurrent with a Reveal of the same payload; holders
// serialise, as storage.RestoreSessions does under its mutex.
package secret

import (
	"fmt"
	"io"
	"log/slog"
	"reflect"
)

// redacted is what every rendering path prints in place of the bytes.
const redacted = "[redacted]"

// Value is a secret. The zero value holds nothing and is safe to use.
type Value struct{ p *payload }

// payload is shared by every struct copy of one Value.
type payload struct{ b []byte }

// New copies b into a new Value. The caller still owns b and zeroes it.
func New(b []byte) Value {
	held := make([]byte, len(b))
	copy(held, b)
	return Value{p: &payload{b: held}}
}

// Reveal returns the held bytes themselves, not a copy: the only way out.
// It is empty for the zero value and after Destroy.
func (v Value) Reveal() []byte {
	if v.p == nil {
		return nil
	}
	return v.p.b
}

// Len is the number of bytes held: 0 for the zero value and after Destroy.
func (v Value) Len() int {
	if v.p == nil {
		return 0
	}
	return len(v.p.b)
}

// Destroy zeroes the bytes and then drops them, for every copy of v.
// Idempotent, and a no-op on the zero value.
func (v Value) Destroy() {
	if v.p == nil {
		return
	}
	for i := range v.p.b {
		v.p.b[i] = 0
	}
	v.p.b = nil
}

// String renders the redaction marker.
func (v Value) String() string { return redacted }

// Format renders the redaction marker for every verb, %#v included.
func (v Value) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// MarshalJSON encodes the redaction marker as a JSON string.
func (v Value) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// LogValue renders the redaction marker in log/slog.
func (v Value) LogValue() slog.Value { return slog.StringValue(redacted) }

var valueType = reflect.TypeFor[Value]()

// Contains reports whether x can carry a Value anywhere: x itself, a struct
// field (exported or not), a pointer, a slice or array element, or a map key
// or value. The answer is about the static type, so an empty slice of Values
// counts; an interface-typed position is answered by the value it holds.
// json.RawMessage, []byte and nil are false.
//
// It is what the job runner asks before it persists a spec: a spec that can
// carry a Value is refused, because a spec is rendered on the Tasks page.
func Contains(x any) bool {
	if x == nil {
		return false
	}
	w := walker{
		holds:   map[reflect.Type]bool{},
		ifaces:  map[reflect.Type]bool{},
		visited: map[visit]bool{},
	}
	return w.value(reflect.ValueOf(x))
}

// visit keys one reference the walk has followed, so a cycle terminates.
// The length is part of the key so two slices sharing a backing array are
// both walked.
type visit struct {
	ptr uintptr
	n   int
	typ reflect.Type
}

// walker memoises the type questions for one Contains call.
type walker struct {
	holds   map[reflect.Type]bool
	ifaces  map[reflect.Type]bool
	visited map[visit]bool
}

// typeReaches reports whether a value of t can reach a type that pred
// accepts, without passing through an interface. Graph reachability with a
// seen set, so a recursive type terminates; the root answer is memoised.
func typeReaches(t reflect.Type, pred func(reflect.Type) bool, memo map[reflect.Type]bool) bool {
	if r, ok := memo[t]; ok {
		return r
	}
	r := reach(t, pred, map[reflect.Type]bool{})
	memo[t] = r
	return r
}

func reach(t reflect.Type, pred func(reflect.Type) bool, seen map[reflect.Type]bool) bool {
	if pred(t) {
		return true
	}
	if seen[t] {
		return false
	}
	seen[t] = true
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return reach(t.Elem(), pred, seen)
	case reflect.Map:
		return reach(t.Key(), pred, seen) || reach(t.Elem(), pred, seen)
	case reflect.Struct:
		for i := range t.NumField() {
			if reach(t.Field(i).Type, pred, seen) {
				return true
			}
		}
	}
	return false
}

func isValue(t reflect.Type) bool     { return t == valueType }
func isInterface(t reflect.Type) bool { return t.Kind() == reflect.Interface }

// value answers Contains for one reflected value.
func (w *walker) value(v reflect.Value) bool {
	if !v.IsValid() {
		return false
	}
	t := v.Type()
	if typeReaches(t, isValue, w.holds) {
		return true
	}
	if !typeReaches(t, isInterface, w.ifaces) {
		return false
	}
	// Only an interface-typed position can still hold a Value: walk the
	// value to find what each one holds.
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return false
		}
		return w.value(v.Elem())
	case reflect.Pointer:
		if v.IsNil() || w.seen(v, t) {
			return false
		}
		return w.value(v.Elem())
	case reflect.Struct:
		for i := range v.NumField() {
			if w.value(v.Field(i)) {
				return true
			}
		}
	case reflect.Slice:
		if v.IsNil() || w.seen(v, t) {
			return false
		}
		return w.elems(v)
	case reflect.Array:
		return w.elems(v)
	case reflect.Map:
		if v.IsNil() || w.seen(v, t) {
			return false
		}
		it := v.MapRange()
		for it.Next() {
			if w.value(it.Key()) || w.value(it.Value()) {
				return true
			}
		}
	}
	return false
}

func (w *walker) elems(v reflect.Value) bool {
	for i := range v.Len() {
		if w.value(v.Index(i)) {
			return true
		}
	}
	return false
}

// seen records a followed reference and reports whether it was followed
// before.
func (w *walker) seen(v reflect.Value, t reflect.Type) bool {
	k := visit{ptr: v.Pointer(), typ: t}
	if v.Kind() == reflect.Slice {
		k.n = v.Len()
	}
	if w.visited[k] {
		return true
	}
	w.visited[k] = true
	return false
}
