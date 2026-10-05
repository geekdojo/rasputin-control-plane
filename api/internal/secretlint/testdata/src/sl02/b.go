package sl02

import (
	"reflect"
	"unsafe"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

type spec struct {
	Name string
	Key  secret.Value
}

type plain struct {
	Name string
	N    int
}

func Access(v secret.Value, s spec, m map[string]secret.Value, p plain) {
	_ = unsafe.Pointer(&v)                    // want "SL02"
	_ = unsafe.Pointer(&s)                    // want "SL02"
	_ = reflect.ValueOf(v)                    // want "SL02"
	_ = reflect.ValueOf(&s)                   // want "SL02"
	_ = reflect.ValueOf(m)                    // want "SL02"
	_ = reflect.Indirect(reflect.ValueOf(&s)) // want "SL02" "SL02"
	_ = reflect.ValueOf(p)
	_ = unsafe.Pointer(&p)
	_ = reflect.Indirect(reflect.ValueOf(&p))
}
