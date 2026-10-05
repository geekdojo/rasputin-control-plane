package secret_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// raw32 is 32 known non-zero bytes.
func raw32() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(0xA0 + i)
	}
	return b
}

// encodings are the four forms of raw a leak would take.
func encodings(raw []byte) []string {
	return []string{
		string(raw),
		hex.EncodeToString(raw),
		base64.StdEncoding.EncodeToString(raw),
		base64.RawURLEncoding.EncodeToString(raw),
	}
}

func assertNoLeak(t *testing.T, label, out string, raw []byte) {
	t.Helper()
	for i, e := range encodings(raw) {
		if strings.Contains(out, e) {
			t.Errorf("%s: output carries encoding %d of the secret: %q", label, i, out)
		}
	}
	// Also refuse the decimal-bytes rendering %d of a []byte would give.
	if strings.Contains(out, fmt.Sprint(raw)) {
		t.Errorf("%s: output carries the secret as a byte list: %q", label, out)
	}
}

// TC-732-01: String, every Format verb and an error chain render [redacted].
func TestValue_StringAndFormat(t *testing.T) {
	raw := raw32()
	v := secret.New(raw)
	if got := v.String(); got != "[redacted]" {
		t.Fatalf("String() = %q", got)
	}
	assertNoLeak(t, "String", v.String(), raw)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		got := fmt.Sprintf(verb, v)
		if got != "[redacted]" {
			t.Errorf("Sprintf(%s) = %q, want [redacted]", verb, got)
		}
		assertNoLeak(t, verb, got, raw)
	}
	e := fmt.Errorf("op: %v", v).Error()
	if !strings.Contains(e, "[redacted]") {
		t.Errorf("error text %q does not carry [redacted]", e)
	}
	assertNoLeak(t, "Errorf", e, raw)
}

// TC-732-02: MarshalJSON at top level and in every nesting.
func TestValue_MarshalJSON(t *testing.T) {
	raw := raw32()
	v := secret.New(raw)
	type exported struct{ K secret.Value }
	type pointer struct{ K *secret.Value }
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"value", v, `"[redacted]"`},
		{"struct field", exported{K: v}, `{"K":"[redacted]"}`},
		{"pointer field", pointer{K: &v}, `{"K":"[redacted]"}`},
		{"slice", []secret.Value{v, v}, `["[redacted]","[redacted]"]`},
		{"map", map[string]secret.Value{"a": v}, `{"a":"[redacted]"}`},
	}
	for _, c := range cases {
		b, err := json.Marshal(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if string(b) != c.want {
			t.Errorf("%s: %s, want %s", c.name, b, c.want)
		}
		assertNoLeak(t, c.name, string(b), raw)
	}
}

// TC-732-03: slog renders [redacted] through both handlers, direct and nested.
func TestValue_LogValue(t *testing.T) {
	raw := raw32()
	v := secret.New(raw)
	type holder struct{ Key secret.Value }
	handlers := map[string]func(*bytes.Buffer) slog.Handler{
		"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
	}
	for name, mk := range handlers {
		var direct, nested bytes.Buffer
		slog.New(mk(&direct)).Info("m", "key", v)
		slog.New(mk(&nested)).Info("m", slog.Any("h", holder{Key: v}))
		for shape, buf := range map[string]*bytes.Buffer{"direct": &direct, "nested": &nested} {
			out := buf.String()
			if !strings.Contains(out, "[redacted]") {
				t.Errorf("%s/%s: %q does not carry [redacted]", name, shape, out)
			}
			assertNoLeak(t, name+"/"+shape, out, raw)
		}
		if name == "text" && !strings.Contains(direct.String(), "key=[redacted]") {
			t.Errorf("text/direct: %q, want key=[redacted]", direct.String())
		}
		if name == "json" && !strings.Contains(direct.String(), `"key":"[redacted]"`) {
			t.Errorf("json/direct: %q, want \"key\":\"[redacted]\"", direct.String())
		}
	}
}

// TC-732-04: an unexported field, which fmt cannot call methods on, prints
// an address and not the bytes.
func TestValue_UnexportedFieldFormatting(t *testing.T) {
	raw := raw32()
	type hidden struct {
		name string
		key  secret.Value
	}
	h := hidden{name: "n", key: secret.New(raw)}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		assertNoLeak(t, verb, fmt.Sprintf(verb, h), raw)
	}
}

// TC-732-05: every method works on the zero value (F-732-03).
func TestValue_ZeroValue(t *testing.T) {
	var z secret.Value
	check := func(when string) {
		t.Helper()
		if got := z.String(); got != "[redacted]" {
			t.Errorf("%s: String() = %q", when, got)
		}
		if got := fmt.Sprintf("%v", z); got != "[redacted]" {
			t.Errorf("%s: %%v = %q", when, got)
		}
		b, err := z.MarshalJSON()
		if err != nil || string(b) != `"[redacted]"` {
			t.Errorf("%s: MarshalJSON() = %s, %v", when, b, err)
		}
		if got := z.LogValue().String(); got != "[redacted]" {
			t.Errorf("%s: LogValue() = %q", when, got)
		}
		if n := len(z.Reveal()); n != 0 {
			t.Errorf("%s: len(Reveal()) = %d", when, n)
		}
		if n := z.Len(); n != 0 {
			t.Errorf("%s: Len() = %d", when, n)
		}
	}
	check("before Destroy")
	z.Destroy()
	z.Destroy()
	check("after Destroy twice")
}

// TC-732-06: New copies its input; Reveal round-trips.
func TestNew_CopiesInput(t *testing.T) {
	b := []byte("correct horse battery staple")
	orig := append([]byte(nil), b...)
	v := secret.New(b)
	for i := range b {
		b[i] = 0
	}
	if !bytes.Equal(v.Reveal(), orig) {
		t.Fatalf("Reveal() = %x after the caller zeroed its slice, want %x", v.Reveal(), orig)
	}
	if v.Len() != len(orig) {
		t.Fatalf("Len() = %d, want %d", v.Len(), len(orig))
	}
}

// TC-732-07: Destroy zeroes and drops the bytes on every copy (F-732-03).
func TestDestroy_ZeroesAndDropsOnEveryCopy(t *testing.T) {
	v := secret.New(raw32())
	w := v
	held := v.Reveal()
	check := func(when string) {
		t.Helper()
		for i, c := range held {
			if c != 0 {
				t.Fatalf("%s: held[%d] = %#x, want 0", when, i, c)
			}
		}
		for name, x := range map[string]secret.Value{"v": v, "w": w} {
			if n := len(x.Reveal()); n != 0 {
				t.Errorf("%s: len(%s.Reveal()) = %d", when, name, n)
			}
			if n := x.Len(); n != 0 {
				t.Errorf("%s: %s.Len() = %d", when, name, n)
			}
		}
	}
	v.Destroy()
	check("after v.Destroy")
	v.Destroy()
	check("after v.Destroy again")
	w.Destroy()
	check("after w.Destroy")
}

type node struct {
	Next *node
	V    secret.Value
}

type plainNode struct {
	Next *plainNode
	S    string
}

type anyNode struct {
	Next any
	S    string
}

// TC-732-08: Contains over every shape.
func TestContains(t *testing.T) {
	v := secret.New([]byte("k"))
	type exported struct{ K secret.Value }
	type unexported struct{ k secret.Value }
	type plain struct {
		S string
		N int
	}
	type withAny struct{ X any }

	a := &plainNode{S: "a"}
	b := &plainNode{S: "b", Next: a}
	a.Next = b
	c := &anyNode{S: "c"}
	d := &anyNode{S: "d", Next: c}
	c.Next = d
	self := &node{}
	self.Next = self

	cases := []struct {
		name string
		in   any
		want bool
	}{
		{"exported field", exported{K: v}, true},
		{"unexported field", unexported{k: v}, true},
		{"pointer to struct", &exported{K: v}, true},
		{"slice", []secret.Value{v}, true},
		{"zero-length array", [0]secret.Value{}, true},
		{"array", [2]secret.Value{v, v}, true},
		{"nil slice", []secret.Value(nil), true},
		{"map key", map[secret.Value]int{v: 1}, true},
		{"map value", map[string]secret.Value{"a": v}, true},
		{"any field holding a Value", withAny{X: v}, true},
		{"any field holding a pointer to a Value carrier", withAny{X: &exported{K: v}}, true},
		{"Value itself", v, true},
		{"self-referential type", self, true},
		{"json.RawMessage", json.RawMessage(`{"a":1}`), false},
		{"[]byte", []byte("x"), false},
		{"untyped nil", nil, false},
		{"plain struct", plain{S: "s", N: 1}, false},
		{"any field holding a string", withAny{X: "s"}, false},
		{"two-node pointer cycle", a, false},
		{"two-node cycle through any", c, false},
		{"slice of any holding a Value", []any{"s", v}, true},
		{"map of any holding a Value", map[string]any{"a": v}, true},
		{"nil any field", withAny{}, false},
	}
	for _, tc := range cases {
		if got := secret.Contains(tc.in); got != tc.want {
			t.Errorf("Contains(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A cycle through a slice of any terminates and answers false.
func TestContains_SliceCycleTerminates(t *testing.T) {
	s := []any{nil, "x"}
	s[0] = s
	if secret.Contains(s) {
		t.Fatal("Contains on a self-holding []any with no Value = true")
	}
	m := map[string]any{}
	m["self"] = m
	if secret.Contains(m) {
		t.Fatal("Contains on a self-holding map with no Value = true")
	}
}
