package logkit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// sentinel is the secret every test hands the logger; it must never reach the
// output with RedactSecrets on.
const sentinel = "SENTINEL-733"

func sentinelValue() secret.Value { return secret.New([]byte(sentinel)) }

// Self-rendering containers: each holds a Value and reveals it from the
// method slog or fmt calls on the outer value, before the field's own
// LogValue could run.
type stringerHolder struct{ v secret.Value }

func (s stringerHolder) String() string { return "str:" + string(s.v.Reveal()) }

type marshalerHolder struct{ v secret.Value }

func (m marshalerHolder) MarshalText() ([]byte, error) { return m.v.Reveal(), nil }

type errHolder struct{ v secret.Value }

func (e errHolder) Error() string { return "err:" + string(e.v.Reveal()) }

type valuerHolder struct{ v secret.Value }

func (l valuerHolder) LogValue() slog.Value {
	return slog.GroupValue(slog.String("tok", string(l.v.Reveal())))
}

// funcValuer's type carries no Value (a func field), so the top-level check
// passes it; its resolved group holds a TextMarshaler that reveals one. It
// exercises the resolve-then-redact path.
type funcValuer struct{ get func() secret.Value }

func (f funcValuer) LogValue() slog.Value {
	return slog.GroupValue(slog.Any("m", marshalerHolder{v: f.get()}))
}

type exportedHolder struct{ Tok secret.Value }

type unexportedHolder struct{ tok secret.Value }

type mixedHolder struct {
	Tok  secret.Value
	Name string
}

type plain struct {
	A int
	B string
}

type plainErr struct{ msg string }

func (e plainErr) Error() string { return e.msg }

type plainValuer struct{}

func (plainValuer) LogValue() slog.Value { return slog.StringValue("resolved") }

func logOne(opts []Option, args ...any) string {
	var buf bytes.Buffer
	New(&buf, opts...).Info("m", args...)
	return buf.String()
}

func redacting() []Option { return []Option{RedactSecrets()} }

// TC-733-01: shapes secret.Value already redacts stay redacted with the option.
func TestRedactSecrets_ShapesTheTypeRedacts(t *testing.T) {
	v := sentinelValue()
	cases := []struct {
		name string
		val  any
	}{
		{"bare Value", v},
		{"pointer", &v},
		{"exported field", exportedHolder{Tok: v}},
		{"slice", []secret.Value{v}},
		{"map", map[string]secret.Value{"a": v}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := logOne(redacting(), "k", c.val)
			if strings.Contains(out, sentinel) {
				t.Fatalf("the sentinel reached the output: %q", out)
			}
			if !strings.Contains(out, " k=[redacted]\n") {
				t.Fatalf("want k=[redacted], got %q", out)
			}
		})
	}
}

// TC-733-02: self-rendering containers leak without the option and are
// redacted with it.
func TestRedactSecrets_SelfRenderingContainers(t *testing.T) {
	v := sentinelValue()
	cases := []struct {
		name string
		val  any
		want string
	}{
		{"Stringer", stringerHolder{v: v}, " k=[redacted]\n"},
		{"TextMarshaler", marshalerHolder{v: v}, " k=[redacted]\n"},
		{"error", errHolder{v: v}, " k=[redacted]\n"},
		{"LogValuer", valuerHolder{v: v}, " k=[redacted]\n"},
		{"LogValuer resolving to a TextMarshaler", funcValuer{get: func() secret.Value { return v }}, " k.m=[redacted]\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if control := logOne(nil, "k", c.val); !strings.Contains(control, sentinel) {
				t.Fatalf("control: without the option the row does not leak, so it proves nothing: %q", control)
			}
			out := logOne(redacting(), "k", c.val)
			if strings.Contains(out, sentinel) {
				t.Fatalf("the sentinel reached the output: %q", out)
			}
			if !strings.Contains(out, c.want) {
				t.Fatalf("want %q, got %q", c.want, out)
			}
		})
	}
}

// TC-733-03: an unexported field prints no address and a nil *Value no panic.
func TestRedactSecrets_UnexportedFieldAndNilPointer(t *testing.T) {
	var nilPtr *secret.Value
	cases := []struct {
		name string
		val  any
	}{
		{"unexported field", unexportedHolder{tok: sentinelValue()}},
		{"nil pointer", nilPtr},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := logOne(redacting(), "k", c.val)
			if !strings.Contains(out, " k=[redacted]\n") {
				t.Fatalf("want k=[redacted], got %q", out)
			}
			if strings.Contains(out, "0x") {
				t.Fatalf("an address reached the output: %q", out)
			}
			if strings.Contains(out, "panicked") {
				t.Fatalf("a LogValue panic reached the output: %q", out)
			}
		})
	}
}

// TC-733-04: every attr path through the handler.
func TestRedactSecrets_EveryAttrPath(t *testing.T) {
	val := stringerHolder{v: sentinelValue()}
	cases := []struct {
		name string
		log  func(*slog.Logger)
		want string
	}{
		{"slog.Group", func(l *slog.Logger) { l.Info("m", slog.Group("g", "k", val)) }, " g.k=[redacted]\n"},
		{"With", func(l *slog.Logger) { l.With("k", val).Info("m") }, " k=[redacted]\n"},
		{"WithGroup", func(l *slog.Logger) { l.WithGroup("g").Info("m", "k", val) }, " g.k=[redacted]\n"},
		{"WithGroup then With", func(l *slog.Logger) { l.WithGroup("g").With("k", val).Info("m") }, " g.k=[redacted]\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			c.log(New(&buf, RedactSecrets()))
			out := buf.String()
			if strings.Contains(out, sentinel) {
				t.Fatalf("the sentinel reached the output: %q", out)
			}
			if !strings.Contains(out, c.want) {
				t.Fatalf("want %q, got %q", c.want, out)
			}
		})
	}
}

// TC-733-05: a Value anywhere in a value redacts the whole attr.
func TestRedactSecrets_FailsClosed(t *testing.T) {
	v := sentinelValue()
	wrapped := fmt.Errorf("op: %w", errHolder{v: v})
	if out := logOne(redacting(), "err", wrapped); !strings.HasSuffix(out, " msg=m err=[redacted]\n") {
		t.Fatalf("want the whole error redacted as err=[redacted], got %q", out)
	}
	if out := logOne(redacting(), "k", mixedHolder{Tok: v, Name: "visible"}); !strings.HasSuffix(out, " msg=m k=[redacted]\n") {
		t.Fatalf("want the whole struct redacted as k=[redacted], got %q", out)
	}
}

var timeAttr = regexp.MustCompile(`^time=\S+ `)

// TC-733-06: values that carry no secret render exactly as without the option.
func TestRedactSecrets_NoOverRedaction(t *testing.T) {
	cases := []struct {
		name string
		args []any
	}{
		{"string", []any{"k", "hello"}},
		{"int", []any{"k", 42}},
		{"struct", []any{"k", plain{A: 1, B: "two"}}},
		{"error", []any{"err", plainErr{msg: "boom"}}},
		{"wrapped error", []any{"err", fmt.Errorf("op: %w", errors.New("inner"))}},
		{"LogValuer", []any{"k", plainValuer{}}},
		{"group", []any{slog.Group("g", "a", "x", "b", 2)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := timeAttr.ReplaceAllString(logOne(redacting(), c.args...), "")
			want := timeAttr.ReplaceAllString(logOne(nil, c.args...), "")
			if got != want {
				t.Fatalf("the option changed a secret-free line:\n got %q\nwant %q", got, want)
			}
		})
	}
}

// TC-733-07: FATAL rename, CRLF escaping and the Info floor survive the option.
func TestRedactSecrets_KeepsNewBehaviour(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, RedactSecrets())
	ctx := context.Background()
	l.Log(ctx, LevelFatal, "cannot continue")
	l.Info("bad value", "value", "x\r\nlevel=INFO msg=forged")
	l.Debug("debug-entry")
	out := buf.String()
	if !strings.Contains(out, "level=FATAL") {
		t.Fatalf("LevelFatal did not render as FATAL: %q", out)
	}
	if n := strings.Count(out, "\n"); n != 2 {
		t.Fatalf("two Info+ records wrote %d lines: %q", n, out)
	}
	if strings.Contains(out, "\r") || !strings.Contains(out, `\r\n`) {
		t.Fatalf("the CRLF was not escaped: %q", out)
	}
	if strings.Contains(out, "debug-entry") {
		t.Fatalf("a Debug record reached the output: %q", out)
	}
}

// TC-733-09: a nil Option is refused with a panic that names logkit.
func TestNew_NilOptionPanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("New accepted a nil Option")
		}
		if !strings.Contains(fmt.Sprint(r), "logkit") {
			t.Fatalf("the panic does not name logkit: %v", r)
		}
	}()
	New(&bytes.Buffer{}, nil)
}
