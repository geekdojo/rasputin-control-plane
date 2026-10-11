package secretstore

import (
	"context"
	"errors"
	"io"
	"math"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// TC-758-07 (b), (c): a call whose ctx has ended is ErrUnreachable with the
// ctx error in its chain, even when the transport's own error does not carry
// it, as when the transport notices the end while reading the body.
func TestClassifyTransport_CarriesTheCtxError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	kind, cause := classifyTransport(ctx, io.ErrUnexpectedEOF)
	if kind != ErrUnreachable || !errors.Is(cause, context.Canceled) || !errors.Is(cause, io.ErrUnexpectedEOF) {
		t.Errorf("classifyTransport = %v, %v; want ErrUnreachable with context.Canceled and the transport error in the chain", kind, cause)
	}

	// A live ctx adds nothing to the cause.
	kind, cause = classifyTransport(context.Background(), io.ErrUnexpectedEOF)
	if kind != ErrUnreachable || cause != io.ErrUnexpectedEOF {
		t.Errorf("live ctx: classifyTransport = %v, %v; want ErrUnreachable and the transport error unchanged", kind, cause)
	}
}

// TC-758-09: the write body reader keeps io.Reader's contract: once its bytes
// are read, every further Read is io.EOF, never (0, nil).
func TestClearingBody_EOFAfterTheLastByte(t *testing.T) {
	r := &clearingBody{b: []byte(`{"k":"v"}`)}
	p := make([]byte, 64)
	n, err := r.Read(p)
	if n != 9 || err != nil {
		t.Fatalf("first Read = %d, %v; want 9, nil", n, err)
	}
	for i := range 2 {
		if n, err := r.Read(p); n != 0 || err != io.EOF {
			t.Errorf("Read %d after the last byte = %d, %v; want 0, io.EOF", i+2, n, err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := r.Read(p); n != 0 || err != io.EOF {
		t.Errorf("Read after Close = %d, %v; want 0, io.EOF", n, err)
	}
}

// TC-758-09: encodeWrite sizes its one buffer for the worst case, so a body
// whose every byte needs a \u00XX escape, with the largest check-and-set
// number, costs no more allocations than a body with nothing to escape: the
// buffer is never grown, so no uncleared copy of a value is left behind.
func TestEncodeWrite_NeverGrowsTheBuffer(t *testing.T) {
	worst := map[string]secret.Value{
		strings.Repeat("\x01", 40): secret.New([]byte(strings.Repeat("\x02", 100))),
		"\x03":                     secret.New([]byte("\x04")),
	}
	plain := map[string]secret.Value{
		strings.Repeat("k", 40): secret.New([]byte(strings.Repeat("v", 100))),
		"j":                     secret.New([]byte("w")),
	}
	worstAllocs := testing.AllocsPerRun(20, func() { _ = encodeWrite(worst, math.MaxInt64) })
	plainAllocs := testing.AllocsPerRun(20, func() { _ = encodeWrite(plain, 0) })
	if worstAllocs != plainAllocs {
		t.Errorf("encodeWrite allocates %v times for an all-escaped body and %v for a plain one; the buffer was grown", worstAllocs, plainAllocs)
	}
	// And the worst case is still the right body.
	got := string(encodeWrite(map[string]secret.Value{"\x01": secret.New([]byte("\x02\"\\"))}, math.MaxInt64))
	if want := `{"options":{"cas":9223372036854775807},"data":{"\u0001":"\u0002\"\\"}}`; got != want {
		t.Errorf("encodeWrite = %s, want %s", got, want)
	}
}
