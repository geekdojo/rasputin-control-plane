package secretstore

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
)

// The kinds of failure. Every error a store method returns is an *Error whose
// Kind is exactly one of these, so a caller decides with errors.Is and never
// reads text. No failure is reported as success.
var (
	// ErrSealed: the store is running and initialised but sealed.
	ErrSealed = errors.New("secretstore: sealed")
	// ErrUninitialised: the store has never been initialised.
	ErrUninitialised = errors.New("secretstore: uninitialised")
	// ErrUnreachable: no usable answer reached the client. The store is down,
	// the call ran out of time or was cancelled, the server's certificate did
	// not verify, the local client leaf is absent or unreadable, or the store
	// answered with a status that says it cannot serve.
	ErrUnreachable = errors.New("secretstore: unreachable")
	// ErrDenied: the store refused the caller, by status 403 or by refusing the
	// client certificate at the TLS layer.
	ErrDenied = errors.New("secretstore: denied")
	// ErrNotFound: the path, or the version asked for, does not exist or is
	// deleted or destroyed.
	ErrNotFound = errors.New("secretstore: not found")
	// ErrCASMismatch: a write's check-and-set version is not the current one.
	ErrCASMismatch = errors.New("secretstore: check-and-set mismatch")
	// ErrProtocol: the store answered something this client does not accept:
	// a redirect, an oversized or malformed body, an unexpected status, or a
	// health answer whose body contradicts its code.
	ErrProtocol = errors.New("secretstore: protocol error")
	// ErrInvalidValue: the call was refused before any request was sent.
	ErrInvalidValue = errors.New("secretstore: invalid value")
	// ErrDisabled: no store is configured; see Disabled.
	ErrDisabled = errors.New("secretstore: disabled")
)

// Error is the one error type a store method returns.
//
// Error() renders the operation, the mount and path, the status and the kind,
// and the transport cause when there is one. It never renders StoreMessages, a
// response body, a token or a value: an error string travels further than a
// log record does. Every fmt verb, %#v included, renders the same text.
//
// LogAttrs carries every field, the store's own messages included, so the
// caller that maps this error logs the full reason under its own correlation
// id (geekdojo/geekdojo-brain#758, F-758-06).
type Error struct {
	Op     string // health, read, write or versions
	Mount  string
	Path   string
	Status int // the HTTP status, 0 when none was received
	// Kind is one of the Err* sentinels.
	Kind error
	// Err is the cause, when there is one: a transport error, a context error,
	// or what was wrong with an answer. It never holds a response body.
	Err error
	// StoreMessages are the store's own "errors" strings, for logs only.
	StoreMessages []string
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("secretstore: ")
	b.WriteString(e.Op)
	if e.Mount != "" || e.Path != "" {
		b.WriteString(" ")
		b.WriteString(e.Mount)
		b.WriteString("/")
		b.WriteString(e.Path)
	}
	if e.Status != 0 {
		b.WriteString(": status ")
		b.WriteString(strconv.Itoa(e.Status))
	}
	b.WriteString(": ")
	b.WriteString(kindName(e.Kind))
	if e.Err != nil {
		b.WriteString(": ")
		b.WriteString(e.Err.Error())
	}
	return b.String()
}

// Format renders Error() for every verb, so %+v and %#v cannot print the
// StoreMessages field that Error() leaves out.
func (e *Error) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, e.Error()) }

// Unwrap lets errors.Is match the kind and anything in the cause, such as
// context.DeadlineExceeded or context.Canceled.
func (e *Error) Unwrap() []error {
	var out []error
	for _, err := range []error{e.Kind, e.Err} {
		if err != nil {
			out = append(out, err)
		}
	}
	return out
}

// LogAttrs is every field of e as log attributes, the store's messages
// included.
func (e *Error) LogAttrs() []slog.Attr {
	attrs := []slog.Attr{
		slog.String("op", e.Op),
		slog.String("mount", e.Mount),
		slog.String("path", e.Path),
		slog.Int("status", e.Status),
		slog.String("kind", kindName(e.Kind)),
		slog.Any("store_messages", e.StoreMessages),
	}
	if e.Err != nil {
		attrs = append(attrs, slog.String("err", e.Err.Error()))
	}
	return attrs
}

// kindName is a kind sentinel's text without the package prefix.
func kindName(kind error) string {
	if kind == nil {
		return "unknown"
	}
	return strings.TrimPrefix(kind.Error(), "secretstore: ")
}

// fail is an *Error for op on p.
func fail(op string, p KVPath, kind, cause error) *Error {
	return &Error{Op: op, Mount: p.mount, Path: p.path, Kind: kind, Err: cause}
}
