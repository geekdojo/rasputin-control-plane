package idclient

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
)

// The kinds of failure. Every error the client, the session and Disabled
// return is an *Error whose Kind is exactly one of these, so a caller decides
// with errors.Is and never reads text. No failure is reported as success.
var (
	// ErrUnreachable: no usable answer reached the client. The service is
	// down, the call ran out of time or was cancelled, the server's
	// certificate did not verify, the local client leaf is absent or
	// unreadable, or the service answered 5xx.
	ErrUnreachable = errors.New("identity: unreachable")
	// ErrDenied: the service refused the caller's credential: its client
	// certificate at the TLS layer (alerts 42, 46, 48, 116), or the token
	// endpoint answering 400 or 401 with invalid_client or
	// unauthorized_client.
	ErrDenied = errors.New("identity: denied")
	// ErrTokenRefused: the Admin API answered 401 to the token it was sent.
	ErrTokenRefused = errors.New("identity: token refused")
	// ErrForbidden: the Admin API answered 403.
	ErrForbidden = errors.New("identity: forbidden")
	// ErrNotFound: the Admin API answered 404.
	ErrNotFound = errors.New("identity: not found")
	// ErrConflict: the Admin API answered 409.
	ErrConflict = errors.New("identity: conflict")
	// ErrProtocol: the service answered something this client does not
	// accept: a redirect, an oversized or malformed body, or any other
	// status.
	ErrProtocol = errors.New("identity: protocol error")
	// ErrInvalidValue: the call was refused before any request was sent.
	ErrInvalidValue = errors.New("identity: invalid value")
	// ErrDisabled: no identity service is configured, or its settings were
	// refused; see Disabled.
	ErrDisabled = errors.New("identity: disabled")
	// ErrMock: the identity backend is the mock, which serves nothing yet
	// (Identity 3.6, geekdojo/geekdojo-brain#982); see Disabled.
	ErrMock = errors.New("identity: mock")
)

// Error is the one error type the package returns.
//
// Error() renders the operation, the path, the status, the kind and the
// cause. It never renders a response body, a token or a secret: an error
// string travels further than a log record does. Every fmt verb, %#v
// included, renders the same text. LogAttrs carries the OAuth error code
// too, for the record the client writes.
type Error struct {
	Op   string // token, admin, ready or login
	Path string // the request path, which holds no secret
	// Status is the HTTP status, 0 when none was received.
	Status int
	// Kind is one of the Err* sentinels.
	Kind error
	// Err is the cause, when there is one: a transport error, a context
	// error, or what was wrong with an answer. It never holds a body.
	Err error
	// OAuthError is the token endpoint's "error" code, for logs only.
	OAuthError string
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("identity: ")
	b.WriteString(e.Op)
	if e.Path != "" {
		b.WriteString(" ")
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

// Format renders Error() for every verb, so %+v and %#v print no field that
// Error() leaves out.
func (e *Error) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, e.Error()) }

// Unwrap lets errors.Is match the kind and anything in the cause, such as
// context.Canceled.
func (e *Error) Unwrap() []error {
	var out []error
	for _, err := range []error{e.Kind, e.Err} {
		if err != nil {
			out = append(out, err)
		}
	}
	return out
}

// LogAttrs is every field of e as log attributes.
func (e *Error) LogAttrs() []slog.Attr {
	attrs := []slog.Attr{
		slog.String("op", e.Op),
		slog.String("path", e.Path),
		slog.Int("status", e.Status),
		slog.String("kind", kindName(e.Kind)),
	}
	if e.OAuthError != "" {
		attrs = append(attrs, slog.String("oauth_error", e.OAuthError))
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
	return strings.TrimPrefix(kind.Error(), "identity: ")
}
