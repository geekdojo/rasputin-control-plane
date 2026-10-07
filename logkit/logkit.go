// Package logkit builds the process logger the api and the agent inject into
// the components that log.
//
// It is an interim stand-in. The engineering standard (ARCH-COMMON) puts
// logging in the Geekdojo common library, and until the Go library exists
// (geekdojo/geekdojo-brain#668) Human System's pattern is the reference: one
// *slog.Logger built at the composition root and handed to every component
// that logs, never reached for globally. This package is that pattern written
// once for both mains here, so the two cannot drift. When #668 publishes the Go
// library, this package is replaced by it.
//
// The handler choice is load-bearing, as in Human System's newLogger:
// slog.TextHandler quotes any value that needs it and escapes control
// characters, so a node-supplied value carrying "\r\n" cannot forge a second
// log line. TestNew_EscapesControlCharacters pins that.
//
// # Redacting secrets
//
// With the RedactSecrets option, any attribute whose value can carry a
// secret.Value (secret.Contains) renders as "[redacted]" as a whole. The check
// is on the value's type and runs before the value can render itself, so it
// catches what secret.Value's own LogValue cannot: a type holding a Value whose
// String, MarshalText, Error or LogValue method reveals it, a Value in an
// unexported field (which would print a heap address), and a nil *Value. It
// covers record attributes, attributes bound with With, groups and WithGroup.
// It fails closed: an attribute is redacted whole, never partly rendered.
//
// It does not catch revealed bytes or strings (secretlint's SL01 governs
// Reveal), a secret's text inside the message or an error string (free text,
// ADR-0009 B), or anything logged through the standard log package.
package logkit

import (
	"io"
	"log/slog"
)

// Option configures New.
type Option func(*options)

type options struct {
	redactSecrets bool
}

// RedactSecrets makes New's logger render any attribute that can carry a
// secret.Value as "[redacted]". Both composition roots pass it.
func RedactSecrets() Option {
	return func(o *options) { o.redactSecrets = true }
}

// LevelFatal is the level of an entry written immediately before the process
// exits because it cannot continue. slog has no such level, so it sits above
// slog.LevelError, and New renders it as "FATAL" rather than "ERROR+4".
const LevelFatal = slog.Level(12)

// New returns the process logger: structured key=value records to w, at Info
// and above. A nil Option is a programming error at the composition root, and
// New panics on it.
func New(w io.Writer, opts ...Option) *slog.Logger {
	var o options
	for _, opt := range opts {
		if opt == nil {
			panic("logkit: New called with a nil Option")
		}
		opt(&o)
	}
	var h slog.Handler = slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.LevelKey {
				if lvl, ok := a.Value.Any().(slog.Level); ok && lvl == LevelFatal {
					a.Value = slog.StringValue("FATAL")
				}
			}
			return a
		},
	})
	if o.redactSecrets {
		h = redactHandler{next: h}
	}
	return slog.New(h)
}
