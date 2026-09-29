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
package logkit

import (
	"io"
	"log/slog"
)

// LevelFatal is the level of an entry written immediately before the process
// exits because it cannot continue. slog has no such level, so it sits above
// slog.LevelError, and New renders it as "FATAL" rather than "ERROR+4".
const LevelFatal = slog.Level(12)

// New returns the process logger: structured key=value records to w, at Info
// and above.
func New(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.LevelKey {
				if lvl, ok := a.Value.Any().(slog.Level); ok && lvl == LevelFatal {
					a.Value = slog.StringValue("FATAL")
				}
			}
			return a
		},
	}))
}
