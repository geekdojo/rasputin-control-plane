package logkit

import (
	"context"
	"log/slog"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// redactHandler replaces every attribute that can carry a secret.Value with
// the redaction marker before next sees it. See RedactSecrets.
type redactHandler struct{ next slog.Handler }

func (h redactHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l)
}

func (h redactHandler) Handle(ctx context.Context, r slog.Record) error {
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(redactAttr(a))
		return true
	})
	return h.next.Handle(ctx, out)
}

func (h redactHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	red := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		red[i] = redactAttr(a)
	}
	return redactHandler{next: h.next.WithAttrs(red)}
}

func (h redactHandler) WithGroup(name string) slog.Handler {
	return redactHandler{next: h.next.WithGroup(name)}
}

// redactAttr judges a by the type of its value, before the value can render
// itself. secret.Value's own LogValue supplies the marker, so its text has one
// owner.
func redactAttr(a slog.Attr) slog.Attr {
	switch a.Value.Kind() {
	case slog.KindLogValuer:
		if secret.Contains(a.Value.Any()) {
			return slog.Attr{Key: a.Key, Value: secret.Value{}.LogValue()}
		}
		return redactAttr(slog.Attr{Key: a.Key, Value: a.Value.Resolve()})
	case slog.KindAny:
		if secret.Contains(a.Value.Any()) {
			return slog.Attr{Key: a.Key, Value: secret.Value{}.LogValue()}
		}
	case slog.KindGroup:
		members := a.Value.Group()
		red := make([]slog.Attr, len(members))
		for i, m := range members {
			red[i] = redactAttr(m)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(red...)}
	}
	return a
}
