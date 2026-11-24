package auth

import (
	"context"
	"log/slog"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
)

// RoleChangeSink ends an account's console sessions when its roles change
// (geekdojo/geekdojo-brain#989, IA-F7): an admin event that changes a user's
// client or realm role mappings ends every session of that user, so the
// next request signs in again and carries the roles as they are now. It is
// an events.AdminSink on the sign-in history drain.
type RoleChangeSink struct {
	sessions *ConsoleSessions
	log      *slog.Logger
}

// NewRoleChangeSink is the sink over sessions.
func NewRoleChangeSink(sessions *ConsoleSessions, log *slog.Logger) (*RoleChangeSink, error) {
	if sessions == nil || log == nil {
		return nil, errNilDep("NewRoleChangeSink")
	}
	return &RoleChangeSink{sessions: sessions, log: log.With("component", "auth")}, nil
}

// AdminEvent ends the sessions of the user a role-mapping event names. A
// store error is logged and the drain's later sinks still run (F-989-11).
func (k *RoleChangeSink) AdminEvent(ctx context.Context, e events.AdminEvent) {
	if e.ResourceType != "CLIENT_ROLE_MAPPING" && e.ResourceType != "REALM_ROLE_MAPPING" {
		return
	}
	sub, ok := roleMappingUser(e.ResourcePath)
	if !ok {
		return
	}
	n, err := k.sessions.EndBySub(ctx, sub)
	if err != nil {
		k.log.LogAttrs(ctx, slog.LevelError, "A role change could not end the account's console sessions.",
			slog.String("event", "rolechange.store_failed"), slog.String("sub", sub), slog.String("err", err.Error()))
		return
	}
	if n > 0 {
		k.log.LogAttrs(ctx, slog.LevelInfo, "A role change ended the account's console sessions.",
			slog.String("event", "rolechange.ended"), slog.String("sub", sub), slog.Int64("sessions", n))
	}
}

// roleMappingUser is the user id of a users/<id>/role-mappings/... path.
func roleMappingUser(path string) (string, bool) {
	rest, ok := strings.CutPrefix(path, "users/")
	if !ok {
		return "", false
	}
	id, tail, ok := strings.Cut(rest, "/")
	if !ok || id == "" || !strings.HasPrefix(tail, "role-mappings") {
		return "", false
	}
	return id, true
}
