package breakglass

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// Session is a live repair session as Resolve found it. The zero Session is
// no session.
type Session struct {
	cookie    [32]byte
	origin    string
	createdAt time.Time
}

// Origin is the origin the session was opened at, the only one it resolves
// at.
func (s Session) Origin() string { return s.origin }

// Submitter is the session as a job's submitter: authz.RepairSession, which
// holds Repair only and records "break-glass". This is the only caller of
// authz.RepairSession (specargs_test.go pins it).
func (s Session) Submitter() authz.Submitter { return authz.RepairSession() }

// Capabilities is what the session holds: Repair only.
func (s Session) Capabilities() authz.Set { return s.Submitter().Capabilities() }

type sessionKey struct{}

// WithSession returns ctx carrying sess, as the api's repair middleware puts
// it.
func WithSession(ctx context.Context, sess Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, sess)
}

// SessionFrom is the session WithSession put in ctx, if any.
func SessionFrom(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(sessionKey{}).(Session)
	return s, ok
}

// encodeCookie is a cookie's random bytes as its value.
func encodeCookie(b []byte) []byte {
	out := make([]byte, base64.RawURLEncoding.EncodedLen(len(b)))
	base64.RawURLEncoding.Encode(out, b)
	return out
}

// cookieHash is the hash a session is kept under.
func cookieHash(v secret.Value) [32]byte { return sha256.Sum256(v.Reveal()) }
