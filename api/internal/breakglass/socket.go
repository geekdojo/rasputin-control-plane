package breakglass

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/privsock"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
)

// The repair-code socket (register row T222): the command `rasputin-api
// repair-code` sends the api the hash of the code it printed, and nothing
// else, over TLS 1.3 on a Unix socket in a 0700 root directory. The peer's
// uid, read from the kernel (SO_PEERCRED), is the authentication: only uid 0
// is served. The api presents the identity CA's identity-repair-code leaf,
// which the command verifies by chain under the name
// repair-code.rasputin.invalid.

// SocketName is the socket's file name inside its directory.
const SocketName = "repair-code.sock"

// CodePath is the one route the socket serves.
const CodePath = "/v1/code"

// maxCodeBody bounds the socket's request body: {"sha256":"<64 hex>"}.
const maxCodeBody = 1 << 10

// socketIOBound bounds each read and write on one socket connection. It
// decides nothing; a client that stalls is dropped.
const socketIOBound = 10 * time.Second

// CodeRequest is the socket's request body.
type CodeRequest struct {
	SHA256 string `json:"sha256"`
}

// CodeResponse is the socket's answer: where the code is typed.
type CodeResponse struct {
	URLs []string `json:"urls"`
}

// Issuer is what the socket hands a hash to (Service).
type Issuer interface {
	Issue(ctx context.Context, hash [32]byte) error
	RepairURLs() []string
}

// SocketDeps are the socket's collaborators.
type SocketDeps struct {
	Issuer Issuer
	Log    *slog.Logger
	// Leaf is the identity-repair-code leaf's files, loaded at every
	// handshake; nil when the identity CA did not load.
	Leaf *tlsca.LeafPaths
	// Dir is the socket's directory (/run/rasputin-repair), made 0700 and
	// owned by OwnerUID, the api's own uid.
	Dir      string
	OwnerUID int
	// PeerUID reads a connection's peer uid (PeerUID on Linux).
	PeerUID func(net.Conn) (int, error)
	// Linux is true on Linux, the one platform the peer uid can be read on.
	Linux bool
}

// Socket is the repair-code socket server.
type Socket struct {
	d   SocketDeps
	log *slog.Logger
}

// NewSocket checks d. It does no I/O.
func NewSocket(d SocketDeps) (*Socket, error) {
	switch {
	case d.Issuer == nil:
		return nil, errors.New("breakglass: SocketDeps.Issuer is nil")
	case d.Log == nil:
		return nil, errors.New("breakglass: SocketDeps.Log is nil")
	case d.Dir == "":
		return nil, errors.New("breakglass: SocketDeps.Dir is empty")
	case d.PeerUID == nil:
		return nil, errors.New("breakglass: SocketDeps.PeerUID is nil")
	}
	return &Socket{d: d, log: d.Log.With("component", "breakglass", "actor", "break-glass")}, nil
}

// Path is the socket's path.
func (s *Socket) Path() string { return filepath.Join(s.d.Dir, SocketName) }

// notServed logs why the socket is not served: ERROR on Linux, where the
// last resort is then missing, INFO elsewhere, where it never exists.
func (s *Socket) notServed(ctx context.Context, reason string, err error) {
	attrs := []any{"event", "breakglass.socket_not_served", "path", s.Path(), "reason", reason}
	if err != nil {
		attrs = append(attrs, "err", err.Error())
	}
	if !s.d.Linux {
		s.log.InfoContext(ctx, "The repair-code socket isn't served on this platform.", attrs...)
		return
	}
	s.log.ErrorContext(ctx, "The repair-code socket isn't served, so no repair code can be made on this control plane.", attrs...)
}

// Start binds the socket and serves it until ctx ends. It reports whether
// the socket is served; when it is not, it has logged why.
func (s *Socket) Start(ctx context.Context) bool {
	switch {
	case !s.d.Linux:
		s.notServed(ctx, "not_linux", nil)
		return false
	case s.d.Leaf == nil:
		s.notServed(ctx, "no_identity_ca", nil)
		return false
	}
	if _, err := privsock.PrepareDir(s.d.Dir, s.d.OwnerUID); err != nil {
		s.notServed(ctx, "dir", err)
		return false
	}
	if err := privsock.ClearStale(s.Path()); err != nil {
		reason := "stale"
		if errors.Is(err, privsock.ErrNotSocket) {
			reason = "not_a_socket"
		}
		s.notServed(ctx, reason, err)
		return false
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "unix", s.Path())
	if err != nil {
		s.notServed(ctx, "listen", err)
		return false
	}
	leaf := *s.d.Leaf
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			c, err := tls.LoadX509KeyPair(leaf.CertPath, leaf.KeyPath)
			if err != nil {
				return nil, err
			}
			return &c, nil
		},
	}
	srv := &http.Server{
		Handler:           s.handler(),
		ReadHeaderTimeout: socketIOBound,
		ReadTimeout:       socketIOBound,
		WriteTimeout:      socketIOBound,
		IdleTimeout:       socketIOBound,
		MaxHeaderBytes:    4 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.With("event", "breakglass.socket_conn_failed").Handler(), slog.LevelWarn),
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close() // the api is stopping; the listener's close removes the socket file
	}()
	go func() {
		if err := srv.Serve(tls.NewListener(peerListener{Listener: ln, uid: s.d.PeerUID, log: s.log}, tlsCfg)); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.ErrorContext(ctx, "The repair-code socket stopped serving.", "event", "breakglass.socket_not_served", "path", s.Path(), "reason", "serve", "err", err.Error())
		}
	}()
	s.log.InfoContext(ctx, "The repair-code socket is served.", "event", "breakglass.socket_served", "path", s.Path())
	return true
}

// handler serves POST /v1/code.
func (s *Socket) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+CodePath, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxCodeBody))
		var req CodeRequest
		var hash []byte
		if err == nil {
			err = json.Unmarshal(body, &req)
		}
		if err == nil {
			hash, err = hex.DecodeString(req.SHA256)
		}
		if err == nil && len(hash) != 32 {
			err = errors.New("the hash is not 32 bytes")
		}
		if err != nil {
			s.log.WarnContext(r.Context(), "The repair-code socket refused a request.", "event", "breakglass.socket_refused", "reason", "body", "err", err.Error())
			http.Error(w, "The request was not a repair code's hash.", http.StatusBadRequest)
			return
		}
		if err := s.d.Issuer.Issue(r.Context(), [32]byte(hash)); err != nil {
			s.log.ErrorContext(r.Context(), "The repair code could not be issued.", "event", "breakglass.issue_failed", "err", err.Error())
			http.Error(w, "The repair code could not be issued.", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(CodeResponse{URLs: s.d.Issuer.RepairURLs()}) // a failed write is the client's gone
	})
	return mux
}

// peerListener serves only connections whose peer is uid 0, closing every
// other one before TLS.
type peerListener struct {
	net.Listener
	uid func(net.Conn) (int, error)
	log *slog.Logger
}

func (l peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, err := l.uid(c)
		switch {
		case err != nil:
			l.log.Warn("The repair-code socket refused a connection whose peer couldn't be read.",
				"event", "breakglass.socket_refused", "reason", "peercred", "err", err.Error())
		case uid != 0:
			l.log.Warn("The repair-code socket refused a connection that isn't root's.",
				"event", "breakglass.socket_refused", "peer_uid", uid)
		default:
			return c, nil
		}
		_ = c.Close() // refused: nothing was read or written on it
	}
}
