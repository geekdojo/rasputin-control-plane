// Package secretstore is the api's client for the node secret store (OpenBao,
// ADR-0010), written on the standard library alone (geekdojo/geekdojo-brain#685
// F0.9, #758).
//
// Everything the client needs arrives through New: the address, the TLS
// config, the per-call bound and the logger. It reads no environment variable
// (no BAO_*, VAULT_* or HTTP(S)_PROXY), holds no global, and follows no
// redirect. It holds no token either: each call takes one, so the login and
// re-login session (#759) is built on top of this client rather than inside it.
//
// Every failure is an *Error of exactly one kind (errors.go), and none is ever
// reported as success. Mock is an in-memory store with the same semantics, for
// a configuration that names it explicitly; Disabled is the store that is not
// configured, and refuses every call with ErrDisabled.
package secretstore

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// maxBody is the largest response body the client reads. Anything longer is
// ErrProtocol; the store's answers here are a few kilobytes.
const maxBody = 1 << 20

// casMismatchText is how kv-v2 words a check-and-set mismatch in its 400. It
// is the one place the client reads the store's text to decide a kind: kv-v2
// answers every bad request with 400, and this sentence is what tells a lost
// race from a malformed call.
const casMismatchText = "check-and-set parameter did not match the current version"

// Config is everything a Client needs. New refuses an incomplete one.
type Config struct {
	// Addr is the store's address; ParseAddr's rules apply.
	Addr *url.URL
	// TLS must verify the server (RootCAs set, InsecureSkipVerify off). The
	// client uses a copy, raised to TLS 1.3 if it allowed less.
	// NewTLSConfig builds the one the composition root uses.
	TLS *tls.Config
	// CallTimeout bounds one method call, including the sys/health question
	// a 503 asks. It bounds I/O only and decides no state.
	CallTimeout time.Duration
	// Logger receives one record per failed call.
	Logger *slog.Logger
}

// Client talks to one store over mutually authenticated TLS.
type Client struct {
	base      string
	transport *http.Transport
	http      *http.Client
	timeout   time.Duration
	log       *slog.Logger
}

// errRedirect is CheckRedirect's refusal. Go does not drop a custom header
// such as X-Vault-Token on a redirect, so following one could hand the token
// to wherever the redirect points.
var errRedirect = errors.New("redirect refused")

// New checks cfg and returns a Client. It does no I/O.
func New(cfg Config) (*Client, error) {
	switch {
	case cfg.Logger == nil:
		return nil, errors.New("secretstore: Config.Logger is nil")
	case cfg.Addr == nil:
		return nil, errors.New("secretstore: Config.Addr is nil")
	case cfg.TLS == nil:
		return nil, errors.New("secretstore: Config.TLS is nil")
	case cfg.TLS.InsecureSkipVerify:
		return nil, errors.New("secretstore: Config.TLS skips server verification")
	case cfg.TLS.RootCAs == nil:
		return nil, errors.New("secretstore: Config.TLS has no RootCAs, so it would trust the system roots")
	case cfg.CallTimeout <= 0:
		return nil, fmt.Errorf("secretstore: Config.CallTimeout %v is not positive", cfg.CallTimeout)
	}
	addr, err := ParseAddr(cfg.Addr.String())
	if err != nil {
		return nil, err
	}
	tlsCfg := cfg.TLS.Clone()
	tlsCfg.MinVersion = max(tlsCfg.MinVersion, tls.VersionTLS13)
	transport := &http.Transport{
		// Proxy nil: no HTTP(S)_PROXY is consulted. The store is on loopback.
		Proxy:               nil,
		DialContext:         (&net.Dialer{}).DialContext,
		TLSClientConfig:     tlsCfg,
		MaxIdleConnsPerHost: 4,
	}
	return &Client{
		base:      addr.String(),
		transport: transport,
		http: &http.Client{
			Transport:     transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect },
		},
		timeout: cfg.CallTimeout,
		log:     cfg.Logger,
	}, nil
}

// CloseIdleConnections drops every idle connection, so the next call makes a
// new handshake and presents the client leaf now on disk. It is the client
// leaf's reload hook.
func (c *Client) CloseIdleConnections() { c.transport.CloseIdleConnections() }

// Health asks the store's sys/health. A 200 that says initialised and
// unsealed is a Health and no error. 501 is ErrUninitialised, 503 ErrSealed,
// 429, 472 and 473 (a standby or secondary) ErrUnreachable, and a body that
// contradicts its code ErrProtocol.
func (c *Client) Health(ctx context.Context) (Health, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	h, e := c.health(ctx)
	if e != nil {
		return Health{}, c.failed(ctx, e)
	}
	return h, nil
}

// Read returns version of the secret at p, or the latest when version is 0.
func (c *Client) Read(ctx context.Context, token secret.Value, p KVPath, version int) (KV, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	kv, e := c.read(ctx, token, p, version)
	if e != nil {
		return KV{}, c.failed(ctx, e)
	}
	return kv, nil
}

// Write stores data at p as a new version and returns its number. cas is
// always sent: 0 creates the secret only if it does not exist, and n writes
// only if n is the current version. There is no write without check-and-set.
func (c *Client) Write(ctx context.Context, token secret.Value, p KVPath, data map[string]secret.Value, cas int) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	v, e := c.write(ctx, token, p, data, cas)
	if e != nil {
		return 0, c.failed(ctx, e)
	}
	return v, nil
}

// Versions returns the version history of the secret at p.
func (c *Client) Versions(ctx context.Context, token secret.Value, p KVPath) (Metadata, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	m, e := c.versions(ctx, token, p)
	if e != nil {
		return Metadata{}, c.failed(ctx, e)
	}
	return m, nil
}

// failed writes the client's one record for a failed call and returns e. The
// level is DEBUG for the outcomes a caller expects (not found, a lost
// check-and-set race), ERROR for a protocol error, and WARN for the rest.
//
// A Health call that finds the store sealed, uninitialised or unreachable is
// DEBUG too: asking whether the store is ready is how its callers find out it
// is not, and each logs that outcome itself (the readiness monitor once per
// change, the audit rotator per run), so a WARN here would repeat on every
// alerts poll while the store is down (geekdojo/geekdojo-brain#760).
func (c *Client) failed(ctx context.Context, e *Error) error {
	level := slog.LevelWarn
	switch e.Kind {
	case ErrNotFound, ErrCASMismatch:
		level = slog.LevelDebug
	case ErrProtocol:
		level = slog.LevelError
	case ErrSealed, ErrUninitialised, ErrUnreachable:
		if e.Op == "health" {
			level = slog.LevelDebug
		}
	}
	c.log.LogAttrs(ctx, level, "secret store call failed",
		append([]slog.Attr{slog.String("component", "secretstore")}, e.LogAttrs()...)...)
	return e
}

// ----- operations ----------------------------------------------------------

func (c *Client) health(ctx context.Context) (Health, *Error) {
	const op = "health"
	status, body, e := c.round(ctx, op, KVPath{}, http.MethodGet, "/v1/sys/health", nil, nil)
	if e != nil {
		return Health{}, e
	}
	defer clear(body)
	var hb struct {
		Initialized *bool  `json:"initialized"`
		Sealed      *bool  `json:"sealed"`
		Standby     bool   `json:"standby"`
		Version     string `json:"version"`
	}
	fail := func(kind, cause error) (Health, *Error) {
		return Health{}, &Error{Op: op, Status: status, Kind: kind, Err: cause}
	}
	switch status {
	case http.StatusTooManyRequests, 472, 473:
		return fail(ErrUnreachable, errors.New("the store is a standby or a secondary"))
	}
	if err := decodeJSON(body, &hb); err != nil {
		return fail(ErrProtocol, err)
	}
	if hb.Initialized == nil || hb.Sealed == nil {
		return fail(ErrProtocol, errors.New("health body lacks initialized or sealed"))
	}
	h := Health{Initialized: *hb.Initialized, Sealed: *hb.Sealed, Standby: hb.Standby, Version: hb.Version}
	switch status {
	case http.StatusOK:
		if !h.Initialized || h.Sealed {
			return fail(ErrProtocol, errors.New("health 200 says uninitialised or sealed"))
		}
		return h, nil
	case http.StatusNotImplemented:
		if h.Initialized {
			return fail(ErrProtocol, errors.New("health 501 says initialised"))
		}
		return fail(ErrUninitialised, nil)
	case http.StatusServiceUnavailable:
		if !h.Sealed || !h.Initialized {
			return fail(ErrProtocol, errors.New("health 503 says unsealed or uninitialised"))
		}
		return fail(ErrSealed, nil)
	}
	if status >= 500 {
		return fail(ErrUnreachable, nil)
	}
	return fail(ErrProtocol, errors.New("unexpected health status"))
}

func (c *Client) read(ctx context.Context, token secret.Value, p KVPath, version int) (KV, *Error) {
	const op = "read"
	if !p.valid() {
		return KV{}, fail(op, p, ErrInvalidValue, errors.New("the path is the zero KVPath"))
	}
	if version < 0 {
		return KV{}, fail(op, p, ErrInvalidValue, fmt.Errorf("version %d is negative", version))
	}
	rel := "/v1/" + p.mount + "/data/" + p.path
	if version > 0 {
		rel += "?version=" + strconv.Itoa(version)
	}
	status, body, e := c.round(ctx, op, p, http.MethodGet, rel, &token, nil)
	if e != nil {
		return KV{}, e
	}
	defer clear(body)
	if status != http.StatusOK {
		return KV{}, c.statusError(ctx, op, p, status, body)
	}
	var env struct {
		Data *struct {
			Data     map[string]json.RawMessage `json:"data"`
			Metadata struct {
				CreatedTime  string `json:"created_time"`
				DeletionTime string `json:"deletion_time"`
				Destroyed    bool   `json:"destroyed"`
				Version      int    `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := decodeJSON(body, &env); err != nil {
		return KV{}, withStatus(fail(op, p, ErrProtocol, err), status)
	}
	if env.Data != nil {
		defer func() {
			for _, raw := range env.Data.Data {
				clear(raw)
			}
		}()
	}
	if env.Data == nil || env.Data.Data == nil {
		return KV{}, withStatus(fail(op, p, ErrNotFound, errors.New("the version holds no data")), status)
	}
	md := env.Data.Metadata
	if md.DeletionTime != "" || md.Destroyed {
		return KV{}, withStatus(fail(op, p, ErrNotFound, errors.New("the version is deleted or destroyed")), status)
	}
	if md.Version < 1 || (version > 0 && md.Version != version) {
		return KV{}, withStatus(fail(op, p, ErrProtocol, errors.New("the answer is for another version")), status)
	}
	created, err := parseTime(md.CreatedTime)
	if err != nil {
		return KV{}, withStatus(fail(op, p, ErrProtocol, err), status)
	}
	kv := KV{Data: make(map[string]secret.Value, len(env.Data.Data)), Version: md.Version, CreatedTime: created}
	for k, raw := range env.Data.Data {
		v, err := decodeValue(raw)
		if err != nil {
			kv.Destroy()
			return KV{}, withStatus(fail(op, p, ErrProtocol, err), status)
		}
		kv.Data[k] = v
	}
	return kv, nil
}

func (c *Client) write(ctx context.Context, token secret.Value, p KVPath, data map[string]secret.Value, cas int) (int, *Error) {
	const op = "write"
	if !p.valid() {
		return 0, fail(op, p, ErrInvalidValue, errors.New("the path is the zero KVPath"))
	}
	if err := checkWrite(data, cas); err != nil {
		return 0, fail(op, p, ErrInvalidValue, err)
	}
	reqBody := encodeWrite(data, cas)
	status, body, e := c.round(ctx, op, p, http.MethodPost, "/v1/"+p.mount+"/data/"+p.path, &token, reqBody)
	if e != nil {
		return 0, e
	}
	defer clear(body)
	if status != http.StatusOK {
		return 0, c.statusError(ctx, op, p, status, body)
	}
	var env struct {
		Data *struct {
			Version int `json:"version"`
		} `json:"data"`
	}
	if err := decodeJSON(body, &env); err != nil {
		return 0, withStatus(fail(op, p, ErrProtocol, err), status)
	}
	if env.Data == nil || env.Data.Version != cas+1 {
		return 0, withStatus(fail(op, p, ErrProtocol, errors.New("the answer is not the version after the check-and-set one")), status)
	}
	return env.Data.Version, nil
}

func (c *Client) versions(ctx context.Context, token secret.Value, p KVPath) (Metadata, *Error) {
	const op = "versions"
	if !p.valid() {
		return Metadata{}, fail(op, p, ErrInvalidValue, errors.New("the path is the zero KVPath"))
	}
	status, body, e := c.round(ctx, op, p, http.MethodGet, "/v1/"+p.mount+"/metadata/"+p.path, &token, nil)
	if e != nil {
		return Metadata{}, e
	}
	defer clear(body)
	if status != http.StatusOK {
		return Metadata{}, c.statusError(ctx, op, p, status, body)
	}
	var env struct {
		Data *struct {
			CreatedTime    string `json:"created_time"`
			UpdatedTime    string `json:"updated_time"`
			CurrentVersion int    `json:"current_version"`
			OldestVersion  int    `json:"oldest_version"`
			Versions       map[string]struct {
				CreatedTime  string `json:"created_time"`
				DeletionTime string `json:"deletion_time"`
				Destroyed    bool   `json:"destroyed"`
			} `json:"versions"`
		} `json:"data"`
	}
	if err := decodeJSON(body, &env); err != nil {
		return Metadata{}, withStatus(fail(op, p, ErrProtocol, err), status)
	}
	if env.Data == nil {
		return Metadata{}, withStatus(fail(op, p, ErrNotFound, errors.New("no metadata")), status)
	}
	d := env.Data
	m := Metadata{CurrentVersion: d.CurrentVersion, OldestVersion: d.OldestVersion, Versions: make(map[int]VersionMetadata, len(d.Versions))}
	var errs []error
	var err error
	m.CreatedTime, err = parseTime(d.CreatedTime)
	errs = append(errs, err)
	m.UpdatedTime, err = parseTime(d.UpdatedTime)
	errs = append(errs, err)
	for k, v := range d.Versions {
		n, err := strconv.Atoi(k)
		if err != nil || n < 1 {
			errs = append(errs, errors.New("a version key is not a positive number"))
			continue
		}
		var vm VersionMetadata
		vm.CreatedTime, err = parseTime(v.CreatedTime)
		errs = append(errs, err)
		vm.DeletionTime, err = parseTime(v.DeletionTime)
		errs = append(errs, err)
		vm.Destroyed = v.Destroyed
		m.Versions[n] = vm
	}
	if err := errors.Join(errs...); err != nil {
		return Metadata{}, withStatus(fail(op, p, ErrProtocol, err), status)
	}
	return m, nil
}

// statusError is the *Error for a KV call's non-200 answer. A 503 is
// classified by asking sys/health, which answers sealed or uninitialised as a
// fact, rather than by reading the 503's text.
func (c *Client) statusError(ctx context.Context, op string, p KVPath, status int, body []byte) *Error {
	e := withStatus(fail(op, p, nil, nil), status)
	e.StoreMessages = storeMessages(body)
	switch {
	case status == http.StatusForbidden:
		e.Kind = ErrDenied
	case status == http.StatusNotFound:
		e.Kind = ErrNotFound
	case status == http.StatusBadRequest:
		e.Kind = ErrProtocol
		if slices.ContainsFunc(e.StoreMessages, func(m string) bool { return strings.Contains(m, casMismatchText) }) {
			e.Kind = ErrCASMismatch
		}
	case status == http.StatusServiceUnavailable:
		e.Kind = ErrUnreachable
		if _, he := c.health(ctx); he != nil {
			switch he.Kind {
			case ErrSealed, ErrUninitialised:
				e.Kind = he.Kind
			default:
				e.Err = fmt.Errorf("sys/health after the 503: %s", kindName(he.Kind))
			}
		} else {
			e.Err = errors.New("sys/health after the 503 answered healthy")
		}
	case status >= 500:
		e.Kind = ErrUnreachable
	default:
		e.Kind = ErrProtocol
		e.Err = errors.New("unexpected status")
	}
	return e
}

// ----- transport -----------------------------------------------------------

// round sends one request and returns the status and the whole body, which
// the caller clears. token, when not nil, is set only in X-Vault-Token: never
// in the URL, the body or a log. reqBody is cleared once the transport is
// done with it.
func (c *Client) round(ctx context.Context, op string, p KVPath, method, rel string, token *secret.Value, reqBody []byte) (int, []byte, *Error) {
	var rd io.Reader
	if reqBody != nil {
		rd = &clearingBody{b: reqBody}
	} else {
		rd = http.NoBody
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+rel, rd)
	if err != nil {
		if cb, ok := rd.(*clearingBody); ok {
			_ = cb.Close()
		}
		return 0, nil, fail(op, p, ErrProtocol, err)
	}
	if reqBody != nil {
		req.ContentLength = int64(len(reqBody))
		req.Header.Set("Content-Type", "application/json")
	}
	if token != nil {
		req.Header.Set("X-Vault-Token", string(token.Reveal()))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		kind, cause := classifyTransport(ctx, err)
		return 0, nil, fail(op, p, kind, cause)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		clear(body)
		kind, cause := classifyTransport(ctx, err)
		return 0, nil, withStatus(fail(op, p, kind, cause), resp.StatusCode)
	}
	if len(body) > maxBody {
		clear(body)
		return 0, nil, withStatus(fail(op, p, ErrProtocol, errors.New("response body is over 1 MiB")), resp.StatusCode)
	}
	return resp.StatusCode, body, nil
}

// classifyTransport is the kind of a request that got no complete answer.
func classifyTransport(ctx context.Context, err error) (kind, cause error) {
	// A cancelled or expired call says so in errors.Is, whatever layer the
	// transport noticed it in.
	if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
		err = fmt.Errorf("%w: %w", ctxErr, err)
	}
	var verr *tls.CertificateVerificationError
	var lerr *leafError
	switch {
	case errors.Is(err, errRedirect):
		return ErrProtocol, err
	case errors.As(err, &verr):
		return ErrUnreachable, fmt.Errorf("server certificate not trusted: %w", err)
	case errors.As(err, &lerr):
		return ErrUnreachable, err
	case clientCertRefused(err):
		return ErrDenied, fmt.Errorf("client certificate refused: %w", err)
	}
	return ErrUnreachable, err
}

// refusalAlerts are the TLS alerts a server sends about the client's
// certificate: bad_certificate (42), certificate_unknown (46), unknown_ca
// (48) and certificate_required (116).
var refusalAlerts = []tls.AlertError{42, 46, 48, 116}

// clientCertRefused reports whether err is the server refusing our client
// certificate.
//
// crypto/tls reports an alert the PEER sent as a *net.OpError with Op
// "remote error" wrapping its unexported alert type, never as tls.AlertError
// (which it uses for QUIC). The unexported alert and tls.AlertError render the
// same text for the same code, so the code is matched through that text, read
// from the standard library itself rather than written here
// (geekdojo/geekdojo-brain#758, F-758-07). tls.AlertError is matched too, so a
// future crypto/tls that returns it still classifies.
func clientCertRefused(err error) bool {
	var ae tls.AlertError
	if errors.As(err, &ae) && slices.Contains(refusalAlerts, ae) {
		return true
	}
	var op *net.OpError
	if !errors.As(err, &op) || op.Op != "remote error" || op.Err == nil {
		return false
	}
	text := op.Err.Error()
	return slices.ContainsFunc(refusalAlerts, func(a tls.AlertError) bool { return a.Error() == text })
}

// clearingBody is a request body that zeroes its bytes when the transport
// closes it, which the transport does once it has finished writing, even
// after Do has returned.
type clearingBody struct {
	mu  sync.Mutex
	b   []byte
	off int
}

func (r *clearingBody) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.off >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.off:])
	r.off += n
	return n, nil
}

func (r *clearingBody) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	clear(r.b)
	r.off = len(r.b)
	return nil
}

// ----- encoding ------------------------------------------------------------

// encodeWrite is the kv-v2 write body, {"options":{"cas":N},"data":{…}},
// built into one buffer the transport clears. The buffer is sized for the
// worst case up front, so it is never reallocated and no uncleared copy of a
// value is left behind. Keys are sorted, so the body is the same for the same
// input.
func encodeWrite(data map[string]secret.Value, cas int) []byte {
	keys := make([]string, 0, len(data))
	size := len(`{"options":{"cas":},"data":{}}`) + 20
	for k, v := range data {
		keys = append(keys, k)
		// Each byte escapes to at most 6 (\u00XX); 2 quotes each, a colon
		// and a comma.
		size += 6*(len(k)+v.Len()) + 6
	}
	slices.Sort(keys)
	b := make([]byte, 0, size)
	b = append(b, `{"options":{"cas":`...)
	b = strconv.AppendInt(b, int64(cas), 10)
	b = append(b, `},"data":{`...)
	for i, k := range keys {
		if i > 0 {
			b = append(b, ',')
		}
		b = appendJSONString(b, []byte(k))
		b = append(b, ':')
		b = appendJSONString(b, data[k].Reveal())
	}
	return append(b, `}}`...)
}

// appendJSONString appends s as a JSON string. s is valid UTF-8 (checkWrite).
// It escapes byte by byte, so the bytes never pass through a string that
// could not be zeroed.
func appendJSONString(b, s []byte) []byte {
	const hex = "0123456789abcdef"
	b = append(b, '"')
	for _, c := range s {
		switch {
		case c == '"' || c == '\\':
			b = append(b, '\\', c)
		case c < 0x20:
			b = append(b, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
		default:
			b = append(b, c)
		}
	}
	return append(b, '"')
}

// decodeValue turns one kv-v2 value into a secret.Value. Only a JSON string
// is a value; anything else is the store holding something this client did
// not write.
func decodeValue(raw json.RawMessage) (secret.Value, error) {
	if len(raw) == 0 || raw[0] != '"' {
		return secret.Value{}, errors.New("a value is not a JSON string")
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return secret.Value{}, errors.New("a value is not a valid JSON string")
	}
	b := []byte(s)
	v := secret.New(b)
	clear(b)
	return v, nil
}

// decodeJSON decodes body into v. Its error never quotes the body: a JSON
// syntax error names only the offset.
func decodeJSON(body []byte, v any) error {
	if err := json.Unmarshal(body, v); err != nil {
		var se *json.SyntaxError
		if errors.As(err, &se) {
			return fmt.Errorf("malformed JSON at offset %d", se.Offset)
		}
		return errors.New("JSON of an unexpected shape")
	}
	return nil
}

// storeMessages is the "errors" list of an error body, or nil.
func storeMessages(body []byte) []string {
	var eb struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(body, &eb) != nil {
		return nil
	}
	return eb.Errors
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, errors.New("a time is not RFC 3339")
	}
	return t, nil
}

func withStatus(e *Error, status int) *Error {
	e.Status = status
	return e
}
