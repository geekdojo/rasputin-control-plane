// Package idclient is the api's admin and token client for the identity
// service (Keycloak, ADR-0013), written on the standard library alone
// (geekdojo/geekdojo-brain#978, Identity 3.2).
//
// Everything the client needs arrives through New: the two loopback
// addresses, the TLS config, the per-call bound and the logger. It reads no
// environment variable (no KC_*, SSL_CERT_FILE or HTTP(S)_PROXY), holds no
// global, and follows no redirect. It holds no token either: Admin takes one,
// and Session (session.go) is the login and re-login rule built on top.
//
// Every failure is an *Error of exactly one kind (errors.go), and none is ever
// reported as success. Disabled is the client of a configuration that has no
// identity service, or the mock's, and refuses every call.
package idclient

import (
	"bytes"
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
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/looptls"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// maxBody is the largest response body the client reads. Anything longer is
// ErrProtocol; the service's answers here are a few kilobytes.
const maxBody = 1 << 20

// adminPrefix is the one path prefix Admin sends to.
const adminPrefix = "/admin/realms/"

// Config is everything a Client needs. New refuses an incomplete one.
type Config struct {
	// Addr is the service's https listener; MgmtAddr its management
	// listener, which serves /health/ready. looptls.ParseAddr's rules apply
	// to both.
	Addr, MgmtAddr *url.URL
	// TLS must verify the server (RootCAs set, InsecureSkipVerify off). The
	// client uses a copy, raised to TLS 1.3 if it allowed less.
	TLS *tls.Config
	// CallTimeout bounds one method call. It bounds I/O only and decides no
	// state.
	CallTimeout time.Duration
	// Logger receives one record per failed call.
	Logger *slog.Logger
}

// Response is what a successful Admin call answered.
type Response struct {
	Status int
	// Location is the Location header, set by a create.
	Location string
}

// Client talks to one identity service over mutually authenticated TLS.
type Client struct {
	base, mgmt string
	transport  *http.Transport
	http       *http.Client
	timeout    time.Duration
	log        *slog.Logger
}

// errRedirect is CheckRedirect's refusal. Following a redirect could hand
// the Authorization header or a client secret to wherever it points.
var errRedirect = errors.New("redirect refused")

// New checks cfg and returns a Client. It does no I/O.
func New(cfg Config) (*Client, error) {
	switch {
	case cfg.Logger == nil:
		return nil, errors.New("idclient: Config.Logger is nil")
	case cfg.Addr == nil:
		return nil, errors.New("idclient: Config.Addr is nil")
	case cfg.MgmtAddr == nil:
		return nil, errors.New("idclient: Config.MgmtAddr is nil")
	case cfg.TLS == nil:
		return nil, errors.New("idclient: Config.TLS is nil")
	case cfg.TLS.InsecureSkipVerify:
		return nil, errors.New("idclient: Config.TLS skips server verification")
	case cfg.TLS.RootCAs == nil:
		return nil, errors.New("idclient: Config.TLS has no RootCAs, so it would trust the system roots")
	case cfg.CallTimeout <= 0:
		return nil, fmt.Errorf("idclient: Config.CallTimeout %v is not positive", cfg.CallTimeout)
	}
	addr, err := looptls.ParseAddr(cfg.Addr.String())
	if err != nil {
		return nil, fmt.Errorf("idclient: %w", err)
	}
	mgmt, err := looptls.ParseAddr(cfg.MgmtAddr.String())
	if err != nil {
		return nil, fmt.Errorf("idclient: management %w", err)
	}
	tlsCfg := cfg.TLS.Clone()
	tlsCfg.MinVersion = max(tlsCfg.MinVersion, tls.VersionTLS13)
	transport := &http.Transport{
		// Proxy nil: no HTTP(S)_PROXY is consulted. The service is on loopback.
		Proxy:               nil,
		DialContext:         (&net.Dialer{}).DialContext,
		TLSClientConfig:     tlsCfg,
		MaxIdleConnsPerHost: 4,
	}
	return &Client{
		base:      addr.String(),
		mgmt:      mgmt.String(),
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

// ClientCredentials gets a client_credentials access token for clientID in
// realm. With clientSecret nil the client authenticates by client-x509 alone:
// the form carries only grant_type and client_id, and the TLS layer presents
// the client leaf. With a secret, its text goes only into the form body,
// built in one buffer that is zeroed once the call is done.
func (c *Client) ClientCredentials(ctx context.Context, realm, clientID string, clientSecret *secret.Value) (secret.Value, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	path := "/realms/" + url.PathEscape(realm) + "/protocol/openid-connect/token"
	if realm == "" || clientID == "" {
		return secret.Value{}, c.failed(ctx, &Error{Op: "token", Path: path, Kind: ErrInvalidValue,
			Err: errors.New("the realm or the client id is empty")})
	}
	tok, e := c.token(ctx, path, tokenForm(clientID, clientSecret))
	if e != nil {
		return secret.Value{}, c.failed(ctx, e)
	}
	return tok, nil
}

// Admin sends one Admin API request with token as its bearer. path must
// start with /admin/realms/; anything else is ErrInvalidValue and nothing is
// sent. in, when not nil, is sent as JSON; out, when not nil, takes a 2xx
// answer's JSON body. A 2xx is success; 401 is ErrTokenRefused, 403
// ErrForbidden, 404 ErrNotFound, 409 ErrConflict, 5xx ErrUnreachable, and
// anything else ErrProtocol.
func (c *Client) Admin(ctx context.Context, token secret.Value, method, path string, in, out any) (Response, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, e := c.admin(ctx, token, method, path, in, out)
	if e != nil {
		return Response{}, c.failed(ctx, e)
	}
	return resp, nil
}

// Ready asks the management listener's /health/ready: 200 with
// "status":"UP" is ready and nil. 5xx is ErrUnreachable; any other answer,
// a 200 that does not say UP included, is ErrProtocol.
func (c *Client) Ready(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if _, e := c.health(ctx, "ready"); e != nil {
		return c.failed(ctx, e)
	}
	return nil
}

// failed writes the client's one record for a failed call and returns e. The
// level is DEBUG for the outcomes a caller expects (not found, conflict) and
// for a readiness answer inside WaitReady, which asks until the service is
// ready; ERROR for a protocol error; WARN for the rest.
func (c *Client) failed(ctx context.Context, e *Error) error {
	level := slog.LevelWarn
	switch {
	case errors.Is(e.Kind, ErrNotFound), errors.Is(e.Kind, ErrConflict):
		level = slog.LevelDebug
	case e.Op == "ready" && inWait(ctx):
		level = slog.LevelDebug
	case errors.Is(e.Kind, ErrProtocol):
		level = slog.LevelError
	}
	c.log.LogAttrs(ctx, level, "identity service call failed",
		append([]slog.Attr{slog.String("component", "identity")}, e.LogAttrs()...)...)
	return e
}

// ----- operations ----------------------------------------------------------

// tokenForm is the token request's form body, built in one buffer sized up
// front, so no copy of the secret is left behind by a grow. roundLocation
// zeroes it when the call returns.
func tokenForm(clientID string, clientSecret *secret.Value) []byte {
	id := url.QueryEscape(clientID)
	size := len("grant_type=client_credentials&client_id=") + len(id)
	if clientSecret != nil {
		// Each byte escapes to at most three (%XX).
		size += len("&client_secret=") + 3*clientSecret.Len()
	}
	b := make([]byte, 0, size)
	b = append(b, "grant_type=client_credentials&client_id="...)
	b = append(b, id...)
	if clientSecret != nil {
		b = append(b, "&client_secret="...)
		b = appendQueryEscaped(b, clientSecret.Reveal())
	}
	return b
}

// appendQueryEscaped form-encodes s byte by byte, so the secret never passes
// through a string that could not be zeroed.
func appendQueryEscaped(b, s []byte) []byte {
	const hex = "0123456789ABCDEF"
	for _, ch := range s {
		switch {
		case 'a' <= ch && ch <= 'z', 'A' <= ch && ch <= 'Z', '0' <= ch && ch <= '9',
			ch == '-', ch == '_', ch == '.', ch == '~':
			b = append(b, ch)
		default:
			b = append(b, '%', hex[ch>>4], hex[ch&0xf])
		}
	}
	return b
}

// token posts form to the token endpoint at path and reads the access token.
// form is zeroed before it returns.
func (c *Client) token(ctx context.Context, path string, form []byte) (secret.Value, *Error) {
	const op = "token"
	status, body, e := c.round(ctx, op, c.base, http.MethodPost, path, nil, form, "application/x-www-form-urlencoded")
	if e != nil {
		return secret.Value{}, e
	}
	defer clear(body)
	fail := func(kind, cause error, oauth string) (secret.Value, *Error) {
		return secret.Value{}, &Error{Op: op, Path: path, Status: status, Kind: kind, Err: cause, OAuthError: oauth}
	}
	if status != http.StatusOK {
		var eb struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &eb) // a body that is not JSON leaves the code empty
		switch {
		case (status == http.StatusBadRequest || status == http.StatusUnauthorized) &&
			(eb.Error == "invalid_client" || eb.Error == "unauthorized_client"):
			return fail(ErrDenied, nil, eb.Error)
		case status >= 500:
			return fail(ErrUnreachable, nil, eb.Error)
		}
		return fail(ErrProtocol, errors.New("unexpected status"), eb.Error)
	}
	var tb struct {
		AccessToken json.RawMessage `json:"access_token"`
	}
	if err := decodeJSON(body, &tb); err != nil {
		return fail(ErrProtocol, err, "")
	}
	defer clear(tb.AccessToken)
	tok, err := decodeString(tb.AccessToken)
	if err != nil {
		return fail(ErrProtocol, errors.New("the answer carries no access token"), "")
	}
	return tok, nil
}

func (c *Client) admin(ctx context.Context, token secret.Value, method, path string, in, out any) (Response, *Error) {
	const op = "admin"
	if !strings.HasPrefix(path, adminPrefix) {
		return Response{}, &Error{Op: op, Path: path, Kind: ErrInvalidValue, Err: errors.New("the path is not under " + adminPrefix)}
	}
	var reqBody []byte
	contentType := ""
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return Response{}, &Error{Op: op, Path: path, Kind: ErrInvalidValue, Err: errors.New("the request body does not encode as JSON")}
		}
		reqBody, contentType = b, "application/json"
	}
	status, body, location, e := c.roundLocation(ctx, op, c.base, method, path, &token, reqBody, contentType)
	if e != nil {
		return Response{}, e
	}
	defer clear(body)
	fail := func(kind, cause error) (Response, *Error) {
		return Response{}, &Error{Op: op, Path: path, Status: status, Kind: kind, Err: cause}
	}
	switch {
	case status >= 200 && status < 300:
	case status == http.StatusUnauthorized:
		return fail(ErrTokenRefused, nil)
	case status == http.StatusForbidden:
		return fail(ErrForbidden, nil)
	case status == http.StatusNotFound:
		return fail(ErrNotFound, nil)
	case status == http.StatusConflict:
		return fail(ErrConflict, nil)
	case status >= 500:
		return fail(ErrUnreachable, nil)
	default:
		return fail(ErrProtocol, errors.New("unexpected status"))
	}
	if out != nil && len(bytes.TrimSpace(body)) > 0 {
		if err := decodeJSON(body, out); err != nil {
			return fail(ErrProtocol, err)
		}
	}
	return Response{Status: status, Location: location}, nil
}

// health asks /health/ready once as op and returns its report. A 200 that
// says UP is the report and nil. A 5xx is ErrUnreachable, with the report
// when its body is the health JSON (a 503 names each check's status), and
// with an empty one otherwise. Any other status, and a 200 whose body is not
// the health JSON or does not say UP, is ErrProtocol.
func (c *Client) health(ctx context.Context, op string) (HealthReport, *Error) {
	const path = "/health/ready"
	status, body, e := c.round(ctx, op, c.mgmt, http.MethodGet, path, nil, nil, "")
	if e != nil {
		return HealthReport{}, e
	}
	fail := func(kind, cause error) *Error {
		return &Error{Op: op, Path: path, Status: status, Kind: kind, Err: cause}
	}
	var rep HealthReport
	decodeErr := decodeJSON(body, &rep)
	if status >= 500 {
		if decodeErr != nil {
			rep = HealthReport{}
		}
		return rep, fail(ErrUnreachable, nil)
	}
	if status != http.StatusOK {
		return HealthReport{}, fail(ErrProtocol, errors.New("unexpected status"))
	}
	if decodeErr != nil {
		return HealthReport{}, fail(ErrProtocol, decodeErr)
	}
	if rep.Status != "UP" {
		return rep, fail(ErrProtocol, errors.New("health 200 does not say UP"))
	}
	return rep, nil
}

// ----- transport -----------------------------------------------------------

// round is roundLocation without the Location header.
func (c *Client) round(ctx context.Context, op, base, method, path string, token *secret.Value, reqBody []byte, contentType string) (int, []byte, *Error) {
	status, body, _, e := c.roundLocation(ctx, op, base, method, path, token, reqBody, contentType)
	return status, body, e
}

// roundLocation sends one request and returns the status, the whole body,
// which the caller clears, and the Location header. token, when not nil, is
// set only in Authorization: Bearer, never in the URL, the body or a log.
// reqBody is zeroed before it returns.
func (c *Client) roundLocation(ctx context.Context, op, base, method, path string, token *secret.Value, reqBody []byte, contentType string) (int, []byte, string, *Error) {
	fail := func(kind, cause error) *Error { return &Error{Op: op, Path: path, Kind: kind, Err: cause} }
	// The body is a *bytes.Reader, which net/http knows is in memory, so it
	// sends the headers and the body in one write. Any other reader makes it
	// flush the headers first; a server that refuses the client certificate
	// after the TLS 1.3 handshake then resets the connection under the second
	// write, and the refusal reads as a broken pipe rather than its alert.
	// The bytes are zeroed when the call returns.
	var rd io.Reader = http.NoBody
	if reqBody != nil {
		defer clear(reqBody)
		rd = bytes.NewReader(reqBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
	if err != nil {
		return 0, nil, "", fail(ErrInvalidValue, errors.New("the request could not be built"))
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	if token != nil {
		req.Header.Set("Authorization", "Bearer "+string(token.Reveal()))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		kind, cause := classifyTransport(ctx, err)
		return 0, nil, "", fail(kind, cause)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		clear(body)
		kind, cause := classifyTransport(ctx, err)
		e := fail(kind, cause)
		e.Status = resp.StatusCode
		return 0, nil, "", e
	}
	if len(body) > maxBody {
		clear(body)
		e := fail(ErrProtocol, errors.New("response body is over 1 MiB"))
		e.Status = resp.StatusCode
		return 0, nil, "", e
	}
	return resp.StatusCode, body, resp.Header.Get("Location"), nil
}

// classifyTransport is the kind of a request that got no complete answer.
func classifyTransport(ctx context.Context, err error) (kind, cause error) {
	// A cancelled or expired call says so in errors.Is, whatever layer the
	// transport noticed it in.
	if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
		err = fmt.Errorf("%w: %w", ctxErr, err)
	}
	var verr *tls.CertificateVerificationError
	switch {
	case errors.Is(err, errRedirect):
		return ErrProtocol, err
	case errors.As(err, &verr):
		return ErrUnreachable, fmt.Errorf("server certificate not trusted: %w", err)
	case looptls.IsLeafError(err):
		return ErrUnreachable, err
	case looptls.ClientCertRefused(err):
		return ErrDenied, fmt.Errorf("client certificate refused: %w", err)
	}
	return ErrUnreachable, err
}

// ----- encoding ------------------------------------------------------------

// decodeString turns one JSON string into a non-empty secret.Value.
func decodeString(raw json.RawMessage) (secret.Value, error) {
	if len(raw) == 0 || raw[0] != '"' {
		return secret.Value{}, errors.New("not a JSON string")
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil || s == "" {
		return secret.Value{}, errors.New("not a non-empty JSON string")
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
