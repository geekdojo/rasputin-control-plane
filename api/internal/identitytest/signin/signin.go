// Package signin is the Go headless sign-in client: it drives Keycloak's own
// login pages the way a browser would, reading each page by its
// data-page-id, and runs the OIDC authorization code flow with PKCE S256 to
// a token. It is the Go half of identity testing.md §6's harness; the
// Python half (#967) passes the same vector file
// (../testdata/signin-vectors.json). Today it knows one verb: a password
// sign-in.
//
// Tests import it; nothing in a shipped binary does.
package signin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// maxHops bounds the redirects and pages one sign-in may pass through. The
// password flow takes two pages and three redirects; a chain longer than
// this is a loop, never a slow server.
const maxHops = 16

// Config is the client's collaborators and the client registration it signs
// in to. Every field is required.
type Config struct {
	// Transport carries every request; it holds the TLS trust.
	Transport http.RoundTripper
	// Issuer is the realm's issuer URL; the endpoints are under it.
	Issuer string
	// ClientID and RedirectURI are the public client's.
	ClientID, RedirectURI string
	// Rand feeds the PKCE verifier, state and nonce.
	Rand io.Reader
	// Logger receives one DEBUG record per page. Nothing secret is logged.
	Logger *slog.Logger
}

// Client signs in. It holds no state between calls: each call gets a fresh
// cookie jar, so two sign-ins never share a session.
type Client struct {
	cfg Config
}

// New checks cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	missing := ""
	switch {
	case cfg.Transport == nil:
		missing = "Transport is nil"
	case cfg.Issuer == "":
		missing = "Issuer is empty"
	case cfg.ClientID == "":
		missing = "ClientID is empty"
	case cfg.RedirectURI == "":
		missing = "RedirectURI is empty"
	case cfg.Rand == nil:
		missing = "Rand is nil"
	case cfg.Logger == nil:
		missing = "Logger is nil"
	}
	if missing != "" {
		return nil, errors.New("signin: Config." + missing)
	}
	return &Client{cfg: cfg}, nil
}

// Result is what a sign-in shows: the page ids it passed, in order, and the
// ID token's claims. The tokens themselves are never returned.
type Result struct {
	PageIDs []string
	Claims  Claims
}

// Claims are the ID token claims a test asserts. The token's signature is
// not checked: the token came over the TLS connection to the issuer.
type Claims struct {
	Iss   string
	Sub   string
	Aud   []string
	Nonce string
}

// The flow's errors. Each is wrapped with %w, so errors.Is and errors.As
// find it.
var (
	// ErrStateMismatch is a redirect to RedirectURI carrying another state.
	ErrStateMismatch = errors.New("signin: the redirect carried a different state")
	// ErrNonceMismatch is an ID token carrying another nonce.
	ErrNonceMismatch = errors.New("signin: the ID token carried a different nonce")
	// ErrNoRedirect is a chain that never reached RedirectURI.
	ErrNoRedirect = errors.New("signin: the sign-in never redirected to the client's redirect URI")
)

// RefusedError is the server refusing the sign-in on a page: login-error, or
// login-login shown again after the credentials were posted. Message is the
// page's feedback sentence.
type RefusedError struct {
	PageID, Message string
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("signin: refused on %s: %q", e.PageID, e.Message)
}

// UnexpectedPageError is a known page that is not a step of this verb.
type UnexpectedPageError struct{ PageID string }

func (e *UnexpectedPageError) Error() string {
	return fmt.Sprintf("signin: the page %s (%s) is not a step of a password sign-in", e.PageID, KnownPages[e.PageID])
}

// TokenError is the token endpoint refusing the code. It carries the status
// and the OAuth error code only; the body may hold anything else.
type TokenError struct {
	Status     int
	OAuthError string
}

func (e *TokenError) Error() string {
	return fmt.Sprintf("signin: the token endpoint answered %d %s", e.Status, e.OAuthError)
}

// flow is one sign-in's state.
type flow struct {
	c      *Client
	http   *http.Client
	state  string
	nonce  string
	pages  []string
	posted bool
}

// PasswordCodeFlow signs user in with password: the authorization request
// (prompt=login, state, nonce, S256), the sign-in form posted to the page's
// own action, the redirect to RedirectURI with the same state, and the code
// exchanged with the verifier. It returns the page ids seen and the ID
// token's claims.
func (c *Client) PasswordCodeFlow(ctx context.Context, user string, password secret.Value) (Result, error) {
	verifier, err := Verifier(c.cfg.Rand)
	if err != nil {
		return Result{}, err
	}
	state, err := token(c.cfg.Rand)
	if err != nil {
		return Result{}, fmt.Errorf("signin: state: %w", err)
	}
	nonce, err := token(c.cfg.Rand)
	if err != nil {
		return Result{}, fmt.Errorf("signin: nonce: %w", err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return Result{}, fmt.Errorf("signin: cookie jar: %w", err)
	}
	f := &flow{
		c: c, state: state, nonce: nonce,
		http: &http.Client{
			Transport: c.cfg.Transport, Jar: jar,
			// Redirects are followed by hand, so each page and the final
			// redirect are seen.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	defer f.http.CloseIdleConnections()

	q := url.Values{
		"client_id":             {c.cfg.ClientID},
		"redirect_uri":          {c.cfg.RedirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {Challenge(verifier)},
		"code_challenge_method": {"S256"},
		"prompt":                {"login"},
	}
	code, err := f.walk(ctx, c.cfg.Issuer+"/protocol/openid-connect/auth?"+q.Encode(), user, password)
	if err != nil {
		return Result{PageIDs: f.pages}, err
	}
	claims, err := f.exchange(ctx, code, verifier)
	if err != nil {
		return Result{PageIDs: f.pages}, err
	}
	if claims.Nonce != nonce {
		return Result{PageIDs: f.pages}, ErrNonceMismatch
	}
	return Result{PageIDs: f.pages, Claims: claims}, nil
}

// walk follows redirects and pages from start until a redirect to
// RedirectURI, and returns its code.
func (f *flow) walk(ctx context.Context, start, user string, password secret.Value) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, start, nil)
	if err != nil {
		return "", fmt.Errorf("signin: authorization request: %w", err)
	}
	for range maxHops {
		resp, err := f.http.Do(req)
		if err != nil {
			return "", fmt.Errorf("signin: %s %s: %w", req.Method, redact(req.URL), err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close() // the body is read; a failed close only drops the connection
		if err != nil {
			return "", fmt.Errorf("signin: read %s: %w", redact(req.URL), err)
		}
		switch {
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			loc, err := resp.Location()
			if err != nil {
				return "", fmt.Errorf("signin: a %d from %s with no usable Location: %w", resp.StatusCode, redact(req.URL), err)
			}
			if strings.HasPrefix(loc.String(), f.c.cfg.RedirectURI) {
				return f.callback(loc)
			}
			if req, err = http.NewRequestWithContext(ctx, http.MethodGet, loc.String(), nil); err != nil {
				return "", fmt.Errorf("signin: follow the redirect: %w", err)
			}
		case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized:
			// Keycloak serves a refused sign-in's page with 200 or 4xx.
			page, err := ParsePage(body)
			if err != nil {
				return "", err
			}
			f.pages = append(f.pages, page.ID)
			f.c.cfg.Logger.Debug("sign-in page", "page_id", page.ID, "status", resp.StatusCode)
			if req, err = f.next(ctx, resp.Request.URL, page, user, password); err != nil {
				return "", err
			}
		default:
			return "", fmt.Errorf("signin: %s answered %d", redact(req.URL), resp.StatusCode)
		}
	}
	return "", fmt.Errorf("%w within %d hops", ErrNoRedirect, maxHops)
}

// next is the request a page leads to.
func (f *flow) next(ctx context.Context, at *url.URL, page Page, user string, password secret.Value) (*http.Request, error) {
	switch page.ID {
	case "login-error":
		return nil, &RefusedError{PageID: page.ID, Message: page.Alert}
	case "login-login":
		if f.posted {
			return nil, &RefusedError{PageID: page.ID, Message: page.Alert}
		}
		form, ok := page.Form("kc-form-login")
		if !ok {
			return nil, fmt.Errorf("signin: the page %s has no form kc-form-login", page.ID)
		}
		action, err := at.Parse(form.Action)
		if err != nil {
			return nil, fmt.Errorf("signin: the sign-in form's action: %w", err)
		}
		f.posted = true
		return postForm(ctx, action, form.Fields, user, password)
	default:
		return nil, &UnexpectedPageError{PageID: page.ID}
	}
}

// postForm is the sign-in form's POST: the page's own fields, with the user
// name and the password filled in. The body is the one place the password
// leaves its secret.Value; http.NewRequest copies nothing more than the
// reader, which is drained by the send.
func postForm(ctx context.Context, action *url.URL, fields map[string]string, user string, password secret.Value) (*http.Request, error) {
	v := url.Values{}
	for k, val := range fields {
		if k != "password" {
			v.Set(k, val)
		}
	}
	v.Set("username", user)
	body := []byte(v.Encode() + "&password=")
	body = append(body, []byte(url.QueryEscape(string(password.Reveal())))...)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, action.String(), bytes.NewReader(body))
	if err != nil {
		clear(body)
		return nil, fmt.Errorf("signin: the sign-in form's request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// callback reads the redirect to RedirectURI: its state must be the one
// sent, and it must carry a code or an OAuth error.
func (f *flow) callback(loc *url.URL) (string, error) {
	q := loc.Query()
	if q.Get("state") != f.state {
		return "", ErrStateMismatch
	}
	if e := q.Get("error"); e != "" {
		return "", fmt.Errorf("signin: the redirect carried the OAuth error %s", e)
	}
	code := q.Get("code")
	if code == "" {
		return "", fmt.Errorf("signin: the redirect to %s carried no code", f.c.cfg.RedirectURI)
	}
	return code, nil
}

// exchange trades the code and verifier for tokens at the token endpoint and
// returns the ID token's claims. The body is cleared after parsing.
func (f *flow) exchange(ctx context.Context, code, verifier string) (Claims, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.c.cfg.RedirectURI},
		"client_id":     {f.c.cfg.ClientID},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.c.cfg.Issuer+"/protocol/openid-connect/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return Claims{}, fmt.Errorf("signin: token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.http.Do(req)
	if err != nil {
		return Claims{}, fmt.Errorf("signin: token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	defer clear(body)
	if err != nil {
		return Claims{}, fmt.Errorf("signin: read the token answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e) // a body that is not JSON leaves the code empty
		return Claims{}, &TokenError{Status: resp.StatusCode, OAuthError: e.Error}
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.IDToken == "" {
		return Claims{}, errors.New("signin: the token answer carried no id_token")
	}
	return idTokenClaims(tok.IDToken)
}

// idTokenClaims decodes the ID token's payload. aud may be a string or an
// array (OIDC Core §2).
func idTokenClaims(jwt string) (Claims, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("signin: the id_token is not a JWS compact serialization")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("signin: the id_token payload: %w", err)
	}
	defer clear(payload)
	var raw struct {
		Iss   string          `json:"iss"`
		Sub   string          `json:"sub"`
		Aud   json.RawMessage `json:"aud"`
		Nonce string          `json:"nonce"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return Claims{}, fmt.Errorf("signin: the id_token payload: %w", err)
	}
	c := Claims{Iss: raw.Iss, Sub: raw.Sub, Nonce: raw.Nonce}
	var one string
	if err := json.Unmarshal(raw.Aud, &one); err == nil {
		c.Aud = []string{one}
	} else if err := json.Unmarshal(raw.Aud, &c.Aud); err != nil {
		return Claims{}, fmt.Errorf("signin: the id_token aud: %w", err)
	}
	return c, nil
}

// token is 16 random bytes as unpadded base64url, for state and nonce.
func token(r io.Reader) (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// redact is a URL without its query, which may carry a code or session id.
func redact(u *url.URL) string {
	c := *u
	c.RawQuery = ""
	return c.String()
}
