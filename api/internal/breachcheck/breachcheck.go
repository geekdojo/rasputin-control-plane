// Package breachcheck asks a public breached-password list whether a
// password appears in it (geekdojo/geekdojo-brain#1145, PR 2): the range
// API of Have I Been Pwned's Pwned Passwords, by k-anonymity. Only the first
// 5 hex characters of the password's SHA-1 leave the process; the answer is
// every listed suffix under that prefix, padded with entries of count 0, and
// the match is made here.
//
// It is a client of a public API and nothing more: it keeps no cache, logs
// nothing and stores nothing. Its errors never hold the URL, so they never
// hold the prefix.
package breachcheck

import (
	"bytes"
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// ErrUnexpectedAnswer is an answer the checker cannot read: a status other
// than 200, a malformed line, or a body over maxBody.
var ErrUnexpectedAnswer = errors.New("breach check: unexpected range answer")

const (
	// maxBody bounds the answer read. A padded answer is about 83 KB.
	maxBody = 1 << 20
	// prefixLen and suffixLen split the 40 hex characters of a SHA-1.
	prefixLen = 5
	suffixLen = 40 - prefixLen
	// userAgent is the one header the API recommends for these endpoints.
	userAgent = "Rasputin"
	hexUpper  = "0123456789ABCDEF"
)

// Config is the checker's collaborators. New refuses a missing one.
type Config struct {
	// Client is the HTTP client the range request goes through.
	Client *http.Client
	// Base is the range endpoint, https://api.pwnedpasswords.com/range; the
	// prefix is its last path segment.
	Base *url.URL
	// CallTimeout bounds the one range request a check makes.
	CallTimeout time.Duration
}

// Checker is the breached-password check.
type Checker struct {
	client  *http.Client
	base    *url.URL
	timeout time.Duration
}

// New checks cfg and builds the checker. It does no I/O.
func New(cfg Config) (*Checker, error) {
	switch {
	case cfg.Client == nil:
		return nil, errors.New("breachcheck: Config.Client is missing")
	case cfg.Base == nil || cfg.Base.Scheme != "https" || cfg.Base.Host == "":
		return nil, errors.New("breachcheck: Config.Base is missing or is not https")
	case cfg.CallTimeout <= 0:
		return nil, errors.New("breachcheck: Config.CallTimeout is missing")
	}
	return &Checker{client: cfg.Client, base: cfg.Base, timeout: cfg.CallTimeout}, nil
}

// Listed reports whether password's suffix is in the range answer for its
// prefix with a count above 0. A padding entry (count 0) is never a match.
// Any failure is an error and no verdict: the caller decides what an
// unfinished check means.
func (c *Checker) Listed(ctx context.Context, password secret.Value) (bool, error) {
	// SHA-1 here is the range API's index, not password storage and not a
	// security primitive: only its first 5 hex characters leave, and nothing
	// is kept (gosec G401/G505 in sast-register.tsv, CodeQL
	// go/weak-sensitive-data-hashing in codeql-register.tsv). TRIP-WIRE: the
	// verdicts hold only while this hash is never stored or compared as a
	// credential.
	sum := sha1.Sum(password.Reveal())
	var hexed [40]byte
	for i, b := range sum {
		hexed[2*i], hexed[2*i+1] = hexUpper[b>>4], hexUpper[b&0x0f]
	}
	defer func() {
		clear(sum[:])
		clear(hexed[:])
	}()
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base.JoinPath(string(hexed[:prefixLen])).String(), nil)
	if err != nil {
		return false, withoutURL(err)
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.client.Do(req)
	if err != nil {
		return false, withoutURL(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("%w (status %d)", ErrUnexpectedAnswer, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return false, withoutURL(err)
	}
	if len(body) > maxBody {
		return false, fmt.Errorf("%w (over 1 MiB)", ErrUnexpectedAnswer)
	}
	return match(body, hexed[prefixLen:])
}

// match reads the answer's SUFFIX:COUNT lines, CRLF or LF, and reports
// whether suffix is listed with a count above 0. Every line is checked, so
// a malformed answer is refused whatever it holds.
func match(body, suffix []byte) (bool, error) {
	listed := false
	for line := range bytes.Lines(body) {
		line = bytes.TrimRight(line, "\r\n")
		if len(line) == 0 {
			continue
		}
		got, count, ok := bytes.Cut(line, []byte(":"))
		if !ok || len(got) != suffixLen || !isHex(got) {
			return false, fmt.Errorf("%w (a malformed line)", ErrUnexpectedAnswer)
		}
		n, err := strconv.ParseUint(string(count), 10, 64)
		if err != nil {
			return false, fmt.Errorf("%w (a malformed count)", ErrUnexpectedAnswer)
		}
		if n > 0 && bytes.EqualFold(got, suffix) {
			listed = true
		}
	}
	return listed, nil
}

func isHex(b []byte) bool {
	for _, c := range b {
		if (c < '0' || c > '9') && (c < 'A' || c > 'F') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// withoutURL drops the *url.Error wrapper http.Client puts on every
// failure, whose text names the request URL and so the prefix. What it
// wraps (a dial, TLS or context error) keeps its type for errors.Is/As.
func withoutURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}
