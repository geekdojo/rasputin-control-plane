package backupxfer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// The agent's side of the restore stream: fetch one member's plaintext tar
// from the source the api named, on the credential the api minted. The
// mirror of Put — one interface, one implementation per source scheme — and
// like Put it knows nothing about what it carries: the bytes are a tar the
// api unsealed, and everything the agent does with them (unpack, verify,
// swap) happens above this seam.

// GetRequest is one member fetch.
type GetRequest struct {
	// Source is the URI the api handed the agent; Generation and Member name
	// the object beneath it.
	Source     string
	Generation string
	Member     string
	// Credential is presented and never retained. Implementations must not
	// log it or place it in an error.
	Credential string
}

// Stream is an open member fetch: the body and what the source declared
// about it. The caller closes Body.
type Stream struct {
	Body io.ReadCloser
	// DeclaredDigest and DeclaredBytes are what the source said the plaintext
	// hashes to and how long it is — the manifest's numbers, echoed. The
	// caller verifies the bytes against the numbers the COMMAND carried; these
	// are here so the two can be compared and a disagreement named.
	DeclaredDigest string
	DeclaredBytes  uint64
}

// Fetcher fetches one member's plaintext from a source.
type Fetcher interface {
	Get(ctx context.Context, req GetRequest) (*Stream, error)
}

// FetcherFor selects a fetcher by the source's scheme.
func FetcherFor(source string, opts HTTPOptions) (Fetcher, error) {
	u, err := url.Parse(strings.TrimSpace(source))
	if err != nil {
		return nil, fmt.Errorf("backupxfer: source: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return NewHTTPTransport(opts), nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedDestination, u.Scheme)
	}
}

// Get opens the member's plaintext stream. A refusal from the source is a
// *RefusedError carrying its code; a transport failure is any other error.
// The returned stream's Body is the response body: reading it to EOF is
// reading the whole member, and a body that ends early — the source going
// away mid-stream — surfaces as an unexpected EOF to the reader, which the
// caller's byte count and digest then refuse.
func (t *HTTPTransport) Get(ctx context.Context, req GetRequest) (*Stream, error) {
	target, err := MemberURL(req.Source, req.Generation, req.Member)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Credential) == "" {
		return nil, errors.New("backupxfer: Get needs a credential")
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Authorization", "Bearer "+req.Credential)
	hreq.Header.Set("Accept", EgressContentType)
	resp, err := t.client.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", req.Member, redact(err, req.Credential))
	}
	if resp.StatusCode != http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		var p Problem
		if err := json.Unmarshal(raw, &p); err != nil || p.Code == "" {
			p = Problem{Code: fmt.Sprintf("http-%d", resp.StatusCode), Detail: strings.TrimSpace(string(raw))}
		}
		return nil, &RefusedError{Status: resp.StatusCode, Problem: p}
	}
	if ct := resp.Header.Get("Content-Type"); ct != EgressContentType {
		_ = resp.Body.Close()
		return nil, &RefusedError{Status: resp.StatusCode, Problem: Problem{Code: CodeNotAnArchive,
			Detail: fmt.Sprintf("the source answered with %q, not a volume tar", ct)}}
	}
	declaredBytes, _ := strconv.ParseUint(strings.TrimSpace(resp.Header.Get(HeaderPlaintextBytes)), 10, 64)
	return &Stream{
		Body:           resp.Body,
		DeclaredDigest: strings.ToLower(strings.TrimSpace(resp.Header.Get(HeaderPlaintextDigest))),
		DeclaredBytes:  declaredBytes,
	}, nil
}
