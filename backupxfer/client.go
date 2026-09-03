package backupxfer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// The agent's side: one interface, one implementation per destination scheme.
//
// Everything the agent does around the transport — resolve the staged file,
// seal it, hash it, report the facts — is identical whatever the destination
// is. The only thing that varies is how a sealed stream with a known
// plaintext digest and an as-yet-unknown sealed digest becomes an object at
// a URI, and Transport is exactly that operation. An S3 prefix is a second
// implementation of Put (a multipart upload whose final part carries the
// checksum), selected by TransportFor on the URI's scheme, and nothing above
// it changes.

// PutRequest is one member upload.
type PutRequest struct {
	// Destination is the URI the api handed the agent; Generation and Member
	// name the object beneath it.
	Destination string
	Generation  string
	Member      string
	// Credential is presented and never retained. Implementations must not
	// log it or place it in an error.
	Credential string
	// PlaintextDigest and PlaintextBytes are declared up front — they are
	// known before a byte is sealed.
	PlaintextDigest string
	PlaintextBytes  uint64
	// Body is the sealed stream. Sealed is called after Body returns EOF and
	// yields the digest and length of what was streamed; an implementation
	// sends both as the upload's trailer or its completion record.
	Body   io.Reader
	Sealed func() (digest string, size uint64)
}

// Transport uploads one sealed member to a destination.
type Transport interface {
	Put(ctx context.Context, req PutRequest) (*Receipt, error)
}

// ErrUnsupportedDestination is a destination URI whose scheme has no
// transport in this build.
var ErrUnsupportedDestination = errors.New("backupxfer: no transport for that destination scheme")

// HTTPOptions configures the HTTP transport.
type HTTPOptions struct {
	// CABundlePath is a PEM file trusted in addition to the system roots — the
	// per-installation mesh CA that signs the api's HTTPS leaf. Empty means
	// system roots only, which is right for a dev api on plain http.
	CABundlePath string
	// AcceptWait is how long the client waits for the endpoint's 100 Continue
	// before giving up on the slot — the §4.7 backpressure wait. Zero means
	// DefaultAcceptWait.
	AcceptWait time.Duration
	// Client overrides the constructed client entirely. Tests.
	Client *http.Client
}

// DefaultAcceptWait is how long an upload queues behind the endpoint's
// semaphore before the agent reports the transfer failed. Long, because the
// thing ahead in the queue is another node's volume landing on a USB disk;
// bounded, because an unbounded wait with a credential in hand is a slot leak
// from the other side.
const DefaultAcceptWait = 20 * time.Minute

// TransportFor selects a transport by the destination's scheme.
func TransportFor(destination string, opts HTTPOptions) (Transport, error) {
	u, err := url.Parse(strings.TrimSpace(destination))
	if err != nil {
		return nil, fmt.Errorf("backupxfer: destination: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return NewHTTPTransport(opts), nil
	case "s3":
		return nil, fmt.Errorf("%w: s3 (the cloud target is designed, not built; design/storage.md §4.1)", ErrUnsupportedDestination)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedDestination, u.Scheme)
	}
}

// HTTPTransport is Transport over the api's ingest endpoint.
type HTTPTransport struct {
	client *http.Client
}

// NewHTTPTransport builds the transport. The client's root pool is the system
// roots plus the CA bundle at opts.CABundlePath when it is readable; the
// bundle is read per construction so a re-enrolled CA is picked up without a
// restart, exactly as the updater's download client does.
func NewHTTPTransport(opts HTTPOptions) *HTTPTransport {
	if opts.Client != nil {
		return &HTTPTransport{client: opts.Client}
	}
	wait := opts.AcceptWait
	if wait <= 0 {
		wait = DefaultAcceptWait
	}
	tr := &http.Transport{
		// Non-zero, and this is the whole backpressure mechanism: a zero
		// ExpectContinueTimeout makes net/http send the body immediately
		// without waiting for the server's 100, which would defeat the
		// semaphore on the other side.
		ExpectContinueTimeout: wait,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		// A new connection per upload: the connection is the lease, and a
		// pooled idle connection is a lease nobody is using.
		DisableKeepAlives: true,
	}
	if opts.CABundlePath != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if pem, err := os.ReadFile(opts.CABundlePath); err == nil { //nolint:gosec // G304: the path is the agent's own configured trust bundle, never request data
			pool.AppendCertsFromPEM(pem)
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	return &HTTPTransport{client: &http.Client{Transport: tr}}
}

// Put streams the sealed body to the member's URL and returns the receipt.
//
// A refusal from the endpoint is a *RefusedError carrying its code; a
// transport failure (unreachable, reset, timed out) is any other error. The
// caller must not conclude from a transport failure that nothing landed — the
// api holds the record and is asked.
func (t *HTTPTransport) Put(ctx context.Context, req PutRequest) (*Receipt, error) {
	target, err := MemberURL(req.Destination, req.Generation, req.Member)
	if err != nil {
		return nil, err
	}
	if req.Body == nil || req.Sealed == nil {
		return nil, errors.New("backupxfer: Put needs a body and a way to learn its digest")
	}
	if strings.TrimSpace(req.Credential) == "" {
		return nil, errors.New("backupxfer: Put needs a credential")
	}

	// The trailer values are filled in by trailingBody once the sealed
	// stream has ended; net/http writes req.Trailer after the body's EOF.
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPut, target, &trailingBody{r: req.Body})
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Authorization", "Bearer "+req.Credential)
	hreq.Header.Set("Content-Type", ContentType)
	hreq.Header.Set("Expect", "100-continue")
	hreq.Header.Set(HeaderPlaintextDigest, req.PlaintextDigest)
	hreq.Header.Set(HeaderPlaintextBytes, strconv.FormatUint(req.PlaintextBytes, 10))
	hreq.Trailer = http.Header{TrailerSealedDigest: nil, TrailerSealedBytes: nil}
	hreq.Body.(*trailingBody).onEOF = func() {
		digest, size := req.Sealed()
		hreq.Trailer.Set(TrailerSealedDigest, digest)
		hreq.Trailer.Set(TrailerSealedBytes, strconv.FormatUint(size, 10))
	}

	resp, err := t.client.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("upload %s: %w", req.Member, redact(err, req.Credential))
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("upload %s: read response: %w", req.Member, err)
	}
	if resp.StatusCode == http.StatusCreated {
		var rc Receipt
		if err := json.Unmarshal(raw, &rc); err != nil {
			return nil, fmt.Errorf("upload %s: the destination confirmed with an unreadable receipt: %w", req.Member, err)
		}
		return &rc, nil
	}
	var p Problem
	if err := json.Unmarshal(raw, &p); err != nil || p.Code == "" {
		p = Problem{Code: fmt.Sprintf("http-%d", resp.StatusCode), Detail: strings.TrimSpace(string(raw))}
	}
	return nil, &RefusedError{Status: resp.StatusCode, Problem: p}
}

// trailingBody wraps the sealed stream and runs onEOF exactly once when the
// stream ends, before EOF is returned to net/http — which is the moment the
// trailer values have to exist.
type trailingBody struct {
	r     io.Reader
	onEOF func()
	done  bool
}

func (b *trailingBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if errors.Is(err, io.EOF) && !b.done {
		b.done = true
		if b.onEOF != nil {
			b.onEOF()
		}
	}
	return n, err
}

func (b *trailingBody) Close() error {
	if c, ok := b.r.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// redact keeps a credential out of an error. net/http does not echo request
// headers into its errors, but the URL can appear in one and a caller could
// one day put a credential in a query string; this makes the rule hold
// regardless.
func redact(err error, secret string) error {
	if secret == "" || !strings.Contains(err.Error(), secret) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), secret, "[credential]"))
}
